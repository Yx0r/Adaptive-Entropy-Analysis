# PolyEntropy Pro - Polymorphic Detection
import struct

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    from scipy.stats import chisquare
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

from config import CRYPTO_CONSTANTS


def _get_cs(arch: str):
    """Return a Capstone disassembler for the given arch."""
    if not CAPSTONE_AVAILABLE:
        return None
    if arch == "x64":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif arch == "ARM":
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    else:  # default x86
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


# Instructions that modify memory or registers for crypto operations
CRYPTO_MNEMONICS = {"xor", "add", "sub", "ror", "rol", "not", "and", "or", "shl", "shr"}
# Jump mnemonics that can create loops
LOOP_MNEMONICS = {"loop", "loope", "loopne", "jmp", "je", "jne", "jl", "jle",
                  "jg", "jge", "jb", "jbe", "ja", "jae", "jnz", "jz"}


def find_decryptor_loops(data: bytes, entry_point_offset: int, arch: str) -> list:
    """
    Scan entry point region and detect potential decryptor loops.
    Returns list of dicts with offset, description, instructions.
    """
    if not CAPSTONE_AVAILABLE or not data:
        return []

    cs = _get_cs(arch)
    if cs is None:
        return []
    cs.detail = False

    results = []

    # Regions to scan: entry point area + beginning of data
    regions = []
    ep = entry_point_offset if entry_point_offset else 0
    # Entry point region (first 512 bytes from EP)
    if ep < len(data):
        end = min(ep + 512, len(data))
        regions.append((ep, data[ep:end]))
    # Also scan first 512 bytes
    if ep != 0:
        regions.append((0, data[:min(512, len(data))]))

    for base_offset, region_data in regions:
        _scan_region_for_loops(cs, region_data, base_offset, arch, results)

    # Deduplicate by offset
    seen = set()
    unique = []
    for r in results:
        if r["offset"] not in seen:
            seen.add(r["offset"])
            unique.append(r)

    return unique


def _scan_region_for_loops(cs, data: bytes, base_offset: int, arch: str, results: list):
    """Scan a region for loop patterns."""
    try:
        insns = list(cs.disasm(data, base_offset))
    except Exception:
        return

    if len(insns) < 3:
        return

    for i, insn in enumerate(insns):
        mnem = insn.mnemonic.lower()

        # Check for LOOP instruction
        if mnem in ("loop", "loope", "loopne"):
            # Collect surrounding instructions
            start = max(0, i - 8)
            window = insns[start:i + 1]
            has_crypto = any(w.mnemonic.lower() in CRYPTO_MNEMONICS for w in window)
            seq = " | ".join(f"{w.mnemonic} {w.op_str}" for w in window)
            results.append({
                "offset": insn.address,
                "type": "LOOP instruction",
                "description": f"LOOP at 0x{insn.address:x}, crypto ops: {has_crypto}",
                "instructions": seq,
                "loop_size": len(window),
            })

        # Check for backward JMP (potential loop)
        elif mnem in LOOP_MNEMONICS and insn.op_str:
            try:
                target = int(insn.op_str, 16)
                # Backward jump = loop
                if target < insn.address and (insn.address - target) < 256:
                    # Check if there are crypto ops in the loop body
                    loop_start = target
                    loop_insns = [x for x in insns
                                  if loop_start <= x.address <= insn.address]
                    has_crypto = any(x.mnemonic.lower() in CRYPTO_MNEMONICS
                                     for x in loop_insns)
                    has_mem = any(
                        ("[" in x.op_str and x.mnemonic.lower() in CRYPTO_MNEMONICS)
                        for x in loop_insns
                    )
                    if has_crypto:
                        seq = " | ".join(
                            f"{x.mnemonic} {x.op_str}" for x in loop_insns[:10]
                        )
                        results.append({
                            "offset": loop_start,
                            "type": "Backward JMP loop",
                            "description": (
                                f"Loop 0x{loop_start:x}→0x{insn.address:x}, "
                                f"crypto_ops={has_crypto}, mem_ops={has_mem}"
                            ),
                            "instructions": seq,
                            "loop_size": len(loop_insns),
                        })
            except (ValueError, TypeError):
                pass


# Junk instruction patterns
JUNK_PATTERNS_X86 = {
    "nop",
    "nop word",
    "nop dword",
}


def _is_junk_insn(insn) -> bool:
    """Return True if instruction appears to be junk/useless."""
    mnem = insn.mnemonic.lower()
    ops = insn.op_str.lower().strip()

    if mnem == "nop":
        return True
    # MOV reg, reg (same register)
    if mnem == "mov" and ops and "," in ops:
        parts = [p.strip() for p in ops.split(",")]
        if len(parts) == 2 and parts[0] == parts[1]:
            return True
    # XOR reg, reg (zero a register - sometimes junk used as padding)
    if mnem == "xor" and ops and "," in ops:
        parts = [p.strip() for p in ops.split(",")]
        if len(parts) == 2 and parts[0] == parts[1]:
            return True
    # PUSH/POP same reg in sequence - handled at higher level
    # ADD/SUB reg, 0
    if mnem in ("add", "sub") and ops.endswith(", 0"):
        return True
    # XCHG eax, eax
    if mnem == "xchg" and ops and "," in ops:
        parts = [p.strip() for p in ops.split(",")]
        if len(parts) == 2 and parts[0] == parts[1]:
            return True
    return False


def junk_ratio(data: bytes, arch: str) -> float:
    """Compute overall junk instruction ratio for a section."""
    if not CAPSTONE_AVAILABLE or not data:
        return 0.0
    cs = _get_cs(arch)
    if cs is None:
        return 0.0
    cs.detail = False
    try:
        insns = list(cs.disasm(data, 0))
    except Exception:
        return 0.0
    if not insns:
        return 0.0
    junk_count = sum(1 for i in insns if _is_junk_insn(i))
    return junk_count / len(insns)


def junk_regions(data: bytes, arch: str, window: int = 200) -> list:
    """
    Return list of (offset, ratio) for windows with high junk ratio.
    """
    if not CAPSTONE_AVAILABLE or not data:
        return []
    cs = _get_cs(arch)
    if cs is None:
        return []
    cs.detail = False

    results = []
    step = window // 2
    i = 0
    while i + window <= len(data):
        chunk = data[i:i + window]
        try:
            insns = list(cs.disasm(chunk, i))
        except Exception:
            i += step
            continue
        if insns:
            junk_count = sum(1 for ins in insns if _is_junk_insn(ins))
            ratio = junk_count / len(insns)
            results.append((i, ratio))
        i += step
    return results


def chi_square_uniform(data: bytes) -> tuple:
    """
    Chi-square test against uniform distribution.
    Returns (p_value, is_uniform).
    is_uniform=True means data looks random/encrypted.
    """
    if not data or len(data) < 16:
        return (1.0, False)

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    if SCIPY_AVAILABLE:
        try:
            expected = len(data) / 256.0
            # Avoid zero expected frequencies
            if expected < 1:
                return (1.0, False)
            _, p_value = chisquare(freq)
            return (float(p_value), p_value > 0.05)
        except Exception:
            pass

    # Manual chi-square approximation if scipy unavailable
    expected = len(data) / 256.0
    if expected < 1:
        return (1.0, False)
    chi2 = sum((f - expected) ** 2 / expected for f in freq)
    # Very rough p-value: chi2 >> 255 means non-uniform
    # For 255 df, critical value at p=0.05 is ~293
    p_approx = 0.01 if chi2 > 293 else (0.5 if chi2 < 200 else 0.1)
    return (p_approx, p_approx > 0.05)


def scan_crypto_constants(data: bytes, constants_list: list = None) -> list:
    """
    Search for known crypto constants in binary data.
    Returns list of (offset, value, name).
    """
    if constants_list is None:
        constants_list = CRYPTO_CONSTANTS

    results = []
    if not data:
        return results

    # Build set of (packed_le, packed_be, value, name)
    patterns = []
    for entry in constants_list:
        if isinstance(entry, tuple) and len(entry) == 2:
            val, name = entry
        elif isinstance(entry, int):
            val, name = entry, hex(entry)
        else:
            continue
        try:
            le = struct.pack("<I", val & 0xFFFFFFFF)
            be = struct.pack(">I", val & 0xFFFFFFFF)
            patterns.append((le, be, val, name))
        except struct.error:
            continue

    for le, be, val, name in patterns:
        offset = 0
        while True:
            idx = data.find(le, offset)
            if idx == -1:
                break
            results.append((idx, val, name, "LE"))
            offset = idx + 1

        offset = 0
        while True:
            idx = data.find(be, offset)
            if idx == -1:
                break
            # Avoid duplicate if le==be
            if le != be:
                results.append((idx, val, name, "BE"))
            offset = idx + 1

    results.sort(key=lambda x: x[0])
    return results
