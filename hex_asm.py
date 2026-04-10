# PolyEntropy Pro - Hex Dump & Disassembly

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


def hex_dump(data: bytes, offset: int = 0, width: int = 16, max_bytes: int = 4096) -> str:
    """
    Return formatted hex dump string.
    offset: base address to display.
    max_bytes: cap how much to dump.
    """
    if not data:
        return "(no data)"
    data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        addr = offset + i
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex part
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr:08x}  {hex_part}  |{ascii_part}|")
    if len(data) == max_bytes:
        lines.append(f"... (truncated at {max_bytes} bytes)")
    return "\n".join(lines)


def _get_cs(arch: str):
    """Return configured Capstone disassembler."""
    if not CAPSTONE_AVAILABLE:
        return None
    arch = arch or "x86"
    if arch == "x64":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif arch == "ARM":
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    else:
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


def disassemble(data: bytes, arch: str = "x86", offset: int = 0,
                max_insns: int = 200) -> str:
    """
    Disassemble bytes and return formatted string.
    """
    if not data:
        return "(no data)"
    if not CAPSTONE_AVAILABLE:
        return "Capstone not installed. Install with: pip install capstone"

    cs = _get_cs(arch)
    if cs is None:
        return "Could not create disassembler."
    cs.detail = False

    lines = []
    count = 0
    try:
        for insn in cs.disasm(data, offset):
            bytes_str = " ".join(f"{b:02x}" for b in insn.bytes)
            lines.append(
                f"0x{insn.address:08x}  {bytes_str:<20}  {insn.mnemonic} {insn.op_str}"
            )
            count += 1
            if count >= max_insns:
                lines.append(f"... (truncated at {max_insns} instructions)")
                break
    except Exception as e:
        lines.append(f"Disassembly error: {e}")

    return "\n".join(lines) if lines else "(no instructions decoded)"
