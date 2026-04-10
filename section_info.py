# PolyEntropy Pro - Section Classification & Entropy Rating
# Inspired by the EXE Analyzer tool's classify_section() and entropy_rating()
from collections import Counter

# ── Known PE section name → human label ───────────────────────────────────────
KNOWN_SECTIONS = {
    ".text":    "Executable Code",
    ".code":    "Executable Code",
    "CODE":     "Executable Code",
    ".data":    "Initialised Data",
    ".rdata":   "Read-only Data / Strings",
    ".idata":   "Import Directory",
    ".edata":   "Export Directory",
    ".bss":     "Uninitialised Data",
    ".rsrc":    "Resources",
    ".reloc":   "Base Relocations",
    ".pdata":   "Exception Handling Data",
    ".tls":     "Thread Local Storage",
    ".debug":   "Debug Info",
    ".CRT":     "C Runtime Init",
    ".xdata":   "Exception Unwind Data",
    ".ndata":   "Nullsoft Installer Data",
    ".upx0":    "UPX Packed  (segment 0)",
    ".upx1":    "UPX Packed  (segment 1)",
    "UPX0":     "UPX Packed  (segment 0)",
    "UPX1":     "UPX Packed  (segment 1)",
    ".themida": "Themida Protected",
    ".vmp0":    "VMProtect  (segment 0)",
    ".vmp1":    "VMProtect  (segment 1)",
    ".aspack":  "ASPack Packed",
    ".adata":   "ASPack Data",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    ".perplex": "Perplexor Protected",
    ".MPRESS1": "MPRESS Packed",
    ".MPRESS2": "MPRESS Packed",
    ".nsp0":    "NsPack Packed",
    ".nsp1":    "NsPack Packed",
    # ELF / Mach-O common
    ".init":    "Initialisation Code",
    ".fini":    "Finalisation Code",
    ".plt":     "Procedure Linkage Table",
    ".got":     "Global Offset Table",
    ".dynsym":  "Dynamic Symbol Table",
    ".dynstr":  "Dynamic String Table",
    "__text":   "Executable Code  (Mach-O)",
    "__data":   "Initialised Data  (Mach-O)",
    "__bss":    "Uninitialised Data  (Mach-O)",
    "__const":  "Constants  (Mach-O)",
}

# PE section characteristic flags
_SCN_CNT_CODE        = 0x00000020
_SCN_CNT_INIT_DATA   = 0x00000040
_SCN_CNT_UNINIT_DATA = 0x00000080
_SCN_MEM_EXECUTE     = 0x20000000
_SCN_MEM_WRITE       = 0x80000000


def classify_section(name: str, characteristics: int, entropy: float) -> str:
    """
    Return a human-readable section classification string.
    Combines name lookup, PE flags, and entropy hint.
    """
    clean = name.strip("\x00").strip()

    # Direct name match
    base = KNOWN_SECTIONS.get(clean)
    if not base:
        # Case-insensitive fallback
        lower = clean.lower()
        for k, v in KNOWN_SECTIONS.items():
            if k.lower() == lower:
                base = v
                break

    # Derive from flags if name unknown
    if not base:
        flags = characteristics
        if flags & _SCN_MEM_EXECUTE or flags & _SCN_CNT_CODE:
            base = "Executable Code"
        elif flags & _SCN_CNT_UNINIT_DATA:
            base = "Uninitialised Data"
        elif flags & _SCN_CNT_INIT_DATA:
            base = "Initialised Data"
        else:
            base = "Unknown"

    # Entropy override — append hint
    if entropy >= 7.5:
        return f"{base}  [likely encrypted/compressed]"
    elif entropy >= 6.5:
        return f"{base}  [possibly packed]"
    return base


def entropy_rating(entropy: float) -> tuple:
    """
    Map Shannon entropy (0–8) to a 0–10 scale with label and color.
    Returns (score_float, label_str, color_str)

    Bands (matching the reference tool, slightly refined):
      0.0 – 5.0  → Plaintext / Raw Data        green
      5.0 – 6.5  → Normal Compiled Code         yellow
      6.5 – 7.2  → Packed / Obfuscated          orange
      7.2 – 8.0  → Encrypted / Compressed       red
    """
    score = round((entropy / 8.0) * 10.0, 2)

    if entropy < 5.0:
        label = "Plaintext / Raw Data"
        color = "#4caf50"   # green
    elif entropy < 6.5:
        label = "Normal Compiled Code"
        color = "#ffeb3b"   # yellow
    elif entropy < 7.2:
        label = "Packed / Obfuscated"
        color = "#ff9800"   # orange
    else:
        label = "Encrypted / Compressed"
        color = "#f44336"   # red

    return score, label, color


def byte_frequency(data: bytes, top_n: int = 16) -> list:
    """
    Return top_n most frequent bytes as list of (byte_val, count, probability, bar_str).
    bar_str is a text bar scaled to 30 chars.
    """
    if not data:
        return []
    counts = Counter(data)
    total = len(data)
    sorted_bytes = counts.most_common(top_n)
    result = []
    for byte_val, count in sorted_bytes:
        prob = count / total
        bar_len = int(prob * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        result.append((byte_val, count, prob, bar))
    return result


def dominant_byte_info(data: bytes) -> dict:
    """
    Analyse byte distribution for XOR key hints.
    Returns dict with dominant byte, its probability, and a hint string.
    """
    if not data or len(data) < 16:
        return {}
    counts = Counter(data)
    total = len(data)
    top_byte, top_count = counts.most_common(1)[0]
    top_prob = top_count / total
    unique_bytes = len(counts)

    hint = ""
    if top_prob > 0.4:
        hint = f"POSSIBLE XOR KEY: 0x{top_byte:02X} dominates {top_prob:.0%} of bytes"
    elif unique_bytes < 16:
        hint = f"Very few unique byte values ({unique_bytes}) — suspicious"
    elif unique_bytes == 256 and top_prob < 0.01:
        hint = "Near-perfect uniform distribution — strong encryption indicator"

    return {
        "dominant_byte": top_byte,
        "dominant_prob": top_prob,
        "unique_bytes": unique_bytes,
        "hint": hint,
    }
