# PolyEntropy Pro - String Extraction
import re


def extract_strings(data: bytes, min_len: int = 4) -> list:
    """
    Extract printable ASCII strings from binary data.
    Returns list of (offset, string).
    """
    if not data:
        return []
    results = []
    pattern = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')
    for m in pattern.finditer(data):
        results.append((m.start(), m.group().decode("ascii", errors="replace")))
    return results


def extract_unicode_strings(data: bytes, min_len: int = 4) -> list:
    """
    Extract wide (UTF-16LE) strings from binary data.
    Returns list of (offset, string).
    """
    if not data:
        return []
    results = []
    # Match sequences of char + null byte (UTF-16LE printable ASCII)
    pattern = re.compile(rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}')
    for m in pattern.finditer(data):
        try:
            s = m.group().decode("utf-16-le", errors="replace").rstrip("\x00")
            if len(s) >= min_len:
                results.append((m.start(), s))
        except Exception:
            pass
    return results


def analyze_strings(data: bytes, min_len: int = 4) -> dict:
    """Full string analysis for a section."""
    ascii_strs = extract_strings(data, min_len)
    unicode_strs = extract_unicode_strings(data, min_len)
    all_strs = ascii_strs + [(off, s + " [W]") for off, s in unicode_strs]
    all_strs.sort(key=lambda x: x[0])
    return {
        "ascii_count": len(ascii_strs),
        "unicode_count": len(unicode_strs),
        "total_count": len(all_strs),
        "strings": all_strs[:500],  # cap for display
    }
