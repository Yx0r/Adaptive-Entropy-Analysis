# PolyEntropy Pro - Entropy Analysis
import math
from config import SLIDING_WINDOW_SIZE, SLIDING_WINDOW_STEP


def shannon(data: bytes) -> float:
    """Calculate Shannon entropy of bytes. Returns value 0-8."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


def sliding_window(data: bytes, window_size: int = SLIDING_WINDOW_SIZE,
                   step: int = SLIDING_WINDOW_STEP) -> list:
    """
    Compute entropy over sliding windows.
    Returns list of (offset, entropy) tuples.
    """
    if not data or window_size <= 0:
        return []
    results = []
    i = 0
    while i + window_size <= len(data):
        chunk = data[i:i + window_size]
        e = shannon(chunk)
        results.append((i, e))
        i += step
    # Handle tail
    if i < len(data) and len(data) - i > 8:
        chunk = data[i:]
        e = shannon(chunk)
        results.append((i, e))
    return results


def entropy_color(value: float) -> str:
    """Return color string based on entropy value."""
    if value < 5.0:
        return "green"
    elif value < 7.2:
        return "#FFA500"  # orange/yellow
    else:
        return "red"
