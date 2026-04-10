# PolyEntropy Pro - Import/Export Analysis
from config import SUSPICIOUS_IMPORTS


def analyze_imports(imports: list, exports: list) -> dict:
    """
    Analyze import list for suspicious APIs.
    Returns dict with counts and flags.
    """
    suspicious_found = []
    import_lower = [imp.lower() for imp in imports]

    for sus in SUSPICIOUS_IMPORTS:
        if sus.lower() in import_lower:
            suspicious_found.append(sus)

    few_imports = len(imports) < 5 and len(imports) > 0

    return {
        "import_count": len(imports),
        "export_count": len(exports),
        "suspicious": suspicious_found,
        "suspicious_count": len(suspicious_found),
        "few_imports": few_imports,
        "imports": imports[:200],   # cap for display
        "exports": exports[:200],
    }
