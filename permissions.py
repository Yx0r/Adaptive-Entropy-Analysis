# PolyEntropy Pro - Permission Analysis

# PE section characteristics flags
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ    = 0x40000000
IMAGE_SCN_MEM_WRITE   = 0x80000000

# ELF section flags
SHF_WRITE     = 0x1
SHF_EXECINSTR = 0x4

# Standard executable section names
STANDARD_CODE_SECTIONS = {
    ".text", ".code", "CODE", "TEXT",
    "__text",  # Mach-O
    ".init", ".plt", ".plt.got",
}


def is_rwx(section: dict) -> bool:
    """Return True if section is both writable and executable."""
    perms = section.get("permissions", "")
    return "W" in perms and "X" in perms


def check_rwx_sections(sections: list) -> list:
    """Return list of section names that are RWX."""
    return [sec["name"] for sec in sections if is_rwx(sec)]


def check_entry_point(entry_point: int, sections: list, file_type: str) -> dict:
    """
    Check if entry point falls within a standard executable section.
    Returns dict with 'anomaly' bool and 'description'.
    """
    if not sections or entry_point == 0:
        return {"anomaly": False, "description": "Entry point is 0 or no sections"}

    # Find section containing entry point (by VA)
    containing = None
    for sec in sections:
        va = sec.get("virtual_address", 0)
        size = sec.get("size", 0)
        if va <= entry_point < va + max(size, 1):
            containing = sec
            break

    if containing is None:
        return {
            "anomaly": True,
            "description": f"Entry point 0x{entry_point:x} not in any known section",
        }

    name = containing.get("name", "").strip("\x00").lower()
    perms = containing.get("permissions", "")

    # Check if name is a standard code section
    standard_names = {s.lower() for s in STANDARD_CODE_SECTIONS}
    is_standard_name = any(name == s or name.startswith(s) for s in standard_names)
    is_executable = "X" in perms

    if not is_executable:
        return {
            "anomaly": True,
            "description": (
                f"Entry point 0x{entry_point:x} in non-executable section '{containing['name']}'"
            ),
        }

    if not is_standard_name and is_executable:
        return {
            "anomaly": True,
            "description": (
                f"Entry point 0x{entry_point:x} in non-standard section "
                f"'{containing['name']}' (may be packed)"
            ),
        }

    return {
        "anomaly": False,
        "description": (
            f"Entry point 0x{entry_point:x} in '{containing['name']}' (normal)"
        ),
    }
