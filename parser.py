# PolyEntropy Pro - File Parser
import os
import struct
import zipfile

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


class ParsedFile:
    def __init__(self):
        self.raw_bytes = b""
        self.sections = []  # list of dicts
        self.entry_point = 0
        self.arch = "Unknown"
        self.file_type = "Unknown"
        self.imports = []
        self.exports = []
        self.error = None


def _detect_file_type(data: bytes) -> str:
    """Detect file type from magic bytes."""
    if len(data) < 4:
        return "Unknown"
    magic = data[:4]
    if magic[:2] == b"MZ":
        return "PE"
    elif magic == b"\x7fELF":
        return "ELF"
    elif magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                   b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                   b"\xca\xfe\xba\xbe"):
        return "Mach-O"
    elif magic[:4] == b"PK\x03\x04":
        return "APK"  # ZIP-based, may be APK
    elif magic[:3] == b"dex":
        return "DEX"
    return "Unknown"


def _parse_pe(path: str, data: bytes) -> ParsedFile:
    pf = ParsedFile()
    pf.raw_bytes = data
    pf.file_type = "PE"

    if not LIEF_AVAILABLE:
        pf.error = "lief not installed - cannot parse PE"
        return pf

    try:
        binary = lief.parse(path)
        if binary is None:
            pf.error = "lief could not parse PE file"
            return pf

        # Arch — use string representation to avoid lief version differences
        # lief 0.13 uses lief.PE.MACHINE_TYPES; lief 0.14+ changed this API
        try:
            machine_str = str(binary.header.machine).upper()
            if "AMD64" in machine_str or "X86_64" in machine_str:
                pf.arch = "x64"
            elif "ARM64" in machine_str or "AARCH64" in machine_str or "AA64" in machine_str:
                pf.arch = "ARM"
            elif "ARM" in machine_str:
                pf.arch = "ARM"
            elif "386" in machine_str:
                pf.arch = "x86"
            else:
                try:
                    m_val = int(binary.header.machine)
                except Exception:
                    m_val = 0
                if m_val == 0x8664:
                    pf.arch = "x64"
                elif m_val == 0x014c:
                    pf.arch = "x86"
                elif m_val in (0x01c0, 0x01c4, 0xaa64):
                    pf.arch = "ARM"
                else:
                    pf.arch = "x86"
        except Exception:
            pf.arch = "x86" 

        # Entry point
        try:
            pf.entry_point = binary.optional_header.addressof_entrypoint
        except Exception:
            pf.entry_point = 0

        # Sections
        for sec in binary.sections:
            try:
                raw = bytes(sec.content)
            except Exception:
                raw = b""
            chars = 0
            try:
                chars = int(sec.characteristics)
            except Exception:
                pass
            pf.sections.append({
                "name": sec.name,
                "offset": sec.offset,
                "size": sec.size,
                "raw_data": raw,
                "virtual_address": sec.virtual_address,
                "characteristics": chars,
                "permissions": _pe_perms(chars),
            })

        # Imports
        try:
            for imp in binary.imports:
                for entry in imp.entries:
                    name = entry.name if entry.name else f"ord_{entry.ordinal}"
                    pf.imports.append(name)
        except Exception:
            pass

        # Exports
        try:
            for exp in binary.exported_functions:
                pf.exports.append(exp.name)
        except Exception:
            pass

    except Exception as e:
        pf.error = f"PE parse error: {e}"

    return pf


def _pe_perms(chars: int) -> str:
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000
    perms = ""
    if chars & IMAGE_SCN_MEM_READ:
        perms += "R"
    if chars & IMAGE_SCN_MEM_WRITE:
        perms += "W"
    if chars & IMAGE_SCN_MEM_EXECUTE:
        perms += "X"
    return perms or "---"


def _parse_elf(path: str, data: bytes) -> ParsedFile:
    pf = ParsedFile()
    pf.raw_bytes = data
    pf.file_type = "ELF"

    if not LIEF_AVAILABLE:
        pf.error = "lief not installed - cannot parse ELF"
        return pf

    try:
        binary = lief.parse(path)
        if binary is None:
            pf.error = "lief could not parse ELF file"
            return pf

        # Arch
        try:
            arch_val = binary.header.machine_type
            arch_str = str(arch_val)
            if "X86_64" in arch_str or "AARCH64" in arch_str.upper():
                pf.arch = "x64"
            elif "386" in arch_str or "i386" in arch_str.lower():
                pf.arch = "x86"
            elif "ARM" in arch_str.upper():
                pf.arch = "ARM"
            else:
                pf.arch = "x86"
        except Exception:
            pf.arch = "x86"

        try:
            pf.entry_point = binary.header.entrypoint
        except Exception:
            pf.entry_point = 0

        for sec in binary.sections:
            try:
                raw = bytes(sec.content)
            except Exception:
                raw = b""
            flags = 0
            try:
                flags = int(sec.flags)
            except Exception:
                pass
            pf.sections.append({
                "name": sec.name,
                "offset": sec.offset,
                "size": sec.size,
                "raw_data": raw,
                "virtual_address": sec.virtual_address,
                "characteristics": flags,
                "permissions": _elf_perms(flags),
            })

        try:
            for sym in binary.exported_symbols:
                pf.exports.append(sym.name)
        except Exception:
            pass

        try:
            for sym in binary.imported_symbols:
                pf.imports.append(sym.name)
        except Exception:
            pass

    except Exception as e:
        pf.error = f"ELF parse error: {e}"

    return pf


def _elf_perms(flags: int) -> str:
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    perms = ""
    if flags & SHF_ALLOC:
        perms += "R"
    if flags & SHF_WRITE:
        perms += "W"
    if flags & SHF_EXECINSTR:
        perms += "X"
    return perms or "---"


def _parse_macho(path: str, data: bytes) -> ParsedFile:
    pf = ParsedFile()
    pf.raw_bytes = data
    pf.file_type = "Mach-O"

    if not LIEF_AVAILABLE:
        pf.error = "lief not installed - cannot parse Mach-O"
        return pf

    try:
        binary = lief.parse(path)
        if binary is None:
            pf.error = "lief could not parse Mach-O file"
            return pf

        try:
            arch_str = str(binary.header.cpu_type)
            if "X86_64" in arch_str:
                pf.arch = "x64"
            elif "X86" in arch_str:
                pf.arch = "x86"
            elif "ARM" in arch_str:
                pf.arch = "ARM"
            else:
                pf.arch = "x86"
        except Exception:
            pf.arch = "x86"

        try:
            pf.entry_point = binary.entrypoint
        except Exception:
            pf.entry_point = 0

        for sec in binary.sections:
            try:
                raw = bytes(sec.content)
            except Exception:
                raw = b""
            flags = 0
            try:
                flags = int(sec.flags)
            except Exception:
                pass
            # Mach-O segment permissions come from segment
            seg_perms = ""
            try:
                seg = sec.segment
                if seg:
                    VM_PROT_READ = 1
                    VM_PROT_WRITE = 2
                    VM_PROT_EXECUTE = 4
                    mp = int(seg.max_protection)
                    if mp & VM_PROT_READ:
                        seg_perms += "R"
                    if mp & VM_PROT_WRITE:
                        seg_perms += "W"
                    if mp & VM_PROT_EXECUTE:
                        seg_perms += "X"
            except Exception:
                seg_perms = "---"

            pf.sections.append({
                "name": f"{sec.segment_name},{sec.name}" if sec.segment_name else sec.name,
                "offset": sec.offset,
                "size": sec.size,
                "raw_data": raw,
                "virtual_address": sec.virtual_address,
                "characteristics": flags,
                "permissions": seg_perms or "---",
            })

        try:
            for sym in binary.exported_symbols:
                pf.exports.append(sym.name)
        except Exception:
            pass

        try:
            for sym in binary.imported_symbols:
                pf.imports.append(sym.name)
        except Exception:
            pass

    except Exception as e:
        pf.error = f"Mach-O parse error: {e}"

    return pf


def _parse_apk(path: str, data: bytes) -> ParsedFile:
    pf = ParsedFile()
    pf.raw_bytes = data
    pf.file_type = "APK"
    pf.arch = "ARM"

    # Try androguard first
    try:
        from androguard.core.bytecodes.dvm import DalvikVMFormat
        from androguard.core.apk import APK as AndroAPK
        apk = AndroAPK(path)
        dex_data = apk.get_dex()
        if dex_data:
            pf.sections.append({
                "name": "classes.dex",
                "offset": 0,
                "size": len(dex_data),
                "raw_data": dex_data,
                "virtual_address": 0,
                "characteristics": 0,
                "permissions": "R",
            })
        return pf
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: extract DEX from ZIP
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            names = zf.namelist()
            dex_files = [n for n in names if n.startswith("classes") and n.endswith(".dex")]
            if not dex_files:
                pf.error = "No DEX files found in APK"
                return pf
            for dex_name in dex_files:
                dex_data = zf.read(dex_name)
                pf.sections.append({
                    "name": dex_name,
                    "offset": 0,
                    "size": len(dex_data),
                    "raw_data": dex_data,
                    "virtual_address": 0,
                    "characteristics": 0,
                    "permissions": "R",
                })
    except Exception as e:
        pf.error = f"APK parse error: {e}"

    return pf


def load_file(path: str) -> ParsedFile:
    """Load and parse a binary file. Returns ParsedFile object."""
    if not os.path.isfile(path):
        pf = ParsedFile()
        pf.error = f"File not found: {path}"
        return pf

    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        pf = ParsedFile()
        pf.error = f"Cannot read file: {e}"
        return pf

    file_type = _detect_file_type(data)

    if file_type == "PE":
        return _parse_pe(path, data)
    elif file_type == "ELF":
        return _parse_elf(path, data)
    elif file_type == "Mach-O":
        return _parse_macho(path, data)
    elif file_type == "APK":
        return _parse_apk(path, data)
    else:
        # Try lief as fallback
        pf = ParsedFile()
        pf.raw_bytes = data
        pf.file_type = "Unknown"
        pf.arch = "x86"
        if LIEF_AVAILABLE:
            try:
                binary = lief.parse(path)
                if binary:
                    # Generic fallback
                    pf.sections.append({
                        "name": "raw",
                        "offset": 0,
                        "size": len(data),
                        "raw_data": data,
                        "virtual_address": 0,
                        "characteristics": 0,
                        "permissions": "R",
                    })
                    return pf
            except Exception:
                pass
        # Last resort: treat whole file as one section
        pf.sections.append({
            "name": "raw",
            "offset": 0,
            "size": len(data),
            "raw_data": data,
            "virtual_address": 0,
            "characteristics": 0,
            "permissions": "R",
        })
        return pf
