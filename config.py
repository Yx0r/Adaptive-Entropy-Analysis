# Adaptive Entropy Analyzer — Configuration
# Author: Yx0R
import os, json

APP_NAME    = "Adaptive Entropy Analyzer"
APP_VERSION = "2.0.0"
APP_AUTHOR  = "Yx0R"
APP_TAGLINE = "Advanced Static Malware Analysis Framework"
GITHUB_URL  = "https://github.com/Yx0R"

# ── Analysis thresholds ───────────────────────────────────────────────────────
ENTROPY_LOW            = 5.0
ENTROPY_HIGH           = 7.2
JUNK_RATIO_THRESHOLD   = 0.30
CHI_SQUARE_P_THRESHOLD = 0.05
SLIDING_WINDOW_SIZE    = 256
SLIDING_WINDOW_STEP    = 128
MAX_HEX_BYTES          = 8192
MAX_DISASM_INSNS       = 300
MAX_STRINGS_DISPLAY    = 500
MIN_STRING_LEN         = 4

# ── Scoring weights ───────────────────────────────────────────────────────────
WEIGHTS = {
    "decryptor_loop":        30,
    "high_entropy_contrast": 15,
    "junk_ratio":            15,
    "chi_square":            10,
    "crypto_const":          10,
    "rwx_section":           10,
    "entry_point_anomaly":    5,
    "few_imports":            5,
}

VERDICT_THRESHOLDS = {
    "Clean":               (0,  20),
    "Suspicious/Packed":   (21, 50),
    "Likely Polymorphic":  (51, 80),
    "Strong Polymorphic":  (81, 100),
}

# ── Crypto constants ──────────────────────────────────────────────────────────
CRYPTO_CONSTANTS = [
    (0x9E3779B9, "XTEA/Blowfish delta"),
    (0x61C88647, "RC4-like"),
    (0x67452301, "MD5 init A"),
    (0x6ED9EBA1, "MD5/SHA1 K"),
    (0x5C4CDF34, "Custom/Unknown"),
    (0x243F6A88, "Pi constant (AES?)"),
    (0xDEADBEEF, "Magic/Placeholder"),
    (0xC3D2E1F0, "SHA1 init"),
    (0x6A09E667, "SHA-256 H0"),
    (0xBB67AE85, "SHA-256 H1"),
    (0x428A2F98, "SHA-256 K0"),
    (0x71374491, "SHA-256 K1"),
]

# ── Suspicious imports ────────────────────────────────────────────────────────
SUSPICIOUS_IMPORTS = [
    "VirtualProtect","VirtualAlloc","VirtualAllocEx",
    "WriteProcessMemory","ReadProcessMemory",
    "CreateRemoteThread","CreateRemoteThreadEx",
    "LoadLibrary","LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW",
    "GetProcAddress",
    "SetWindowsHookEx","SetWindowsHookExA","SetWindowsHookExW",
    "NtUnmapViewOfSection","ZwUnmapViewOfSection",
    "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
    "CreateThread","HeapCreate",
    "OpenProcess","TerminateProcess",
    "RegOpenKeyEx","RegSetValueEx","RegCreateKeyEx",
    "WinExec","ShellExecute","ShellExecuteA","ShellExecuteW",
    "URLDownloadToFile","InternetOpenUrl",
    "CryptEncrypt","CryptDecrypt",
]

# ── VirusTotal ────────────────────────────────────────────────────────────────
VT_API_KEY          = ""
VT_ENABLED          = False
VT_TIMEOUT          = 15
VT_AUTO_SUBMIT      = False
VT_RATE_LIMIT_DELAY = 16

# ── GUI preferences ───────────────────────────────────────────────────────────
GUI_FONT_MONO_SIZE    = 9
GUI_FONT_UI_SIZE      = 9
GUI_WINDOW_W          = 1400
GUI_WINDOW_H          = 860
GUI_HEATMAP_H         = 100
GUI_SHOW_LEGEND       = True
GUI_SHOW_TOOLTIPS     = True
GUI_AUTO_SELECT_FIRST = True
GUI_ACCENT_COLOR      = "#00d4ff"

# ── Persistence ───────────────────────────────────────────────────────────────
# ── Settings file path — works for both .py script and compiled .exe ─────────
# When frozen by PyInstaller, __file__ points to a read-only temp dir (_MEIPASS).
# We must use sys.executable (the actual .exe) instead, so the file persists.
import sys as _sys

def _get_cfg_dir() -> str:
    """Return the directory where settings.json should live."""
    if getattr(_sys, "frozen", False):
        # Compiled exe: save next to the .exe file
        return os.path.dirname(_sys.executable)
    else:
        # Running as script: save next to config.py
        return os.path.dirname(os.path.abspath(__file__))

_CFG_FILE = os.path.join(_get_cfg_dir(), "settings.json")

_PERSIST = [
    "ENTROPY_LOW","ENTROPY_HIGH","JUNK_RATIO_THRESHOLD","CHI_SQUARE_P_THRESHOLD",
    "SLIDING_WINDOW_SIZE","SLIDING_WINDOW_STEP","MAX_HEX_BYTES","MAX_DISASM_INSNS",
    "MAX_STRINGS_DISPLAY","MIN_STRING_LEN","WEIGHTS",
    "VT_API_KEY","VT_TIMEOUT","VT_AUTO_SUBMIT","VT_RATE_LIMIT_DELAY",
    "GUI_FONT_MONO_SIZE","GUI_FONT_UI_SIZE","GUI_WINDOW_W","GUI_WINDOW_H",
    "GUI_HEATMAP_H","GUI_SHOW_LEGEND","GUI_SHOW_TOOLTIPS","GUI_AUTO_SELECT_FIRST",
    "GUI_ACCENT_COLOR","SUSPICIOUS_IMPORTS",
]

def save():
    import sys
    mod  = sys.modules[__name__]
    data = {k: getattr(mod, k) for k in _PERSIST if hasattr(mod, k)}
    try:
        with open(_CFG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[config] save failed: {e}")

def load():
    if not os.path.isfile(_CFG_FILE):
        return
    import sys
    mod = sys.modules[__name__]
    try:
        with open(_CFG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.items():
            if k in _PERSIST and hasattr(mod, k):
                setattr(mod, k, v)
    except Exception as e:
        print(f"[config] load failed: {e}")

load()


def vt_is_enabled() -> bool:
    """
    VT is considered enabled if a non-empty API key is configured.
    We do NOT persist VT_ENABLED as a separate flag — the key IS the switch.
    This prevents the common issue where the key is saved but VT_ENABLED=False
    because the user forgot to also tick the checkbox.
    """
    return bool(VT_API_KEY and VT_API_KEY.strip())
