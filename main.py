# Adaptive Entropy Analyzer — Main GUI
# Author: Yx0R
import sys, os, threading, hashlib, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
import entropy  as entropy_mod
import parser   as file_parser
import analyzer
import hex_asm
import reporter
import strings  as strings_mod
import section_info as sec_info_mod
import virustotal   as vt_mod

# ── Dynamic palette (reads from config so accent is changeable) ───────────────
def _pal():
    A = config.GUI_ACCENT_COLOR
    return dict(
        BG_DARK="#1a1a2e", BG_MED="#16213e", BG_LIGHT="#0f3460",
        BG_CARD="#0d1b2a",
        FG_MAIN="#e0e0e0", FG_ACCENT=A, FG_WHITE="#ffffff",
        FG_GREEN="#4caf50", FG_YELLOW="#ffeb3b",
        FG_ORANGE="#ff9800", FG_RED="#f44336", FG_DIM="#607080",
    )

P = _pal()
def _p(k): return P[k]

FONT_MONO = lambda: ("Courier New", config.GUI_FONT_MONO_SIZE)
FONT_UI   = lambda: ("Segoe UI",    config.GUI_FONT_UI_SIZE)
FONT_HEAD = lambda: ("Segoe UI",    config.GUI_FONT_UI_SIZE+1, "bold")
FONT_BIG  = lambda: ("Segoe UI",    config.GUI_FONT_UI_SIZE+2, "bold")

def efg(e):
    if e>=7.2: return _p("FG_RED")
    if e>=6.5: return _p("FG_ORANGE")
    if e>=5.0: return _p("FG_YELLOW")
    return _p("FG_GREEN")


# ══════════════════════════════════════════════════════════════════════════════
#  SETTINGS DIALOG  (tabbed, full options)
# ══════════════════════════════════════════════════════════════════════════════
class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Settings — Adaptive Entropy Analyzer")
        self.configure(bg=_p("BG_DARK"))
        self.geometry("680x560")
        self.resizable(True, True)
        self.minsize(560, 480)
        self.grab_set()
        self.transient(parent)
        self._vars = {}
        self._net_label = None
        self._build()
        self.wait_window()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=(10,0))

        tabs = [
            ("🔬 Analysis",    self._tab_analysis),
            ("⚖ Weights",     self._tab_weights),
            ("🌐 VirusTotal",  self._tab_vt),
            ("🎨 Interface",   self._tab_gui),
            ("📋 Imports",     self._tab_imports),
        ]
        for title, builder in tabs:
            f = tk.Frame(nb, bg=_p("BG_DARK"))
            nb.add(f, text=title)
            builder(f)

        # Bottom bar
        bb = tk.Frame(self, bg=_p("BG_MED"), pady=8)
        bb.pack(fill="x", side="bottom")
        tk.Button(bb, text="✔  Save & Apply", command=self._apply,
                  bg=_p("FG_ACCENT"), fg=_p("BG_DARK"), font=FONT_HEAD(),
                  relief="flat", cursor="hand2", padx=16, pady=5).pack(side="left", padx=10)
        tk.Button(bb, text="✘  Cancel", command=self.destroy,
                  bg=_p("BG_LIGHT"), fg=_p("FG_MAIN"), font=FONT_UI(),
                  relief="flat", cursor="hand2", padx=14, pady=5).pack(side="left", padx=4)
        tk.Button(bb, text="↺  Reset Defaults", command=self._reset,
                  bg=_p("BG_LIGHT"), fg=_p("FG_DIM"), font=FONT_UI(),
                  relief="flat", cursor="hand2", padx=14, pady=5).pack(side="right", padx=10)

    def _row(self, parent, row, label, key, val, tooltip="", width=14):
        tk.Label(parent, text=label+":", bg=_p("BG_DARK"), fg=_p("FG_MAIN"),
                 font=FONT_UI()).grid(row=row, column=0, sticky="w", padx=12, pady=5)
        var = tk.StringVar(value=str(val))
        self._vars[key] = var
        e = tk.Entry(parent, textvariable=var, bg=_p("BG_MED"), fg=_p("FG_MAIN"),
                     insertbackground=_p("FG_MAIN"), width=width, relief="flat")
        e.grid(row=row, column=1, sticky="w", padx=8, pady=5)
        if tooltip:
            tk.Label(parent, text=tooltip, bg=_p("BG_DARK"), fg=_p("FG_DIM"),
                     font=("Segoe UI", 8)).grid(row=row, column=2, sticky="w", padx=4)
        return var

    def _check(self, parent, row, label, key, val, tooltip=""):
        var = tk.BooleanVar(value=bool(val))
        self._vars[key] = var
        tk.Checkbutton(parent, text=label, variable=var,
                       bg=_p("BG_DARK"), fg=_p("FG_MAIN"),
                       selectcolor=_p("BG_MED"), activebackground=_p("BG_DARK"),
                       activeforeground=_p("FG_ACCENT"),
                       font=FONT_UI()).grid(row=row, column=0, columnspan=2,
                                           sticky="w", padx=12, pady=4)
        if tooltip:
            tk.Label(parent, text=tooltip, bg=_p("BG_DARK"), fg=_p("FG_DIM"),
                     font=("Segoe UI",8)).grid(row=row, column=2, sticky="w", padx=4)

    def _section_label(self, parent, row, text):
        tk.Label(parent, text=text, bg=_p("BG_DARK"), fg=_p("FG_ACCENT"),
                 font=FONT_HEAD()).grid(row=row, column=0, columnspan=3,
                                       sticky="w", padx=10, pady=(12,2))

    # ── Tab: Analysis ─────────────────────────────────────────────────────────
    def _tab_analysis(self, f):
        f.columnconfigure(2, weight=1)
        self._section_label(f, 0, "Entropy Thresholds")
        self._row(f, 1, "Low threshold",   "ENTROPY_LOW",  config.ENTROPY_LOW,  "Sections below = green (code/data)")
        self._row(f, 2, "High threshold",  "ENTROPY_HIGH", config.ENTROPY_HIGH, "Sections above = red (packed/encrypted)")
        self._section_label(f, 3, "Detection")
        self._row(f, 4, "Junk ratio threshold", "JUNK_RATIO_THRESHOLD",   config.JUNK_RATIO_THRESHOLD,   "Flag if > this fraction of instructions are junk")
        self._row(f, 5, "Chi-square p-value",   "CHI_SQUARE_P_THRESHOLD", config.CHI_SQUARE_P_THRESHOLD, "p > this = uniform byte dist (encrypted)")
        self._section_label(f, 6, "Sliding Window")
        self._row(f, 7, "Window size (bytes)", "SLIDING_WINDOW_SIZE", config.SLIDING_WINDOW_SIZE, "Heatmap window granularity")
        self._row(f, 8, "Window step (bytes)", "SLIDING_WINDOW_STEP", config.SLIDING_WINDOW_STEP, "50% overlap = window/2")
        self._section_label(f, 9, "Display Limits")
        self._row(f, 10, "Max hex bytes",       "MAX_HEX_BYTES",         config.MAX_HEX_BYTES,         "Bytes shown in hex dump tab")
        self._row(f, 11, "Max disasm insns",    "MAX_DISASM_INSNS",      config.MAX_DISASM_INSNS,      "Instructions shown in disassembly tab")
        self._row(f, 12, "Max strings",         "MAX_STRINGS_DISPLAY",   config.MAX_STRINGS_DISPLAY,   "Strings shown per section")
        self._row(f, 13, "Min string length",   "MIN_STRING_LEN",        config.MIN_STRING_LEN,        "Minimum printable chars to extract")

    # ── Tab: Weights ──────────────────────────────────────────────────────────
    def _tab_weights(self, f):
        f.columnconfigure(2, weight=1)
        self._section_label(f, 0, "Confidence Score Weights  (total max = 100)")
        wt = config.WEIGHTS
        descs = [
            ("decryptor_loop",        "Decryptor loop detected",         "Highest-value indicator"),
            ("high_entropy_contrast", "High/low entropy contrast",       "Packer signature"),
            ("junk_ratio",            "Junk instruction ratio",          "Obfuscation padding"),
            ("chi_square",            "Chi-square uniform distribution", "Encrypted bytes"),
            ("crypto_const",          "Crypto constants found",          "Algorithm signatures"),
            ("rwx_section",           "RWX section present",             "Self-modifying code"),
            ("entry_point_anomaly",   "Entry point anomaly",             "EP outside .text"),
            ("few_imports",           "Very few imports (<5)",           "Packer stub"),
        ]
        for i, (key, label, tip) in enumerate(descs, start=1):
            self._row(f, i, label, f"W_{key}", wt.get(key, 0), tip, width=6)

    # ── Tab: VirusTotal ───────────────────────────────────────────────────────
    def _tab_vt(self, f):
        f.columnconfigure(1, weight=1)
        self._section_label(f, 0, "VirusTotal API Configuration")

        tk.Label(f, text="API Key:", bg=_p("BG_DARK"), fg=_p("FG_MAIN"),
                 font=FONT_UI()).grid(row=1, column=0, sticky="w", padx=12, pady=6)
        key_var = tk.StringVar(value=config.VT_API_KEY)
        self._vars["VT_API_KEY"] = key_var
        key_entry = tk.Entry(f, textvariable=key_var, bg=_p("BG_MED"),
                             fg=_p("FG_MAIN"), insertbackground=_p("FG_MAIN"),
                             width=52, show="•", relief="flat")
        key_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=8, pady=6)

        def toggle_show():
            key_entry.config(show="" if key_entry.cget("show") else "•")
        tk.Button(f, text="👁", command=toggle_show,
                  bg=_p("BG_LIGHT"), fg=_p("FG_MAIN"), relief="flat",
                  cursor="hand2", padx=6).grid(row=1, column=3, padx=4)

        self._net_label = tk.Label(f, text="", bg=_p("BG_DARK"),
                                   fg=_p("FG_DIM"), font=("Segoe UI",8))
        self._net_label.grid(row=2, column=0, columnspan=4, sticky="w", padx=12)

        def test_key():
            self._net_label.config(text="Testing...", fg=_p("FG_ACCENT"))
            self.update_idletasks()
            def _run():
                ok, msg = vt_mod.check_api_key(key_var.get())
                col = _p("FG_GREEN") if ok else _p("FG_RED")
                self.after(0, lambda: self._net_label.config(text=msg, fg=col))
            threading.Thread(target=_run, daemon=True).start()

        def check_net():
            self._net_label.config(text="Checking...", fg=_p("FG_ACCENT"))
            self.update_idletasks()
            def _run():
                ok = vt_mod.check_network()
                msg = "Network: reachable ✔" if ok else "Network: offline or VT unreachable ✖"
                col = _p("FG_GREEN") if ok else _p("FG_RED")
                self.after(0, lambda: self._net_label.config(text=msg, fg=col))
            threading.Thread(target=_run, daemon=True).start()

        btn_f = tk.Frame(f, bg=_p("BG_DARK"))
        btn_f.grid(row=3, column=0, columnspan=4, sticky="w", padx=10, pady=4)
        tk.Button(btn_f, text="Test API Key", command=test_key,
                  bg=_p("FG_ACCENT"), fg=_p("BG_DARK"), font=FONT_UI(),
                  relief="flat", cursor="hand2", padx=12, pady=4).pack(side="left", padx=4)
        tk.Button(btn_f, text="Check Network", command=check_net,
                  bg=_p("BG_LIGHT"), fg=_p("FG_MAIN"), font=FONT_UI(),
                  relief="flat", cursor="hand2", padx=12, pady=4).pack(side="left", padx=4)
        tk.Button(btn_f, text="Clear Key", command=lambda: key_var.set(""),
                  bg=_p("BG_LIGHT"), fg=_p("FG_DIM"), font=FONT_UI(),
                  relief="flat", cursor="hand2", padx=12, pady=4).pack(side="left", padx=4)

        self._section_label(f, 5, "Behaviour")
        tk.Label(f, text="ℹ  VirusTotal is automatically enabled when an API key is set.",
                 bg=_p("BG_DARK"), fg=_p("FG_GREEN"),
                 font=("Segoe UI", 8)).grid(row=6, column=0, columnspan=4, sticky="w", padx=12, pady=(0,4))
        self._check(f, 7,  "Auto-submit on file open",     "VT_AUTO_SUBMIT", config.VT_AUTO_SUBMIT,
                    "(only if API key is set & network available)")
        self._row(f, 8, "Request timeout (sec)", "VT_TIMEOUT",          config.VT_TIMEOUT,          "", 6)
        self._row(f, 9, "Rate-limit delay (sec)","VT_RATE_LIMIT_DELAY", config.VT_RATE_LIMIT_DELAY, "Free tier: 16s (4 req/min)", 6)

        tk.Label(f, text="ℹ  The API key is stored in settings.json next to the script.\n"
                         "   It is never sent anywhere except VirusTotal's official API.",
                 bg=_p("BG_DARK"), fg=_p("FG_DIM"),
                 font=("Segoe UI",8), justify="left").grid(
                     row=10, column=0, columnspan=4, sticky="w", padx=12, pady=12)

    # ── Tab: Interface ────────────────────────────────────────────────────────
    def _tab_gui(self, f):
        f.columnconfigure(2, weight=1)
        self._section_label(f, 0, "Typography")
        self._row(f, 1, "Mono font size",  "GUI_FONT_MONO_SIZE", config.GUI_FONT_MONO_SIZE, "Hex/asm/strings tabs", 5)
        self._row(f, 2, "UI font size",    "GUI_FONT_UI_SIZE",   config.GUI_FONT_UI_SIZE,   "Menus, labels, tree",  5)
        self._section_label(f, 3, "Window")
        self._row(f, 4, "Default width",  "GUI_WINDOW_W",   config.GUI_WINDOW_W,   "px", 6)
        self._row(f, 5, "Default height", "GUI_WINDOW_H",   config.GUI_WINDOW_H,   "px", 6)
        self._row(f, 6, "Heatmap height", "GUI_HEATMAP_H",  config.GUI_HEATMAP_H,  "px", 6)
        self._section_label(f, 7, "Accent Color")
        self._row(f, 8, "Accent hex color", "GUI_ACCENT_COLOR", config.GUI_ACCENT_COLOR,
                  "e.g. #00d4ff  #ff6b35  #7c3aed", 10)
        self._section_label(f, 9, "Behaviour")
        self._check(f, 10, "Show entropy legend below heatmap",       "GUI_SHOW_LEGEND",       config.GUI_SHOW_LEGEND)
        self._check(f, 11, "Show tooltips in status bar on hover",    "GUI_SHOW_TOOLTIPS",     config.GUI_SHOW_TOOLTIPS)
        self._check(f, 12, "Auto-select first section after analysis","GUI_AUTO_SELECT_FIRST", config.GUI_AUTO_SELECT_FIRST)

        tk.Label(f, text="⚠  Font size and accent color changes take effect on next launch.",
                 bg=_p("BG_DARK"), fg=_p("FG_DIM"),
                 font=("Segoe UI",8)).grid(row=13, column=0, columnspan=3,
                                           sticky="w", padx=12, pady=8)

    # ── Tab: Imports ──────────────────────────────────────────────────────────
    def _tab_imports(self, f):
        f.columnconfigure(0, weight=1)
        f.rowconfigure(1, weight=1)
        tk.Label(f, text="Suspicious Import List  (one per line)",
                 bg=_p("BG_DARK"), fg=_p("FG_ACCENT"), font=FONT_HEAD()).grid(
                     row=0, column=0, sticky="w", padx=10, pady=(10,4))
        box = scrolledtext.ScrolledText(f, bg=_p("BG_MED"), fg=_p("FG_MAIN"),
                                        font=("Courier New",9),
                                        insertbackground=_p("FG_MAIN"), relief="flat")
        box.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0,6))
        box.insert("end", "\n".join(config.SUSPICIOUS_IMPORTS))
        self._vars["SUSPICIOUS_IMPORTS_TEXT"] = box
        tk.Label(f, text="Changes take effect on next analysis run.",
                 bg=_p("BG_DARK"), fg=_p("FG_DIM"),
                 font=("Segoe UI",8)).grid(row=2, column=0, sticky="w", padx=12)

    # ── Apply ─────────────────────────────────────────────────────────────────
    def _apply(self):
        try:
            # Analysis
            config.ENTROPY_LOW            = float(self._vars["ENTROPY_LOW"].get())
            config.ENTROPY_HIGH           = float(self._vars["ENTROPY_HIGH"].get())
            config.JUNK_RATIO_THRESHOLD   = float(self._vars["JUNK_RATIO_THRESHOLD"].get())
            config.CHI_SQUARE_P_THRESHOLD = float(self._vars["CHI_SQUARE_P_THRESHOLD"].get())
            config.SLIDING_WINDOW_SIZE    = int(self._vars["SLIDING_WINDOW_SIZE"].get())
            config.SLIDING_WINDOW_STEP    = int(self._vars["SLIDING_WINDOW_STEP"].get())
            config.MAX_HEX_BYTES          = int(self._vars["MAX_HEX_BYTES"].get())
            config.MAX_DISASM_INSNS       = int(self._vars["MAX_DISASM_INSNS"].get())
            config.MAX_STRINGS_DISPLAY    = int(self._vars["MAX_STRINGS_DISPLAY"].get())
            config.MIN_STRING_LEN         = int(self._vars["MIN_STRING_LEN"].get())
            # Weights
            for k in ["decryptor_loop","high_entropy_contrast","junk_ratio","chi_square",
                      "crypto_const","rwx_section","entry_point_anomaly","few_imports"]:
                config.WEIGHTS[k] = int(self._vars[f"W_{k}"].get())
            # VT — key presence IS the enable switch (vt_is_enabled() checks it)
            config.VT_API_KEY          = self._vars["VT_API_KEY"].get().strip()
            config.VT_AUTO_SUBMIT      = bool(self._vars["VT_AUTO_SUBMIT"].get())
            config.VT_TIMEOUT          = int(self._vars["VT_TIMEOUT"].get())
            config.VT_RATE_LIMIT_DELAY = int(self._vars["VT_RATE_LIMIT_DELAY"].get())
            # GUI
            config.GUI_FONT_MONO_SIZE    = int(self._vars["GUI_FONT_MONO_SIZE"].get())
            config.GUI_FONT_UI_SIZE      = int(self._vars["GUI_FONT_UI_SIZE"].get())
            config.GUI_WINDOW_W          = int(self._vars["GUI_WINDOW_W"].get())
            config.GUI_WINDOW_H          = int(self._vars["GUI_WINDOW_H"].get())
            config.GUI_HEATMAP_H         = int(self._vars["GUI_HEATMAP_H"].get())
            config.GUI_ACCENT_COLOR      = self._vars["GUI_ACCENT_COLOR"].get().strip()
            config.GUI_SHOW_LEGEND       = bool(self._vars["GUI_SHOW_LEGEND"].get())
            config.GUI_SHOW_TOOLTIPS     = bool(self._vars["GUI_SHOW_TOOLTIPS"].get())
            config.GUI_AUTO_SELECT_FIRST = bool(self._vars["GUI_AUTO_SELECT_FIRST"].get())
            # Imports list
            raw = self._vars["SUSPICIOUS_IMPORTS_TEXT"].get("1.0","end")
            config.SUSPICIOUS_IMPORTS = [l.strip() for l in raw.splitlines() if l.strip()]
            # Persist
            config.save()
            self.destroy()
        except Exception as e:
            messagebox.showerror("Settings Error", str(e), parent=self)

    def _reset(self):
        if messagebox.askyesno("Reset", "Reset all settings to defaults?", parent=self):
            import importlib, sys
            # Reload defaults by re-reading defaults from scratch
            messagebox.showinfo("Reset", "Close and reopen Settings to see defaults.\n"
                                "Delete settings.json to fully reset.", parent=self)


# ══════════════════════════════════════════════════════════════════════════════
#  ABOUT DIALOG
# ══════════════════════════════════════════════════════════════════════════════
class AboutDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("About")
        self.configure(bg=_p("BG_DARK"))
        self.geometry("480x420")
        self.resizable(False, False)
        self.grab_set()
        self.transient(parent)
        self._build()
        self.wait_window()

    def _build(self):
        # Title banner
        banner = tk.Frame(self, bg=_p("BG_LIGHT"), pady=18)
        banner.pack(fill="x")
        tk.Label(banner, text="🔬", bg=_p("BG_LIGHT"),
                 font=("Segoe UI Emoji",36)).pack()
        tk.Label(banner, text=config.APP_NAME,
                 bg=_p("BG_LIGHT"), fg=_p("FG_ACCENT"),
                 font=("Segoe UI",18,"bold")).pack()
        tk.Label(banner, text=config.APP_TAGLINE,
                 bg=_p("BG_LIGHT"), fg=_p("FG_DIM"),
                 font=("Segoe UI",9,"italic")).pack(pady=(2,0))

        body = tk.Frame(self, bg=_p("BG_DARK"))
        body.pack(fill="both", expand=True, padx=30, pady=20)

        def row(label, val, val_color=None):
            f = tk.Frame(body, bg=_p("BG_DARK"))
            f.pack(fill="x", pady=3)
            tk.Label(f, text=f"{label:<18}", bg=_p("BG_DARK"), fg=_p("FG_DIM"),
                     font=("Segoe UI",9)).pack(side="left")
            tk.Label(f, text=val, bg=_p("BG_DARK"),
                     fg=val_color or _p("FG_MAIN"),
                     font=("Segoe UI",9,"bold")).pack(side="left")

        row("Version",    config.APP_VERSION,   _p("FG_ACCENT"))
        row("Author",     config.APP_AUTHOR,     _p("FG_GREEN"))
        row("GitHub",     config.GITHUB_URL,     _p("FG_ACCENT"))
        row("License",    "MIT — Free to use")

        tk.Frame(body, bg=_p("BG_LIGHT"), height=1).pack(fill="x", pady=12)

        tk.Label(body,
                 text="Adaptive Entropy Analyzer is a static malware triage\n"
                      "tool built for reverse engineers and security analysts.\n\n"
                      "It combines Shannon entropy analysis, disassembly-based\n"
                      "loop detection, statistical testing, and VirusTotal\n"
                      "integration into a single unified interface.",
                 bg=_p("BG_DARK"), fg=_p("FG_MAIN"),
                 font=("Segoe UI",9), justify="center").pack()

        tk.Frame(body, bg=_p("BG_LIGHT"), height=1).pack(fill="x", pady=12)

        tk.Label(body,
                 text="Developed with ❤  by Yx0R",
                 bg=_p("BG_DARK"), fg=_p("FG_DIM"),
                 font=("Segoe UI",8,"italic")).pack()

        tk.Button(self, text="Close", command=self.destroy,
                  bg=_p("BG_LIGHT"), fg=_p("FG_MAIN"), font=FONT_UI(),
                  relief="flat", cursor="hand2", padx=20, pady=6).pack(pady=12)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class AdaptiveEntropyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{config.APP_NAME}  v{config.APP_VERSION}  —  by {config.APP_AUTHOR}")
        self.configure(bg=_p("BG_DARK"))
        self.geometry(f"{config.GUI_WINDOW_W}x{config.GUI_WINDOW_H}")
        self.minsize(1000, 640)

        self._parsed       = None
        self._results      = None
        self._current_sec  = None
        self._section_list = []
        self._file_hashes  = {}
        self._vt_result    = None
        self._network_ok   = False

        # Check network in background immediately
        threading.Thread(target=self._bg_net_check, daemon=True).start()

        self._build_ui()
        self._apply_style()

    def _bg_net_check(self):
        ok = vt_mod.check_network()
        self._network_ok = ok
        # VT_ENABLED is now derived from whether a key exists (config.vt_is_enabled())
        # No side-effects here — just update the status indicator
        self.after(0, self._update_vt_status_indicator)

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_menubar()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

    def _build_menubar(self):
        mb = tk.Menu(self, bg=_p("BG_MED"), fg=_p("FG_MAIN"),
                     activebackground=_p("BG_LIGHT"),
                     activeforeground=_p("FG_ACCENT"),
                     relief="flat", borderwidth=0)
        self.config(menu=mb)

        fm = tk.Menu(mb, tearoff=0, bg=_p("BG_MED"), fg=_p("FG_MAIN"),
                     activebackground=_p("BG_LIGHT"), activeforeground=_p("FG_ACCENT"))
        fm.add_command(label="Open File…",      command=self._open_file)
        fm.add_command(label="Re-Analyze",       command=self._run_analysis)
        fm.add_separator()
        fm.add_command(label="Export JSON…",     command=lambda: self._export("json"))
        fm.add_command(label="Export HTML…",     command=lambda: self._export("html"))
        fm.add_separator()
        fm.add_command(label="Exit",             command=self.quit)
        mb.add_cascade(label="File", menu=fm)

        am = tk.Menu(mb, tearoff=0, bg=_p("BG_MED"), fg=_p("FG_MAIN"),
                     activebackground=_p("BG_LIGHT"), activeforeground=_p("FG_ACCENT"))
        am.add_command(label="Analyze",          command=self._run_analysis)
        am.add_command(label="VirusTotal Lookup",command=self._vt_lookup)
        am.add_command(label="VirusTotal Submit",command=self._vt_submit)
        mb.add_cascade(label="Analysis", menu=am)

        tm = tk.Menu(mb, tearoff=0, bg=_p("BG_MED"), fg=_p("FG_MAIN"),
                     activebackground=_p("BG_LIGHT"), activeforeground=_p("FG_ACCENT"))
        tm.add_command(label="Settings…",        command=self._settings)
        mb.add_cascade(label="Tools", menu=tm)

        hm = tk.Menu(mb, tearoff=0, bg=_p("BG_MED"), fg=_p("FG_MAIN"),
                     activebackground=_p("BG_LIGHT"), activeforeground=_p("FG_ACCENT"))
        hm.add_command(label=f"About {config.APP_NAME}…", command=self._about)
        mb.add_cascade(label="Help", menu=hm)

    def _build_toolbar(self):
        tb = tk.Frame(self, bg=_p("BG_MED"), pady=6)
        tb.pack(side="top", fill="x")

        def btn(text, cmd, accent=False, color=None):
            b = tk.Button(tb, text=text, command=cmd,
                bg=color or (_p("FG_ACCENT") if accent else _p("BG_LIGHT")),
                fg=_p("BG_DARK") if accent else _p("FG_MAIN"),
                font=FONT_HEAD(), relief="flat", cursor="hand2", padx=13, pady=4)
            return b

        btn("📂  Open",      self._open_file).pack(side="left", padx=6)
        btn("🔍  Analyze",   self._run_analysis, accent=True).pack(side="left", padx=4)
        btn("💾  Export",    self._export).pack(side="left", padx=4)

        # VT button — dynamic label
        self._vt_btn = btn("🌐  VirusTotal", self._vt_lookup,
                           color=_p("BG_LIGHT"))
        self._vt_btn.pack(side="left", padx=4)

        btn("⚙  Settings",  self._settings).pack(side="left", padx=4)
        btn("ℹ  About",     self._about).pack(side="left", padx=4)

        # Separator
        tk.Frame(tb, bg=_p("BG_LIGHT"), width=2).pack(side="left", fill="y",
                                                        padx=8, pady=4)

        self._file_label = tk.Label(tb, text="No file loaded",
                                    bg=_p("BG_MED"), fg=_p("FG_DIM"), font=FONT_UI())
        self._file_label.pack(side="left", padx=4)

        # Right side: VT status + verdict
        self._vt_status_lbl = tk.Label(tb, text="", bg=_p("BG_MED"),
                                       fg=_p("FG_DIM"), font=("Segoe UI",8))
        self._vt_status_lbl.pack(side="right", padx=8)

        self._verdict_label = tk.Label(tb, text="", bg=_p("BG_MED"),
                                       fg=_p("FG_ACCENT"), font=FONT_HEAD())
        self._verdict_label.pack(side="right", padx=10)

        # Author credit — subtle
        tk.Label(tb, text=f"by {config.APP_AUTHOR}",
                 bg=_p("BG_MED"), fg=_p("FG_DIM"),
                 font=("Segoe UI",8,"italic")).pack(side="right", padx=4)

    def _build_body(self):
        outer = tk.PanedWindow(self, orient="horizontal", bg=_p("BG_DARK"),
                               sashwidth=5, sashrelief="flat")
        outer.pack(fill="both", expand=True, padx=4, pady=4)

        left = tk.Frame(outer, bg=_p("BG_DARK"), width=320)
        outer.add(left, minsize=220)
        self._build_left(left)

        rp = tk.PanedWindow(outer, orient="vertical", bg=_p("BG_DARK"), sashwidth=5)
        outer.add(rp, minsize=500)

        hm = tk.Frame(rp, bg=_p("BG_DARK"))
        rp.add(hm, minsize=config.GUI_HEATMAP_H + 30)
        self._build_heatmap(hm)

        tabs = tk.Frame(rp, bg=_p("BG_DARK"))
        rp.add(tabs, minsize=280)
        self._build_notebook(tabs)

    def _build_left(self, parent):
        tk.Label(parent, text="Sections", bg=_p("BG_DARK"), fg=_p("FG_ACCENT"),
                 font=FONT_HEAD()).pack(anchor="w", padx=6, pady=(6,2))

        tf = tk.Frame(parent, bg=_p("BG_DARK"))
        tf.pack(fill="both", expand=True, padx=4, pady=(0,4))

        cols = ("Name","Entropy","Score","Perms","Junk%")
        self._tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        for col, w in zip(cols, [95,65,58,50,48]):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, anchor="center", stretch=False)
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._tree.bind("<<TreeviewSelect>>", self._on_sec_select)
        self._tree.bind("<Double-1>",         self._on_sec_select)

        tk.Label(parent, text="Indicators", bg=_p("BG_DARK"), fg=_p("FG_ACCENT"),
                 font=FONT_HEAD()).pack(anchor="w", padx=6, pady=(4,2))

        inf = tk.Frame(parent, bg=_p("BG_DARK"))
        inf.pack(fill="both", expand=True, padx=4, pady=(0,4))
        self._ind_text = tk.Text(inf, bg=_p("BG_MED"), fg=_p("FG_MAIN"),
                                 font=("Segoe UI",8), wrap="word",
                                 state="disabled", relief="flat", height=10)
        isb = ttk.Scrollbar(inf, orient="vertical", command=self._ind_text.yview)
        self._ind_text.configure(yscrollcommand=isb.set)
        self._ind_text.pack(side="left", fill="both", expand=True)
        isb.pack(side="right", fill="y")

    def _build_heatmap(self, parent):
        hdr = tk.Frame(parent, bg=_p("BG_DARK"))
        hdr.pack(fill="x", padx=6, pady=(4,0))
        tk.Label(hdr, text="Entropy Heatmap", bg=_p("BG_DARK"),
                 fg=_p("FG_ACCENT"), font=FONT_HEAD()).pack(side="left")
        tk.Label(hdr, text="  (click to inspect  •  hover for details)",
                 bg=_p("BG_DARK"), fg=_p("FG_DIM"), font=FONT_UI()).pack(side="left")

        self._canvas = tk.Canvas(parent, bg=_p("BG_CARD"),
                                 height=config.GUI_HEATMAP_H, highlightthickness=0)
        self._canvas.pack(fill="x", padx=6, pady=4)
        self._canvas.bind("<Button-1>", self._on_hm_click)
        self._canvas.bind("<Motion>",   self._on_hm_hover)
        self._canvas.bind("<Configure>",lambda e: self._redraw_hm())

        if config.GUI_SHOW_LEGEND:
            leg = tk.Frame(parent, bg=_p("BG_DARK"))
            leg.pack(fill="x", padx=10, pady=(0,2))
            for lbl, col in [("Plaintext <5.0", _p("FG_GREEN")),
                              ("Code 5.0–6.5",  _p("FG_YELLOW")),
                              ("Packed 6.5–7.2",_p("FG_ORANGE")),
                              ("Encrypted >7.2",_p("FG_RED"))]:
                tk.Label(leg, text="■ "+lbl, bg=_p("BG_DARK"), fg=col,
                         font=("Segoe UI",8)).pack(side="left", padx=8)

    def _build_notebook(self, parent):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=_p("BG_DARK"), borderwidth=0)
        style.configure("TNotebook.Tab", background=_p("BG_MED"), foreground=_p("FG_MAIN"),
                        padding=[11,4], font=FONT_UI())
        style.map("TNotebook.Tab",
                  background=[("selected", _p("BG_LIGHT"))],
                  foreground=[("selected", _p("FG_ACCENT"))])

        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True, padx=4, pady=4)
        self._nb = nb

        for text, attr in [
            ("📊 Section Info",   "_info_text"),
            ("📋 File Summary",   "_sum_text"),
            ("🌐 VirusTotal",     "_vt_text"),
            ("🔢 Hex Dump",       "_hex_text"),
            ("⚙ Disassembly",    "_asm_text"),
            ("📝 Strings",        "_str_text"),
            ("📦 Imports",        "_imp_text"),
        ]:
            f = tk.Frame(nb, bg=_p("BG_DARK"))
            nb.add(f, text=text)
            setattr(self, attr, self._make_text(f))

    def _make_text(self, parent):
        t = scrolledtext.ScrolledText(parent, bg=_p("BG_MED"), fg=_p("FG_MAIN"),
                                      font=FONT_MONO(), wrap="none",
                                      state="disabled", relief="flat",
                                      insertbackground=_p("FG_MAIN"))
        t.pack(fill="both", expand=True)
        t.tag_configure("header",  foreground=_p("FG_ACCENT"), font=(FONT_MONO()[0], FONT_MONO()[1], "bold"))
        t.tag_configure("title",   foreground=_p("FG_WHITE"),  font=(FONT_MONO()[0], FONT_MONO()[1]+1, "bold"))
        t.tag_configure("high",    foreground=_p("FG_RED"))
        t.tag_configure("orange",  foreground=_p("FG_ORANGE"))
        t.tag_configure("med",     foreground=_p("FG_YELLOW"))
        t.tag_configure("low",     foreground=_p("FG_GREEN"))
        t.tag_configure("dim",     foreground=_p("FG_DIM"))
        t.tag_configure("sus",     foreground=_p("FG_RED"), font=(FONT_MONO()[0], FONT_MONO()[1], "bold"))
        t.tag_configure("accent",  foreground=_p("FG_ACCENT"))
        t.tag_configure("ok",      foreground=_p("FG_GREEN"))
        return t

    def _build_statusbar(self):
        sb = tk.Frame(self, bg=_p("BG_MED"), pady=3)
        sb.pack(side="bottom", fill="x")

        # Author credit in status bar
        tk.Label(sb,
                 text=f" {config.APP_NAME} v{config.APP_VERSION}  |  {config.APP_AUTHOR} ",
                 bg=_p("BG_MED"), fg=_p("FG_DIM"),
                 font=("Segoe UI",8)).pack(side="right", padx=6)

        self._prog = ttk.Progressbar(sb, length=200, mode="determinate")
        self._prog.pack(side="right", padx=6)

        self._status = tk.Label(sb, text="Ready — open a file to begin",
                                bg=_p("BG_MED"), fg=_p("FG_DIM"),
                                font=FONT_UI(), anchor="w")
        self._status.pack(side="left", padx=10)

    def _apply_style(self):
        s = ttk.Style()
        s.configure("Treeview", background=_p("BG_MED"), foreground=_p("FG_MAIN"),
                    fieldbackground=_p("BG_MED"), rowheight=22, font=FONT_UI())
        s.configure("Treeview.Heading", background=_p("BG_LIGHT"),
                    foreground=_p("FG_ACCENT"), font=FONT_HEAD())
        s.map("Treeview",
              background=[("selected", _p("BG_LIGHT"))],
              foreground=[("selected", _p("FG_ACCENT"))])

    # ── Network / VT status ───────────────────────────────────────────────────

    def _update_vt_status_indicator(self):
        if not hasattr(self, "_vt_status_lbl"):
            return
        has_key = config.vt_is_enabled()
        if self._network_ok and has_key:
            self._vt_status_lbl.config(text="🌐 VT: ready", fg=_p("FG_GREEN"))
            self._vt_btn.config(bg="#1b4f1b")
        elif has_key and not self._network_ok:
            self._vt_status_lbl.config(text="🌐 VT: offline", fg=_p("FG_ORANGE"))
        elif self._network_ok and not has_key:
            self._vt_status_lbl.config(text="🌐 VT: no key", fg=_p("FG_ORANGE"))
        else:
            self._vt_status_lbl.config(text="🌐 offline", fg=_p("FG_DIM"))

    # ── File open ──────────────────────────────────────────────────────────────

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Open Executable",
            filetypes=[("All supported","*.exe *.dll *.sys *.elf *.so *.dylib *.apk *.dex *"),
                       ("PE","*.exe *.dll *.sys"),("ELF","*.elf *.so *"),
                       ("Mach-O","*.dylib *"),("APK","*.apk"),("All","*")])
        if not path: return
        self._stat(f"Loading: {os.path.basename(path)}", 5)
        self._parsed = self._results = None
        self._file_hashes = {}
        try:
            pf = file_parser.load_file(path)
            if pf.error:
                messagebox.showerror("Parse Error", pf.error)
                self._stat("Error loading file", 0); return
            pf.filename  = path
            self._parsed = pf
            self._file_hashes = vt_mod.file_hashes(path)
            self._file_label.config(
                text=f"{os.path.basename(path)}   [{pf.file_type} / {pf.arch}]",
                fg=_p("FG_MAIN"))
            self._stat(f"Loaded: {os.path.basename(path)}", 100)
            self._run_analysis()
            if config.VT_AUTO_SUBMIT and config.vt_is_enabled() and self._network_ok:
                self.after(500, self._vt_lookup)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self._stat("Error", 0)

    # ── Analysis ───────────────────────────────────────────────────────────────

    def _run_analysis(self):
        if not self._parsed:
            messagebox.showwarning("No File","Open a file first."); return
        self._stat("Analyzing...", 0)
        self._verdict_label.config(text="Analyzing...", fg=_p("FG_ACCENT"))

        def worker():
            def cb(msg, pct): self.after(0, lambda: self._stat(msg, pct))
            try:
                res = analyzer.analyze(self._parsed, progress_cb=cb)
                res["filename"] = getattr(self._parsed, "filename", "")
                res["hashes"]   = self._file_hashes
                self.after(0, lambda: self._on_done(res))
            except Exception as e:
                import traceback; traceback.print_exc()
                self.after(0, lambda: messagebox.showerror("Analysis Error", str(e)))
                self.after(0, lambda: self._stat("Analysis failed", 0))

        threading.Thread(target=worker, daemon=True).start()

    def _on_done(self, results):
        self._results      = results
        self._section_list = results.get("sections", [])
        self._populate_tree()
        self._redraw_hm()
        self._update_indicators()
        self._update_imports()
        self._update_file_summary()
        self._update_verdict()
        self._update_vt_tab_placeholder()
        if self._section_list and config.GUI_AUTO_SELECT_FIRST:
            self._show_section(self._section_list[0])
            ch = self._tree.get_children()
            if ch: self._tree.selection_set(ch[0])
        self._stat("Analysis complete", 100)

    # ── VT integration ─────────────────────────────────────────────────────────

    def _vt_lookup(self):
        if not self._parsed:
            messagebox.showwarning("No File", "Open and analyze a file first."); return
        if not config.vt_is_enabled():
            messagebox.showinfo("VirusTotal",
                "No API key configured.\n\nGo to:  Settings → VirusTotal tab\n"
                "Paste your key and click  Save & Apply.\n\n"
                "Free keys: https://www.virustotal.com/gui/join-us"); return
        if not self._network_ok:
            messagebox.showwarning("Offline",
                "No network connection detected.\n\n"
                "The tool will retry connectivity automatically.\n"
                "Check your internet connection and try again."); return

        sha256 = self._file_hashes.get("sha256","")
        if not sha256:
            messagebox.showerror("Error","Could not compute file hash."); return

        self._stat("Querying VirusTotal...", 0)
        self._nb.select(2)  # Switch to VT tab
        self._set_vt_text("  Querying VirusTotal...\n\n  SHA256: "+sha256, "dim")

        def worker():
            raw = vt_mod.lookup_hash(sha256, config.VT_API_KEY, config.VT_TIMEOUT)
            report = vt_mod.parse_report(raw)
            self._vt_result = report
            self.after(0, lambda: self._display_vt_report(report))

        threading.Thread(target=worker, daemon=True).start()

    def _vt_submit(self):
        if not self._parsed:
            messagebox.showwarning("No File","Open a file first."); return
        if not config.vt_is_enabled():
            messagebox.showinfo("VirusTotal","No API key — configure in Settings → VirusTotal tab."); return
        if not self._network_ok:
            messagebox.showwarning("Offline","No network connection detected."); return
        path = getattr(self._parsed, "filename", "")
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error","Cannot locate source file for upload."); return
        size_mb = os.path.getsize(path) / (1024*1024)
        if size_mb > 32:
            messagebox.showwarning("File Too Large",
                f"File is {size_mb:.1f} MB — VT free tier limit is 32 MB."); return
        if not messagebox.askyesno("Submit to VirusTotal",
            f"Upload {os.path.basename(path)} ({size_mb:.2f} MB) to VirusTotal for scanning?\n\n"
            "This sends the file to VirusTotal's servers."): return

        self._stat("Uploading to VirusTotal...", 10)
        self._nb.select(2)
        self._set_vt_text("  Uploading file to VirusTotal...\n", "dim")

        def worker():
            submit = vt_mod.submit_file(path, config.VT_API_KEY, timeout=60)
            if "error" in submit:
                self.after(0, lambda: self._set_vt_text(
                    f"  Upload failed: {submit['error']}\n","high"))
                self.after(0, lambda: self._stat("VT upload failed",0))
                return
            aid = submit.get("analysis_id","")
            self.after(0, lambda: self._set_vt_text(
                f"  File submitted. Analysis ID: {aid}\n  Polling for results...\n","dim"))
            raw = vt_mod.get_analysis(aid, config.VT_API_KEY,
                                       config.VT_TIMEOUT, 20, 8)
            report = vt_mod.parse_report(raw)
            self._vt_result = report
            self.after(0, lambda: self._display_vt_report(report))

        threading.Thread(target=worker, daemon=True).start()

    def _display_vt_report(self, report: dict):
        t = self._vt_text
        t.config(state="normal")
        t.delete("1.0","end")

        def w(text, tag=None):
            t.insert("end", text, tag) if tag else t.insert("end", text)

        rule = "═"*68
        w(f"{rule}\n","header")
        w("  VIRUSTOTAL ANALYSIS REPORT\n","title")
        w(f"{rule}\n\n","header")

        if report.get("status") == "error":
            w(f"  ✖  Error: {report.get('message','Unknown error')}\n\n","high")
            if "not found" in str(report.get("message","")).lower():
                w("  This file has not been submitted to VirusTotal before.\n","dim")
                w("  Use Analysis → VirusTotal Submit to upload it.\n","dim")
            self._stat("VT: not found or error", 0)
            t.config(state="disabled")
            return

        verd    = report.get("vt_verdict","?")
        mal     = report.get("malicious",0)
        sus     = report.get("suspicious",0)
        total   = report.get("total",0)
        pct     = report.get("detect_pct",0)
        dets    = report.get("detections",[])

        # Verdict color
        if "MALICIOUS" in verd:  vtag = "high"
        elif "Likely"   in verd: vtag = "orange"
        elif "Suspicious" in verd: vtag = "med"
        else:                    vtag = "low"

        w("  ┌─ VERDICT ────────────────────────────────────────────────────┐\n","dim")
        w("  │  VT Verdict     ","dim"); w(f"{verd}\n",vtag)
        w("  │  Detections     ","dim"); w(f"{mal} malicious  +  {sus} suspicious  /  {total} engines\n",vtag)
        w("  │  Detection Rate ","dim"); w(f"{pct}%\n",vtag)
        # Detection bar
        filled = int(pct/100*48)
        w("  │  Risk Bar       ","dim"); w("█"*filled,vtag); w("░"*(48-filled)+"\n","dim")
        w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        w("  ┌─ FILE INFO ──────────────────────────────────────────────────┐\n","dim")
        for label, val in [
            ("Name",       report.get("name","")),
            ("Type",       report.get("file_type","")),
            ("SHA256",     report.get("sha256","")),
            ("First Seen", report.get("first_seen","")),
            ("Last Scan",  report.get("last_seen","")),
            ("Reputation", str(report.get("reputation",""))),
            ("Tags",       ", ".join(report.get("tags",[])) or "none"),
            ("YARA Hits",  str(report.get("yara_hits",0))),
        ]:
            if val:
                w(f"  │  {label:<16}","dim"); w(f"{val}\n")
        w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        # Hashes from our own computation
        if self._file_hashes:
            w("  ┌─ FILE HASHES ────────────────────────────────────────────────┐\n","dim")
            for alg in ("md5","sha1","sha256"):
                h = self._file_hashes.get(alg,"")
                if h:
                    w(f"  │  {alg.upper():<8}","dim"); w(f"{h}\n","accent")
            w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        if dets:
            w(f"  ┌─ DETECTIONS  ({len(dets)}) ─────────────────────────────────────────┐\n","dim")
            w("  │  Engine                  Category       Detection Name\n","header")
            w("  │  ─────────────────────────────────────────────────────────────\n","dim")
            for d in dets[:50]:
                cat_tag = "high" if d["category"]=="malicious" else "orange"
                w(f"  │  {d['engine']:<26}", "dim")
                w(f"{d['category']:<14}","orange" if d["category"]=="suspicious" else "high")
                w(f"{d['result']}\n")
            if len(dets) > 50:
                w(f"  │  ... and {len(dets)-50} more detections\n","dim")
            w("  └──────────────────────────────────────────────────────────────┘\n","dim")
        else:
            w("  ✓  No detections — file appears clean on VirusTotal.\n\n","low")

        verd_color = {"MALICIOUS":_p("FG_RED"),"Likely Malicious":_p("FG_ORANGE"),
                      "Suspicious":_p("FG_YELLOW"),"Low Detection":_p("FG_YELLOW"),
                      "Clean":_p("FG_GREEN")}.get(verd,_p("FG_DIM"))
        self._stat(f"VT: {verd}  ({mal}/{total} detections)", 100)
        t.config(state="disabled")

    def _update_vt_tab_placeholder(self):
        if not self._file_hashes:
            return
        t = self._vt_text
        t.config(state="normal"); t.delete("1.0","end")

        def w(text, tag=None):
            t.insert("end",text,tag) if tag else t.insert("end",text)

        sha256 = self._file_hashes.get("sha256","")
        w("  ┌─ VIRUSTOTAL ─────────────────────────────────────────────────┐\n","dim")
        for alg in ("md5","sha1","sha256"):
            h = self._file_hashes.get(alg,"")
            if h: w(f"  │  {alg.upper():<8}","dim"); w(f"{h}\n","accent")
        w("  │\n","dim")

        if not config.vt_is_enabled():
            w("  │  No API key configured.\n","orange")
            w("  │  Go to Settings → VirusTotal to add your key.\n","dim")
            w("  │  Free API keys: https://www.virustotal.com\n","dim")
        elif not self._network_ok:
            w("  │  Network unavailable — VT lookup disabled.\n","orange")
        else:
            w("  │  Click  Analysis → VirusTotal Lookup  or the toolbar button\n","dim")
            w("  │  to query this file hash against VirusTotal.\n","dim")
            w("  │\n","dim")
            w("  │  Auto-submit is ","dim")
            w("ON\n" if config.VT_AUTO_SUBMIT else "OFF\n",
              "low" if config.VT_AUTO_SUBMIT else "dim")
        w("  └──────────────────────────────────────────────────────────────┘\n","dim")
        t.config(state="disabled")

    def _set_vt_text(self, content, tag=None):
        t = self._vt_text
        t.config(state="normal"); t.delete("1.0","end")
        t.insert("end", content, tag)
        t.config(state="disabled")

    # ── Treeview ───────────────────────────────────────────────────────────────

    def _populate_tree(self):
        for r in self._tree.get_children(): self._tree.delete(r)
        for sec in self._section_list:
            e   = sec["entropy"]
            e_s = sec.get("entropy_score", round((e/8)*10,1))
            jr  = sec.get("junk_ratio",0.0)
            rwx = "🔴" if sec.get("rwx") else ""
            if e>=7.2: tag="high"
            elif e>=6.5: tag="orange"
            elif e>=5.0: tag="med"
            else: tag="low"
            self._tree.insert("","end",
                values=((sec["name"] or "(unnamed)")+rwx,
                        f"{e:.3f}", f"{e_s:.1f}/10",
                        sec.get("permissions","---"), f"{jr:.0%}"),
                tags=(tag,))
        self._tree.tag_configure("high",   foreground=_p("FG_RED"))
        self._tree.tag_configure("orange", foreground=_p("FG_ORANGE"))
        self._tree.tag_configure("med",    foreground=_p("FG_YELLOW"))
        self._tree.tag_configure("low",    foreground=_p("FG_GREEN"))

    # ── Heatmap ────────────────────────────────────────────────────────────────

    def _redraw_hm(self):
        c = self._canvas; c.delete("all")
        w = c.winfo_width() or 800
        h = c.winfo_height() or config.GUI_HEATMAP_H
        if not self._section_list:
            c.create_text(w//2,h//2,text="No data",fill=_p("FG_DIM"),font=FONT_UI()); return
        n = len(self._section_list); mg = 30
        bw = max(4,(w-mg-10)//n)
        for thresh,col in [(config.ENTROPY_LOW,_p("FG_YELLOW")),(config.ENTROPY_HIGH,_p("FG_RED"))]:
            y = h-20-int(thresh/8*(h-30))
            c.create_line(mg,y,w-4,y,fill=col,dash=(3,4))
        for val in (0,2,4,6,8):
            y = h-20-int(val/8*(h-30))
            c.create_line(mg-4,y,mg-2,y,fill=_p("FG_DIM"))
            c.create_text(mg-6,y,text=str(val),fill=_p("FG_DIM"),font=("Segoe UI",7),anchor="e")
        x = mg
        for i,sec in enumerate(self._section_list):
            e = sec["entropy"]; col = efg(e)
            bh = max(2,int((e/8)*(h-30)))
            c.create_rectangle(x,h-20-bh,x+bw-2,h-20,fill=col,outline="",tags=(f"b{i}",))
            if bw>22: c.create_text(x+bw//2,h-10,text=f"{e:.1f}",fill=_p("FG_DIM"),font=("Segoe UI",7))
            x += bw

    def _on_hm_click(self, event):
        if not self._section_list: return
        w = self._canvas.winfo_width(); n = len(self._section_list); bw = max(4,(w-40)//n)
        idx = max(0,min((event.x-30)//bw,n-1))
        self._show_section(self._section_list[idx])
        ch = self._tree.get_children()
        if 0<=idx<len(ch): self._tree.selection_set(ch[idx]); self._tree.see(ch[idx])

    def _on_hm_hover(self, event):
        if not self._section_list or not config.GUI_SHOW_TOOLTIPS: return
        w = self._canvas.winfo_width(); n = len(self._section_list); bw = max(4,(w-40)//n)
        idx = max(0,min((event.x-30)//bw,n-1))
        if 0<=idx<n:
            s = self._section_list[idx]
            self._stat(f"{s['name']}  |  {s['entropy']:.4f} bits/byte  "
                       f"|  {s.get('entropy_label','')}  |  {s.get('section_class','')}",
                       self._prog["value"])

    # ── Section ────────────────────────────────────────────────────────────────

    def _on_sec_select(self, event):
        sel = self._tree.selection()
        if not sel: return
        idx = self._tree.index(sel[0])
        if 0<=idx<len(self._section_list): self._show_section(self._section_list[idx])

    def _show_section(self, sec):
        self._current_sec = sec
        data   = sec.get("raw_data",b"")
        offset = sec.get("offset",0)
        arch   = self._parsed.arch if self._parsed else "x86"
        self._update_section_info(sec)
        self._set_text(self._hex_text, hex_asm.hex_dump(data, offset=offset, max_bytes=config.MAX_HEX_BYTES))
        self._set_text(self._asm_text, hex_asm.disassemble(data, arch=arch, offset=offset, max_insns=config.MAX_DISASM_INSNS))
        self._update_strings_tab(data)

    # ── Section Info tab ───────────────────────────────────────────────────────

    def _update_section_info(self, sec):
        t = self._info_text; t.config(state="normal"); t.delete("1.0","end")
        def w(x,tag=None): t.insert("end",x,tag) if tag else t.insert("end",x)

        name=sec.get("name","?"or"(unnamed)"); size=sec.get("size",0)
        offset=sec.get("offset",0); va=sec.get("virtual_address",0)
        perms=sec.get("permissions","---"); e=sec.get("entropy",0.0)
        e_s=sec.get("entropy_score",round((e/8)*10,2)); e_l=sec.get("entropy_label","")
        cls=sec.get("section_class","Unknown"); chi_p=sec.get("chi_p",1.0)
        chi_u=sec.get("chi_uniform",False); jr=sec.get("junk_ratio",0.0)
        rwx=sec.get("rwx",False); dom=sec.get("dominant_byte",{}); bf=sec.get("byte_freq",[])
        data=sec.get("raw_data",b"")

        if e>=7.2: etag="high"
        elif e>=6.5: etag="orange"
        elif e>=5.0: etag="med"
        else: etag="low"

        rule="═"*68
        w(f"{rule}\n","header"); w(f"  SECTION: {name}\n","title"); w(f"{rule}\n\n","header")

        w("  ┌─ BASIC INFO ─────────────────────────────────────────────────┐\n","dim")
        for lbl,val in [("Classification",cls),("Virtual Address",f"0x{va:08X}"),
                        ("File Offset",f"0x{offset:08X}"),
                        ("Raw Size",f"{size:,} bytes  ({size/1024:.1f} KB)" if size>=1024 else f"{size} bytes"),
                        ("Permissions",perms+("  ⚠ RWX — SUSPICIOUS" if rwx else ""))]:
            w(f"  │  {lbl:<20}","dim"); w(f"{val}\n","sus" if "RWX" in val else None)
        w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        w("  ┌─ ENTROPY ────────────────────────────────────────────────────┐\n","dim")
        w("  │  Shannon entropy    ","dim"); w(f"{e:.6f} bits/byte\n",etag)
        w("  │  Rating (0–10)      ","dim"); w(f"{e_s}  —  {e_l}\n",etag)
        filled=int((e/8)*48)
        w("  │  Visual bar        ","dim"); w("█"*filled,etag); w("░"*(48-filled)+"\n","dim")
        w("  │  Chi-square p       ","dim")
        w(f"{chi_p:.4f}  ({'UNIFORM — likely encrypted' if chi_u else 'non-uniform — normal'})\n",
          "high" if chi_u else "low")
        w("  │  Junk instr. ratio  ","dim")
        w(f"{jr:.1%}  ({'⚠ ABOVE THRESHOLD' if jr>config.JUNK_RATIO_THRESHOLD else 'OK'})\n",
          "high" if jr>config.JUNK_RATIO_THRESHOLD else "low")
        w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        if bf:
            w("  ┌─ TOP BYTE FREQUENCIES ───────────────────────────────────────┐\n","dim")
            w("  │   Byte   Dec    Count       Prob     Distribution\n","header")
            w("  │  ────────────────────────────────────────────────────────────\n","dim")
            for bv,cnt,prob,bar in bf[:16]:
                if prob>0.15: bt="high"
                elif prob>0.06: bt="orange"
                elif prob>0.02: bt="med"
                else: bt="dim"
                w(f"  │   0x{bv:02X}   {bv:3d}  {cnt:8,}   {prob:.4f}   ","dim")
                w(bar[:24]+"\n",bt)
            if dom.get("hint"): w(f"\n  │  ⚠  {dom['hint']}\n","sus")
            w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        if data:
            sr=strings_mod.analyze_strings(data)
            ac,uc=sr["ascii_count"],sr["unicode_count"]
            w("  ┌─ STRINGS ────────────────────────────────────────────────────┐\n","dim")
            w(f"  │  ASCII          {ac:,}\n","dim"); w(f"  │  Unicode        {uc:,}\n","dim")
            w(f"  │  Total          {ac+uc:,}\n","dim")
            if (ac+uc)<3 and e>config.ENTROPY_HIGH:
                w("  │  ⚠  Very few strings in high-entropy section — likely encrypted\n","sus")
            w("  └──────────────────────────────────────────────────────────────┘\n","dim")
        t.config(state="disabled")

    # ── File Summary tab ───────────────────────────────────────────────────────

    def _update_file_summary(self):
        if not self._results: return
        r=self._results; t=self._sum_text; t.config(state="normal"); t.delete("1.0","end")
        def w(x,tag=None): t.insert("end",x,tag) if tag else t.insert("end",x)

        fname=os.path.basename(r.get("filename","")); ftype=r.get("file_type","?")
        arch=r.get("arch","?"); ep=r.get("entry_point",0)
        verdict=r.get("verdict","?"); score=r.get("score",0)
        sections=r.get("sections",[]); imp_c=r.get("import_count",0)
        exp_c=r.get("export_count",0); sus_i=r.get("suspicious_imports",[])
        rwx_s=r.get("rwx_sections",[]); crypto=r.get("crypto_constants",[])
        loops=r.get("decryptor_loops",[]); ep_st=r.get("ep_status","")
        hashes=r.get("hashes",{})
        fsize=0
        try: fsize=os.path.getsize(r.get("filename",""))
        except: pass

        rule="═"*68
        w(f"{rule}\n","header"); w("  FILE ANALYSIS SUMMARY\n","title"); w(f"{rule}\n\n","header")

        w("  ┌─ FILE INFO ──────────────────────────────────────────────────┐\n","dim")
        for lbl,val in [("Filename",fname),("Format",ftype),("Architecture",arch),
                        ("File Size",f"{fsize:,} bytes  ({fsize/1024:.1f} KB)" if fsize>=1024 else f"{fsize} bytes"),
                        ("Sections",str(len(sections))),("Entry Point",f"0x{ep:08X}  —  {ep_st}"),
                        ("Imports",str(imp_c)),("Exports",str(exp_c))]:
            w(f"  │  {lbl:<20}","dim"); w(f"{val}\n")
        if hashes:
            for alg in ("md5","sha1","sha256"):
                h=hashes.get(alg,"")
                if h: w(f"  │  {alg.upper():<20}","dim"); w(f"{h}\n","accent")
        w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        if score>=81: vtag="high"
        elif score>=51: vtag="orange"
        elif score>=21: vtag="med"
        else: vtag="low"
        w("  ┌─ VERDICT ────────────────────────────────────────────────────┐\n","dim")
        w("  │  Score      ","dim"); w(f"{score}/100\n",vtag)
        w("  │  Verdict    ","dim"); w(f"{verdict}\n",vtag)
        filled=int(score/100*48)
        w("  │  Risk Bar   ","dim"); w("█"*filled,vtag); w("░"*(48-filled)+"\n","dim")
        w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        w("  ┌─ ALL SECTIONS ───────────────────────────────────────────────┐\n","dim")
        w("  │  #   Name          VA          Size       Entropy  Score   Class\n","header")
        w("  │  ──────────────────────────────────────────────────────────────\n","dim")
        for i,sec in enumerate(sections,1):
            e=sec["entropy"]; e_s=sec.get("entropy_score",round((e/8)*10,1))
            cls=sec.get("section_class","")[:24]; rwx="🔴" if sec.get("rwx") else "  "
            if e>=7.2: etag="high"
            elif e>=6.5: etag="orange"
            elif e>=5.0: etag="med"
            else: etag="low"
            w(f"  │  {i:<3} {sec['name']:<13} 0x{sec['virtual_address']:08X}  {sec['size']:>8,}   ","dim")
            w(f"{e:.4f}  {e_s:.1f}/10",etag); w(f"  {rwx}{cls}\n","dim")
        w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        w("  ┌─ KEY FINDINGS ───────────────────────────────────────────────┐\n","dim")
        if rwx_s:  w(f"  │  ❌ RWX Sections       {', '.join(rwx_s)}\n","high")
        if sus_i:  w(f"  │  ⚠  Suspicious APIs    {', '.join(sus_i[:6])}\n","orange")
        if crypto:
            names=list({c[2] for c in crypto})[:4]
            w(f"  │  ⚠  Crypto Constants   {', '.join(names)}\n","orange")
        if loops:  w(f"  │  ❌ Decryptor Loops    {len(loops)} detected\n","high")
        if not any([rwx_s,sus_i,crypto,loops]):
            w("  │  ✓  No major static indicators found\n","low")
        w("  └──────────────────────────────────────────────────────────────┘\n\n","dim")

        w("  ┌─ ENTROPY RATING LEGEND ──────────────────────────────────────┐\n","dim")
        for rng,rating,lbl,ltag in [
            ("0.0–5.0","0–6/10",  "Plaintext / Raw Data",   "low"),
            ("5.0–6.5","6–8/10",  "Normal Compiled Code",   "med"),
            ("6.5–7.2","8–9/10",  "Packed / Obfuscated",    "orange"),
            ("7.2–8.0","9–10/10", "Encrypted / Compressed", "high")]:
            w(f"  │  {rng:<12}  {rating:<10}  ","dim"); w(f"{lbl}\n",ltag)
        w("  └──────────────────────────────────────────────────────────────┘\n","dim")
        t.config(state="disabled")

    # ── Strings tab ───────────────────────────────────────────────────────────

    def _update_strings_tab(self, data):
        t=self._str_text; t.config(state="normal"); t.delete("1.0","end")
        sa=strings_mod.analyze_strings(data, min_len=config.MIN_STRING_LEN)
        strs=sa.get("strings",[])
        t.insert("end",f"  ASCII: {sa['ascii_count']}   Unicode: {sa['unicode_count']}   "
                       f"Total: {sa['total_count']}\n","header")
        t.insert("end","  "+"─"*60+"\n","dim")
        if not strs: t.insert("end","\n  (no strings — section may be encrypted)\n","dim")
        else:
            for off,s in strs[:config.MAX_STRINGS_DISPLAY]:
                t.insert("end",f"  0x{off:08x}  ","dim"); t.insert("end",f"{s}\n")
        t.config(state="disabled")

    # ── Indicators ────────────────────────────────────────────────────────────

    def _update_indicators(self):
        if not self._results: return
        t=self._ind_text; t.config(state="normal"); t.delete("1.0","end")
        for ind in self._results.get("indicators",[]):
            score=ind.get("score",0); text=ind.get("text","")
            if score>10:  tag,pre="high","❌ "
            elif score>0: tag,pre="med", "⚠  "
            else:         tag,pre="low", "✓  "
            t.insert("end",pre+text+"\n",tag)
        t.tag_configure("high",foreground=_p("FG_RED"))
        t.tag_configure("med", foreground=_p("FG_YELLOW"))
        t.tag_configure("low", foreground=_p("FG_GREEN"))
        t.config(state="disabled")

    # ── Imports tab ───────────────────────────────────────────────────────────

    def _update_imports(self):
        if not self._results: return
        r=self._results; t=self._imp_text; t.config(state="normal"); t.delete("1.0","end")
        sus={s.lower() for s in r.get("suspicious_imports",[])}
        imps=r.get("imports",[]); exps=r.get("exports",[])
        t.insert("end",f"  IMPORTS  ({len(imps)})  —  suspicious: {len(sus)}\n","header")
        t.insert("end","  "+"─"*50+"\n","dim")
        for imp in imps:
            t.insert("end",f"  ⚠  {imp}\n","sus") if imp.lower() in sus else t.insert("end",f"     {imp}\n")
        if exps:
            t.insert("end",f"\n  EXPORTS  ({len(exps)})\n","header")
            t.insert("end","  "+"─"*50+"\n","dim")
            for exp in exps: t.insert("end",f"     {exp}\n")
        t.config(state="disabled")

    # ── Verdict ───────────────────────────────────────────────────────────────

    def _update_verdict(self):
        if not self._results: return
        verdict=self._results.get("verdict","?"); score=self._results.get("score",0)
        color={"Clean":_p("FG_GREEN"),"Suspicious/Packed":_p("FG_YELLOW"),
               "Likely Polymorphic":_p("FG_ORANGE"),"Strong Polymorphic":_p("FG_RED")}.get(verdict,_p("FG_ACCENT"))
        self._verdict_label.config(text=f"  {verdict}  [{score}/100]  ",fg=color)

    # ── Export ────────────────────────────────────────────────────────────────

    def _export(self, fmt=None):
        if not self._results:
            messagebox.showwarning("No Results","Run analysis first."); return
        if fmt is None:
            path=filedialog.asksaveasfilename(title="Export Report",defaultextension=".json",
                filetypes=[("JSON","*.json"),("HTML","*.html"),("All","*")])
        else:
            path=filedialog.asksaveasfilename(title="Export Report",
                defaultextension=f".{fmt}",
                filetypes=[(fmt.upper(),f"*.{fmt}"),("All","*")])
        if not path: return
        try:
            safe={k:v for k,v in self._results.items() if k!="sections"}
            safe["sections"]=[{k:v for k,v in s.items() if k!="raw_data"}
                               for s in self._results.get("sections",[])]
            if self._vt_result: safe["virustotal"]=self._vt_result
            content=(reporter.generate_html(safe) if path.endswith(".html")
                     else reporter.generate_json(safe))
            with open(path,"w",encoding="utf-8") as f: f.write(content)
            messagebox.showinfo("Exported",f"Report saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error",str(e))

    # ── Dialogs ───────────────────────────────────────────────────────────────

    def _settings(self): SettingsDialog(self)
    def _about(self):    AboutDialog(self)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _stat(self, msg, pct):
        self._status.config(text=msg); self._prog["value"]=pct; self.update_idletasks()

    def _set_text(self, widget, content):
        widget.config(state="normal"); widget.delete("1.0","end")
        widget.insert("end",content); widget.config(state="disabled")


# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    app = AdaptiveEntropyApp()
    app.mainloop()

if __name__ == "__main__":
    main()
