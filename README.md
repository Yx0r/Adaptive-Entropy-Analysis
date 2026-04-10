<div align="center">

# 🔬 Adaptive Entropy Analyzer

**Advanced Static Malware Analysis Framework**

*By [Yx0R](https://github.com/Yx0R)*  [Yash Gaikwad](https://yash-gaikwad.onrender.com)

---

![Version](https://img.shields.io/badge/version-2.0.0-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.8+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)

</div>

---

## What is this?

**Adaptive Entropy Analyzer** is a desktop tool for **static analysis of compiled executables** — without running them. It detects packed, encrypted, and polymorphic malware using a combination of entropy analysis, disassembly-based pattern detection, statistical testing, and VirusTotal integration.

Built for **security researchers, reverse engineers, and malware analysts** who need fast, reliable triage of unknown binaries.

> ⚠️ **Ethical use only.** This tool is intended for legitimate security research, malware analysis, CTF challenges, and educational purposes.

---

## Screenshots

> *Screenshots will be added once the full release is published.*

---

## Key Features

### 🧮 Entropy Analysis
- Shannon entropy computed per section (0–8 bit scale, also shown as 0–10 rating)
- Sliding window entropy heatmap with color-coded visual bars
- Entropy contrast detection — high-entropy sections alongside low-entropy sections is a packer signature
- Clickable heatmap to jump directly to any section

### 🔍 Polymorphic & Packer Detection
- **Decryptor loop scanner** — disassembles entry point region using Capstone, detects backward JMP / LOOP instructions containing XOR/ADD/SUB/ROR operations (classic decryptor stubs)
- **Junk instruction ratio** — flags sections with >30% useless instructions (NOP sleds, same-register MOVs, zero-ops) used for obfuscation
- **Chi-square uniformity test** — statistical test for encrypted/random byte distributions (p > 0.05 = uniform = encrypted)
- **Crypto constant scanner** — searches binary for known 32-bit constants from XTEA, RC4, MD5, SHA-1, SHA-256, AES

### 🛡 Permission & Structure Analysis
- **RWX section detection** — writable + executable memory is a self-modifying code indicator
- **Entry point anomaly** — flags binaries where EP is outside standard `.text`/`.code` sections
- **Import table analysis** — flags suspicious APIs: `VirtualProtect`, `WriteProcessMemory`, `CreateRemoteThread`, `LoadLibrary`, `GetProcAddress`, and 25+ more
- **Section classifier** — recognizes 35+ known section names including UPX, Themida, VMProtect, ASPack, MPress, NsPack

### 🌐 VirusTotal Integration
- Hash lookup (MD5, SHA1, SHA256) against VT database — no upload required for known files
- File upload and scan for unknown samples
- Full detection report — engine name, category, detection name, statistics
- Fully offline-safe — zero errors if no network, all calls gracefully handled
- API key stored in local `settings.json`, never hardcoded

### 📊 Confidence Scoring
- 0–100 weighted confidence score
- Verdict bands: **Clean** / **Suspicious/Packed** / **Likely Polymorphic** / **Strong Polymorphic**
- Every indicator contributes a configurable score — full breakdown shown in UI

### 🖥 Interactive GUI
- Section treeview with entropy, 0–10 rating, permissions, junk ratio
- Byte frequency histogram with XOR key detection hints
- Hex dump view (16-column with ASCII)
- Capstone disassembly view (x86/x64/ARM)
- String extraction (ASCII + Unicode/UTF-16LE) with offsets
- Import/export table viewer with suspicious API highlighting
- File Summary panel — all sections, findings, hashes, verdict
- JSON and HTML report export

---

## Supported File Formats

| Format | Extensions | Notes |
|--------|-----------|-------|
| **PE** | `.exe` `.dll` `.sys` | Full import/export analysis, all PE checks |
| **ELF** | `.elf` `.so` (any) | Linux/Unix binaries, arch auto-detected |
| **Mach-O** | `.dylib` (any) | macOS/iOS binaries, segment permission analysis |
| **APK** | `.apk` | Android packages, DEX extracted from ZIP |
| **DEX** | `.dex` | Dalvik bytecode, entropy + string analysis |
| **Unknown** | `*` | Any file — format detected from magic bytes |

---

## Detection Checks & Scoring

| Check | Weight | Fires When |
|-------|--------|-----------|
| Decryptor loop | **30** | Backward JMP or LOOP with XOR/ADD/SUB in loop body near EP |
| High entropy contrast | **15** | High-entropy section exists alongside low-entropy section |
| Junk instruction ratio | **15** | Any section has >30% junk instructions |
| Chi-square uniformity | **10** | Byte distribution in a section is statistically uniform |
| Crypto constants | **10** | Known algorithm constant found in binary |
| RWX section | **10** | A section is both writable and executable |
| Suspicious imports | **5** | VirtualProtect, CreateRemoteThread, etc. |
| Entry point anomaly | **5** | EP is outside `.text` / `.code` |
| Very few imports | **5** | Import count < 5 (packer stub pattern) |

### Verdict Bands

| Score | Verdict |
|-------|---------|
| 0 – 20 | ✅ Clean |
| 21 – 50 | ⚠️ Suspicious / Packed |
| 51 – 80 | 🔶 Likely Polymorphic |
| 81 – 100 | 🔴 Strong Polymorphic |

---

## Download

> **Source code will be published in a future release.**

Currently available as a compiled Windows executable:

📦 **[Download latest release →](https://github.com/Yx0R/releases)**

| File | Description |
|------|-------------|
| `AdaptiveEntropyAnalyzer.exe` | Standalone Windows executable (no install required) |

**Windows**: Just download and run. No Python required for the compiled release.

---

## Running from Source

### Requirements

- Python **3.8** or newer
- Tkinter — bundled with Python on Windows and macOS
  - Linux: `sudo apt install python3-tk`

### Install dependencies

```bash
pip install lief capstone scipy jinja2
```

Optional (for APK support):

```bash
pip install androguard
```

### Run

```bash
python main.py
```

---

## Usage Guide

### Opening a file
Click **📂 Open** or use **File → Open File…**
Format is auto-detected by magic bytes — file extension does not matter.

### Reading the results

| Element | What to look for |
|---------|-----------------|
| **Verdict badge** (top right) | Green = Clean, Yellow = Suspicious, Orange/Red = Polymorphic |
| **Section treeview** (left panel) | Red rows = high entropy. 🔴 icon = RWX section |
| **Entropy heatmap** (center) | Tall red bars = encrypted/packed regions. Click to inspect |
| **Indicators** (left bottom) | ❌ = high-weight hit, ⚠ = medium, ✓ = passed check |
| **Section Info tab** | Entropy rating, byte histogram, chi-square, junk ratio, strings count |
| **File Summary tab** | All sections table, hashes (MD5/SHA1/SHA256), verdict, key findings |
| **VirusTotal tab** | Detection results from 70+ AV engines |
| **Hex Dump tab** | Raw bytes of selected section in 16-column format |
| **Disassembly tab** | Capstone-decoded instructions |
| **Strings tab** | All printable strings with file offsets |
| **Imports tab** | Full import list, suspicious APIs highlighted in red |

### VirusTotal Setup
1. Get a free API key at [virustotal.com](https://www.virustotal.com)
2. Open **⚙ Settings → 🌐 VirusTotal**
3. Paste your key and click **Test API Key**
4. The key saves automatically to `settings.json`

Once configured, use **Analysis → VirusTotal Lookup** to check any open file.
The tool works fully offline if no key is configured — no errors, no required connectivity.

### Exporting reports
Click **💾 Export** and choose:
- **JSON** — machine-readable, includes all sections, indicators, hashes, VT results
- **HTML** — styled report, opens in any browser

---

## Settings

All settings are saved to `settings.json` in the same folder as the tool.

### Analysis tab
| Setting | Default | Effect |
|---------|---------|--------|
| Entropy low threshold | 5.0 | Below = green (code/data) |
| Entropy high threshold | 7.2 | Above = red (packed/encrypted) |
| Junk ratio threshold | 0.30 | Flag sections with >30% junk instructions |
| Chi-square p-value | 0.05 | p > this = uniform byte distribution |
| Sliding window size | 256 bytes | Heatmap granularity |
| Sliding window step | 128 bytes | 50% overlap recommended |
| Max hex bytes | 8192 | Bytes shown in hex dump tab |
| Max disasm instructions | 300 | Instructions shown in disassembly |
| Max strings | 500 | Strings shown per section |
| Min string length | 4 | Minimum printable chars to extract |

### Weights tab
All 8 detection indicator weights are individually configurable.
Total score is capped at 100.

### Interface tab
- Font sizes (mono + UI separately)
- Window dimensions
- Heatmap height
- Accent color (hex, e.g. `#00d4ff` `#ff6b35` `#7c3aed`)
- Legend visibility, tooltip toggle, auto-select first section

### Imports tab
The full suspicious API list is editable — add or remove any function names, one per line. Changes apply on next analysis run.

---

## Architecture

```
adaptive_entropy_analyzer/
├── main.py          # GUI — Tkinter application, all UI logic
├── analyzer.py      # Analysis orchestrator, confidence scoring
├── parser.py        # Unified file loader (PE/ELF/Mach-O/APK)
├── entropy.py       # Shannon entropy, sliding window
├── polymorphic.py   # Loop scanner, junk ratio, chi-square, crypto scan
├── section_info.py  # Section classifier, entropy rating, byte histogram
├── permissions.py   # RWX checks, entry point validation
├── imports.py       # Import/export analysis
├── strings.py       # ASCII + Unicode string extraction
├── hex_asm.py       # Hex dump + Capstone disassembly
├── virustotal.py    # VT API integration, offline-safe
├── reporter.py      # JSON + HTML report generation
├── config.py        # All settings, persistence (settings.json)
└── requirements.txt
```

**Total: ~3,400 lines of Python across 13 modules.**

### Analysis pipeline

```
File open → magic byte detection → lief/zip parse
    → per-section: entropy + chi-square + junk ratio + byte freq
    → polymorphic checks: loop scan + crypto constants
    → permissions: RWX + entry point
    → imports: suspicious API flags
    → strings: ASCII + Unicode extraction
    → scoring: weighted sum → verdict
    → display: treeview + heatmap + tabs
    → (optional) VT lookup: hash → API → report
```

---

## Dependency Reference

| Package | Version | Required | Purpose |
|---------|---------|----------|---------|
| `lief` | ≥ 0.13 | Yes | PE / ELF / Mach-O parsing |
| `capstone` | ≥ 4.0 | Yes | x86/x64/ARM disassembly |
| `scipy` | ≥ 1.7 | Soft | Chi-square test (graceful fallback if absent) |
| `jinja2` | ≥ 3.0 | Soft | HTML report templating (plain fallback if absent) |
| `tkinter` | built-in | Yes | GUI (ships with CPython) |
| `androguard` | ≥ 3.3 | Optional | APK/DEX analysis |

---

## Known Limitations

- **PE only** for full feature coverage — ELF/Mach-O get entropy and string analysis but fewer PE-specific checks
- **No dynamic analysis** — this tool never executes code
- **Large files (>50 MB)** — junk ratio scan may take 10–20 seconds; analysis runs in background thread so GUI stays responsive
- **Fat Mach-O** — only first architecture slice is analyzed
- **Custom obfuscators** — novel schemes not matching known patterns will score lower than warranted
- **VirusTotal free tier** — 4 requests/minute; rate limit delay is configurable in settings

---

## License

```
MIT License

Copyright (c) 2025 Yx0R

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## Disclaimer

This tool is provided for **educational and legitimate security research purposes only**.

The author is **not responsible** for any misuse of this software. Do not use this tool to analyze files you do not own or have explicit permission to analyze. Always follow applicable laws and regulations in your jurisdiction.

---

<div align="center">

**Adaptive Entropy Analyzer** — built with ❤ by [Yx0R](https://yash-gaikwad.onrender.com) 

*Static analysis. No execution. No risk.*

</div>
