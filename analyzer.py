# PolyEntropy Pro - Analysis Orchestrator
import os

import config
import entropy as entropy_mod
import polymorphic
import permissions as perms_mod
import imports as imports_mod
import strings as strings_mod
import section_info as sec_info_mod


def compute_verdict(score: int) -> str:
    for name, (lo, hi) in config.VERDICT_THRESHOLDS.items():
        if lo <= score <= hi:
            return name
    if score > 100:
        return "Strong Polymorphic"
    return "Clean"


def analyze(parsed_file, progress_cb=None) -> dict:
    """
    Run full analysis on a ParsedFile object.
    progress_cb(msg, percent) optional callback.
    Returns results dict.
    """
    def progress(msg, pct):
        if progress_cb:
            progress_cb(msg, pct)

    results = {
        "filename": "",
        "file_type": parsed_file.file_type,
        "arch": parsed_file.arch,
        "entry_point": parsed_file.entry_point,
        "sections": [],
        "indicators": [],
        "score": 0,
        "verdict": "Clean",
        "rwx_sections": [],
        "ep_status": "",
        "import_count": 0,
        "export_count": 0,
        "suspicious_imports": [],
        "crypto_constants": [],
        "decryptor_loops": [],
        "junk_ratio_overall": 0.0,
        "string_analysis": {},
    }

    sections = parsed_file.sections
    arch = parsed_file.arch
    score = 0
    indicators = []

    progress("Analyzing sections entropy...", 10)

    # --- Per-section entropy ---
    section_results = []
    high_entropy_sections = []
    low_entropy_sections = []

    for sec in sections:
        data = sec.get("raw_data", b"")
        e = entropy_mod.shannon(data) if data else 0.0
        chi_p, chi_uniform = polymorphic.chi_square_uniform(data)
        jr = polymorphic.junk_ratio(data, arch)

        e_score, e_label, e_color = sec_info_mod.entropy_rating(e)
        sec_class = sec_info_mod.classify_section(
            sec.get("name", "?"),
            sec.get("characteristics", 0),
            e
        )
        byte_freq = sec_info_mod.byte_frequency(data, top_n=16)
        dom_byte  = sec_info_mod.dominant_byte_info(data)

        sec_result = {
            "name": sec.get("name", "?"),
            "offset": sec.get("offset", 0),
            "size": sec.get("size", 0),
            "virtual_address": sec.get("virtual_address", 0),
            "permissions": sec.get("permissions", "---"),
            "entropy": e,
            "entropy_score": e_score,
            "entropy_label": e_label,
            "entropy_color": e_color,
            "section_class": sec_class,
            "byte_freq": byte_freq,
            "dominant_byte": dom_byte,
            "chi_p": chi_p,
            "chi_uniform": chi_uniform,
            "junk_ratio": jr,
            "rwx": perms_mod.is_rwx(sec),
            "raw_data": data,
        }
        section_results.append(sec_result)

        if e > config.ENTROPY_HIGH:
            high_entropy_sections.append(sec_result)
        elif e < config.ENTROPY_LOW:
            low_entropy_sections.append(sec_result)

    results["sections"] = section_results

    progress("Checking RWX sections...", 20)

    # --- RWX sections ---
    rwx = perms_mod.check_rwx_sections(sections)
    results["rwx_sections"] = rwx
    if rwx:
        score += config.WEIGHTS["rwx_section"]
        indicators.append({
            "text": f"RWX section(s) found: {', '.join(rwx)}",
            "score": config.WEIGHTS["rwx_section"],
            "category": "rwx_section",
        })

    # --- Entry point check ---
    ep_check = perms_mod.check_entry_point(parsed_file.entry_point, sections, parsed_file.file_type)
    results["ep_status"] = ep_check["description"]
    if ep_check["anomaly"]:
        score += config.WEIGHTS["entry_point_anomaly"]
        indicators.append({
            "text": f"Entry point anomaly: {ep_check['description']}",
            "score": config.WEIGHTS["entry_point_anomaly"],
            "category": "entry_point_anomaly",
        })
    else:
        indicators.append({
            "text": f"Entry point OK: {ep_check['description']}",
            "score": 0,
            "category": "entry_point_ok",
        })

    progress("Checking high entropy contrast...", 30)

    # --- High entropy contrast (low section adjacent to high) ---
    if high_entropy_sections:
        n_high = len(high_entropy_sections)
        if n_high > 0 and low_entropy_sections:
            score += config.WEIGHTS["high_entropy_contrast"]
            indicators.append({
                "text": (
                    f"High entropy contrast: {n_high} high-entropy section(s) "
                    f"alongside {len(low_entropy_sections)} low-entropy section(s) "
                    f"(packer signature)"
                ),
                "score": config.WEIGHTS["high_entropy_contrast"],
                "category": "high_entropy_contrast",
            })
        elif n_high > 0:
            score += config.WEIGHTS["high_entropy_contrast"] // 2
            indicators.append({
                "text": f"{n_high} high-entropy section(s) found (possible encryption/packing)",
                "score": config.WEIGHTS["high_entropy_contrast"] // 2,
                "category": "high_entropy_contrast",
            })
    else:
        indicators.append({
            "text": "No high-entropy sections detected",
            "score": 0,
            "category": "entropy_ok",
        })

    progress("Scanning for decryptor loops...", 45)

    # --- Decryptor loop scan ---
    # Find EP offset in file
    ep_offset = 0
    ep_va = parsed_file.entry_point
    for sec in sections:
        va = sec.get("virtual_address", 0)
        sz = sec.get("size", 0)
        if va <= ep_va < va + max(sz, 1):
            ep_offset = sec.get("offset", 0) + (ep_va - va)
            break

    loops = []
    try:
        loops = polymorphic.find_decryptor_loops(
            parsed_file.raw_bytes, ep_offset, arch
        )
    except Exception as e:
        indicators.append({"text": f"Loop scan error: {e}", "score": 0, "category": "error"})

    results["decryptor_loops"] = loops
    if loops:
        score += config.WEIGHTS["decryptor_loop"]
        indicators.append({
            "text": f"Decryptor loop(s) detected: {len(loops)} loop(s) at entry region",
            "score": config.WEIGHTS["decryptor_loop"],
            "category": "decryptor_loop",
        })

    progress("Computing junk ratios...", 55)

    # --- Junk ratio ---
    total_junk = 0.0
    junk_count = 0
    flagged_junk_sections = []
    for sr in section_results:
        jr = sr["junk_ratio"]
        if jr > config.JUNK_RATIO_THRESHOLD:
            flagged_junk_sections.append(f"{sr['name']} ({jr:.0%})")
        if jr > 0:
            total_junk += jr
            junk_count += 1

    overall_junk = total_junk / junk_count if junk_count > 0 else 0.0
    results["junk_ratio_overall"] = overall_junk

    if flagged_junk_sections:
        score += config.WEIGHTS["junk_ratio"]
        indicators.append({
            "text": f"High junk instruction ratio in: {', '.join(flagged_junk_sections)}",
            "score": config.WEIGHTS["junk_ratio"],
            "category": "junk_ratio",
        })

    progress("Running chi-square tests...", 65)

    # --- Chi-square ---
    chi_flagged = [
        sr["name"] for sr in section_results
        if sr["chi_uniform"] and sr["entropy"] > config.ENTROPY_LOW
    ]
    if chi_flagged:
        score += config.WEIGHTS["chi_square"]
        indicators.append({
            "text": f"Chi-square: uniform byte distribution in: {', '.join(chi_flagged)} (encrypted?)",
            "score": config.WEIGHTS["chi_square"],
            "category": "chi_square",
        })

    progress("Scanning crypto constants...", 72)

    # --- Crypto constants ---
    crypto_hits = []
    try:
        crypto_hits = polymorphic.scan_crypto_constants(parsed_file.raw_bytes)
    except Exception as e:
        indicators.append({"text": f"Crypto scan error: {e}", "score": 0, "category": "error"})

    results["crypto_constants"] = crypto_hits
    if crypto_hits:
        score += config.WEIGHTS["crypto_const"]
        names = list({h[2] for h in crypto_hits})[:3]
        indicators.append({
            "text": f"Crypto constant(s) found: {', '.join(names)} ({len(crypto_hits)} hit(s))",
            "score": config.WEIGHTS["crypto_const"],
            "category": "crypto_const",
        })

    progress("Analyzing imports...", 80)

    # --- Imports ---
    imp_analysis = imports_mod.analyze_imports(parsed_file.imports, parsed_file.exports)
    results["import_count"] = imp_analysis["import_count"]
    results["export_count"] = imp_analysis["export_count"]
    results["suspicious_imports"] = imp_analysis["suspicious"]
    results["imports"] = imp_analysis.get("imports", [])
    results["exports"] = imp_analysis.get("exports", [])

    if imp_analysis["suspicious"]:
        indicators.append({
            "text": f"Suspicious API(s): {', '.join(imp_analysis['suspicious'])}",
            "score": 5,
            "category": "suspicious_import",
        })
        score += 5

    if imp_analysis["few_imports"]:
        score += config.WEIGHTS["few_imports"]
        indicators.append({
            "text": f"Very few imports ({imp_analysis['import_count']}) — possible packer stub",
            "score": config.WEIGHTS["few_imports"],
            "category": "few_imports",
        })

    progress("Extracting strings...", 88)

    # --- Strings (whole file) ---
    try:
        str_analysis = strings_mod.analyze_strings(parsed_file.raw_bytes)
        results["string_analysis"] = str_analysis
        results["strings"] = str_analysis.get("strings", [])

        # Low strings in high-entropy sections
        for sr in section_results:
            if sr["entropy"] > config.ENTROPY_HIGH and sr["size"] > 512:
                sec_strs = strings_mod.extract_strings(sr["raw_data"])
                if len(sec_strs) < 3:
                    indicators.append({
                        "text": (
                            f"Section '{sr['name']}' is high-entropy with few strings "
                            f"(likely encrypted)"
                        ),
                        "score": 0,
                        "category": "encrypted_section",
                    })
    except Exception as e:
        results["string_analysis"] = {}
        results["strings"] = []
        indicators.append({"text": f"String extraction error: {e}", "score": 0, "category": "error"})

    progress("Computing verdict...", 95)

    score = min(score, 100)
    results["score"] = score
    results["verdict"] = compute_verdict(score)
    results["indicators"] = indicators

    progress("Done.", 100)
    return results
