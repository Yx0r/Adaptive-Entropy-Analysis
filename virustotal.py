# Adaptive Entropy Analyzer — VirusTotal Integration
# Author: Yx0R
# Fully offline-safe: all network calls wrapped, never raises on connection failure.

import hashlib
import time
import json

# Optional imports — network stack may not be present
try:
    import urllib.request
    import urllib.error
    _URLLIB_OK = True
except ImportError:
    _URLLIB_OK = False

VT_BASE   = "https://www.virustotal.com/api/v3"
VT_LEGACY = "https://www.virustotal.com/vtapi/v2"


# ── Connectivity check ─────────────────────────────────────────────────────────

def check_network() -> bool:
    """Return True if internet is reachable (quick DNS probe, no API key needed)."""
    if not _URLLIB_OK:
        return False
    try:
        urllib.request.urlopen("https://www.virustotal.com", timeout=4)
        return True
    except Exception:
        pass
    # Fallback — try 8.8.8.8
    try:
        import socket
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True
    except Exception:
        return False


def check_api_key(api_key: str) -> tuple:
    """
    Validate an API key against VT.
    Returns (valid: bool, message: str).
    """
    if not api_key or not api_key.strip():
        return False, "No API key provided."
    if not _URLLIB_OK:
        return False, "urllib not available."
    try:
        req = urllib.request.Request(
            f"{VT_BASE}/users/current",
            headers={"x-apikey": api_key.strip()}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        quota = data.get("data", {}).get("attributes", {}).get("quotas", {})
        daily = quota.get("api_requests_daily", {})
        used  = daily.get("used", "?")
        total = daily.get("allowed", "?")
        return True, f"API key valid  |  Daily quota: {used}/{total}"
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "Invalid API key (401 Unauthorized)."
        return False, f"HTTP error {e.code}."
    except Exception as e:
        return False, f"Connection error: {e}"


# ── Hash helpers ──────────────────────────────────────────────────────────────

def file_hashes(path: str) -> dict:
    """Compute MD5, SHA1, SHA256 of a file."""
    try:
        md5  = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5":    md5.hexdigest(),
            "sha1":   sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except Exception as e:
        return {"error": str(e)}


# ── VT API calls ──────────────────────────────────────────────────────────────

def _get(url: str, api_key: str, timeout: int = 15) -> dict:
    """Raw GET to VT API. Returns parsed JSON or {'error': ...}."""
    if not _URLLIB_OK:
        return {"error": "urllib not available"}
    try:
        req = urllib.request.Request(url, headers={"x-apikey": api_key.strip()})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()
        except: pass
        return {"error": f"HTTP {e.code}", "body": body}
    except Exception as e:
        return {"error": str(e)}


def _post_file(path: str, api_key: str, timeout: int = 60) -> dict:
    """Upload a file to VT for scanning. Returns parsed JSON or {'error': ...}."""
    if not _URLLIB_OK:
        return {"error": "urllib not available"}
    try:
        import os
        import mimetypes

        boundary = "----AEABoundary7d3e"
        fname = os.path.basename(path)

        with open(path, "rb") as f:
            file_data = f.read()

        body  = f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'.encode()
        body += b"Content-Type: application/octet-stream\r\n\r\n"
        body += file_data
        body += f"\r\n--{boundary}--\r\n".encode()

        req = urllib.request.Request(
            f"{VT_BASE}/files",
            data=body,
            headers={
                "x-apikey": api_key.strip(),
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()
        except: pass
        return {"error": f"HTTP {e.code}", "body": body}
    except Exception as e:
        return {"error": str(e)}


def lookup_hash(sha256: str, api_key: str, timeout: int = 15) -> dict:
    """
    Look up a file hash on VirusTotal.
    Returns parsed VT report dict or {'error': ...}.
    """
    return _get(f"{VT_BASE}/files/{sha256}", api_key, timeout)


def submit_file(path: str, api_key: str, timeout: int = 60) -> dict:
    """
    Submit a file to VirusTotal for scanning.
    Returns {'analysis_id': ..., 'error': ...}.
    """
    result = _post_file(path, api_key, timeout)
    if "error" in result:
        return result
    try:
        analysis_id = result["data"]["id"]
        return {"analysis_id": analysis_id, "raw": result}
    except (KeyError, TypeError):
        return {"error": "Unexpected response format", "raw": result}


def get_analysis(analysis_id: str, api_key: str,
                 timeout: int = 15, poll_secs: int = 20,
                 max_polls: int = 6) -> dict:
    """
    Poll VT for analysis results until complete or max_polls exhausted.
    Returns parsed report dict or {'error': ...}.
    """
    url = f"{VT_BASE}/analyses/{analysis_id}"
    for attempt in range(max_polls):
        result = _get(url, api_key, timeout)
        if "error" in result:
            return result
        try:
            status = result["data"]["attributes"]["status"]
            if status == "completed":
                return result
        except (KeyError, TypeError):
            return {"error": "Unexpected analysis response", "raw": result}
        if attempt < max_polls - 1:
            time.sleep(poll_secs)
    return {"error": "Analysis timed out — check VT website for results"}


# ── Report parsing ────────────────────────────────────────────────────────────

def parse_report(vt_data: dict) -> dict:
    """
    Parse a VT file report into a clean summary dict.
    Works for both /files/{hash} and /analyses/{id} responses.
    """
    if "error" in vt_data:
        return {"status": "error", "message": vt_data["error"]}

    try:
        # /files/{hash} response
        attrs = vt_data.get("data", {}).get("attributes", {})

        # /analyses/{id} wraps stats differently
        if not attrs:
            attrs = (vt_data.get("data", {})
                            .get("attributes", {}))

        stats       = attrs.get("last_analysis_stats", attrs.get("stats", {}))
        results_raw = attrs.get("last_analysis_results", attrs.get("results", {}))

        malicious   = stats.get("malicious",   0)
        suspicious  = stats.get("suspicious",  0)
        undetected  = stats.get("undetected",  0)
        harmless    = stats.get("harmless",    0)
        total       = malicious + suspicious + undetected + harmless

        detections  = []
        for engine, res in results_raw.items():
            cat = res.get("category","")
            if cat in ("malicious","suspicious"):
                detections.append({
                    "engine":   engine,
                    "category": cat,
                    "result":   res.get("result",""),
                    "version":  res.get("engine_version",""),
                })
        detections.sort(key=lambda x: x["category"])

        # File metadata
        name         = attrs.get("meaningful_name", attrs.get("name",""))
        file_type    = attrs.get("type_description", attrs.get("type_tag",""))
        sha256       = attrs.get("sha256","")
        first_seen   = attrs.get("first_submission_date","")
        last_seen    = attrs.get("last_analysis_date","")
        reputation   = attrs.get("reputation", 0)
        tags         = attrs.get("tags", [])
        crowdsourced = attrs.get("crowdsourced_yara_results", [])

        if first_seen:
            try:
                import datetime
                first_seen = datetime.datetime.utcfromtimestamp(int(first_seen)).strftime("%Y-%m-%d")
                last_seen  = datetime.datetime.utcfromtimestamp(int(last_seen)).strftime("%Y-%m-%d %H:%M UTC")
            except Exception:
                pass

        if total > 0:
            detect_pct = round((malicious + suspicious) / total * 100, 1)
        else:
            detect_pct = 0.0

        if malicious >= 10:       vt_verdict = "MALICIOUS"
        elif malicious >= 3:      vt_verdict = "Likely Malicious"
        elif suspicious >= 3:     vt_verdict = "Suspicious"
        elif malicious + suspicious > 0: vt_verdict = "Low Detection"
        else:                     vt_verdict = "Clean"

        return {
            "status":       "ok",
            "vt_verdict":   vt_verdict,
            "malicious":    malicious,
            "suspicious":   suspicious,
            "undetected":   undetected,
            "total":        total,
            "detect_pct":   detect_pct,
            "detections":   detections,
            "sha256":       sha256,
            "name":         name,
            "file_type":    file_type,
            "first_seen":   str(first_seen),
            "last_seen":    str(last_seen),
            "reputation":   reputation,
            "tags":         tags,
            "yara_hits":    len(crowdsourced),
        }
    except Exception as e:
        return {"status": "error", "message": f"Parse error: {e}"}
