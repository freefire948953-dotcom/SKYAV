"""
virustotal.py
Cross-checks a file's hash against VirusTotal's database (70+ antivirus
engines combined). This dramatically cuts down false positives from our
local heuristics — e.g. a packed installer flagged for "high entropy"
gets instantly confirmed clean (or confirmed malicious) by real-world data.

SETUP (one-time):
    1. Go to https://www.virustotal.com/gui/join-us and make a free account
    2. Go to your profile -> API Key, copy it
    3. Run: python main.py --set-vt-key YOUR_API_KEY_HERE

Free tier limit: 4 requests/minute, 500/day — plenty for checking only the
files that were already flagged suspicious (not every file on your PC).
"""

import os
import json
import time
import requests

import paths

DATA_DIR = paths.DATA_DIR
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
VT_URL = "https://www.virustotal.com/api/v3/files/{}"


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def save_api_key(key: str):
    _ensure_dir()
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
    config["vt_api_key"] = key.strip()
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def get_api_key():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
    return config.get("vt_api_key")


def check_hash(sha256_hash: str, api_key: str = None, timeout: int = 15) -> dict:
    """
    Looks up a file hash on VirusTotal.
    Returns: {found, malicious_count, total_engines, verdict, permalink}
    or {found: False, error: "..."} if the key is missing/invalid/not found.
    """
    key = api_key or get_api_key()
    if not key:
        return {"found": False, "error": "No VirusTotal API key set. Run: python main.py --set-vt-key YOUR_KEY"}

    headers = {"x-apikey": key}
    try:
        resp = requests.get(VT_URL.format(sha256_hash), headers=headers, timeout=timeout)
    except requests.RequestException as e:
        return {"found": False, "error": f"Network error: {e}"}

    if resp.status_code == 404:
        return {"found": False, "error": "Not in VirusTotal's database (unknown file — could be new/private code)"}
    if resp.status_code == 401:
        return {"found": False, "error": "Invalid API key"}
    if resp.status_code == 429:
        return {"found": False, "error": "Rate limit hit (free tier: 4/min, 500/day) — wait a bit"}
    if resp.status_code != 200:
        return {"found": False, "error": f"VirusTotal returned status {resp.status_code}"}

    data = resp.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if malicious >= 3:
        verdict = "MALICIOUS"
    elif malicious > 0 or suspicious > 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "found": True,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total,
        "verdict": verdict,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
    }


def check_flagged_files(flagged_list: list, delay_between: float = 16.0) -> list:
    """
    Takes the 'flagged' list from a scan summary and cross-checks each one
    against VirusTotal. delay_between defaults to 16s to respect the free
    tier's 4-requests/minute limit.
    """
    key = get_api_key()
    if not key:
        print("⚠ No VirusTotal API key set. Run: python main.py --set-vt-key YOUR_KEY")
        return []

    results = []
    for i, item in enumerate(flagged_list):
        path = item["path"]
        if not os.path.isfile(path):
            continue

        import hashlib
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except (PermissionError, OSError):
            continue

        vt_result = check_hash(h.hexdigest(), key)
        vt_result["path"] = path
        results.append(vt_result)

        print(f"[{i+1}/{len(flagged_list)}] {path}")
        if vt_result["found"]:
            print(f"   -> VT verdict: {vt_result['verdict']} "
                  f"({vt_result['malicious_count']}/{vt_result['total_engines']} engines flagged it)")
            print(f"   -> Details: {vt_result['permalink']}")
        else:
            print(f"   -> {vt_result['error']}")

        if i < len(flagged_list) - 1:
            time.sleep(delay_between)

    return results
