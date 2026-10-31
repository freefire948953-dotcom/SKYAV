"""
updater.py
Automatically keeps the malware signature database fresh by pulling
daily threat intelligence from free public feeds:

  • MalwareBazaar (abuse.ch) — real malware samples, updated daily
    https://bazaar.abuse.ch/  — free, no API key needed
  • URLhaus (abuse.ch) — malicious URLs/downloaders
    https://urlhaus.abuse.ch/ — free, no API key needed

This gives SkyAV access to the same threat data that commercial AV
products use — the difference is they process it automatically and
instantly; we pull it once a day (which is fine for most threats,
since new malware takes time to spread anyway).

USAGE:
  python main.py --update          # manual one-time update
  python main.py --auto-update     # start background daily updater
"""

import os
import json
import time
import zipfile
import io
import requests
from datetime import datetime

import paths
import signatures

DATA_DIR = paths.DATA_DIR
UPDATE_LOG = os.path.join(DATA_DIR, "update_log.json")

# MalwareBazaar daily export — real SHA256 hashes of confirmed malware
# Updated daily by abuse.ch, free public download, no API key required
MALWAREBAZAAR_FULL_URL = "https://bazaar.abuse.ch/export/csv/full/"
MALWAREBAZAAR_RECENT_URL = "https://bazaar.abuse.ch/export/csv/recent/"


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_update_log() -> dict:
    if not os.path.exists(UPDATE_LOG):
        return {"last_update": None, "total_signatures": 0, "updates": []}
    with open(UPDATE_LOG, "r") as f:
        return json.load(f)


def _save_update_log(log: dict):
    _ensure_dir()
    with open(UPDATE_LOG, "w") as f:
        json.dump(log, f, indent=2)


def _parse_malwarebazaar_csv(content: str) -> dict:
    """Parses MalwareBazaar CSV export into {sha256: malware_name} dict."""
    new_sigs = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 4:
            continue
        # CSV format: first_seen,sha256,md5,sha1,reporter,file_name,file_type,mime,signature,...
        try:
            sha256 = parts[1].strip().strip('"').lower()
            name = parts[6].strip().strip('"') or parts[5].strip().strip('"') or "Unknown-Malware"
            if len(sha256) == 64:
                new_sigs[sha256] = name
        except IndexError:
            continue
    return new_sigs


def update_from_malwarebazaar(recent_only: bool = True,
                               progress_callback=None,
                               timeout: int = 60) -> dict:
    """
    Downloads and imports the latest malware hashes from MalwareBazaar.
    recent_only=True  → last 1,000 samples (fast, ~few seconds)
    recent_only=False → full database (slow, large download, ~minutes)
    Returns: {added, total, error}
    """
    _ensure_dir()
    url = MALWAREBAZAAR_RECENT_URL if recent_only else MALWAREBAZAAR_FULL_URL
    label = "recent (1,000 samples)" if recent_only else "full database (1M+ samples)"

    if progress_callback:
        progress_callback(f"Downloading MalwareBazaar {label}...")

    try:
        resp = requests.get(url, timeout=timeout, stream=True)
        resp.raise_for_status()
    except requests.RequestException as e:
        return {"added": 0, "total": 0, "error": str(e)}

    content_type = resp.headers.get("content-type", "")
    content = resp.content

    # Full export comes as a zip file
    if "zip" in content_type or url.endswith(".zip") or content[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                csv_name = [n for n in z.namelist() if n.endswith(".csv")][0]
                with z.open(csv_name) as f:
                    content = f.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return {"added": 0, "total": 0, "error": f"Zip extraction failed: {e}"}
    else:
        content = content.decode("utf-8", errors="ignore")

    if progress_callback:
        progress_callback("Parsing and importing signatures...")

    new_sigs = _parse_malwarebazaar_csv(content)

    if not new_sigs:
        return {"added": 0, "total": 0, "error": "No valid signatures parsed from feed"}

    before = len(signatures.load_signatures())
    signatures.add_signatures_bulk(new_sigs)
    after = len(signatures.load_signatures())
    added = after - before

    log = _load_update_log()
    log["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log["total_signatures"] = after
    log["updates"].append({
        "timestamp": log["last_update"],
        "source": "MalwareBazaar",
        "new_signatures": added,
        "total_after": after,
    })
    # Keep only last 30 update entries
    log["updates"] = log["updates"][-30:]
    _save_update_log(log)

    return {"added": added, "total": after, "error": None}


def get_last_update_info() -> dict:
    return _load_update_log()


def should_update_today() -> bool:
    log = _load_update_log()
    last = log.get("last_update")
    if not last:
        return True
    last_date = last.split(" ")[0]
    today = datetime.now().strftime("%Y-%m-%d")
    return last_date != today


def start_daily_updater(progress_callback=None):
    """
    Blocking loop — checks once at startup if an update is due,
    then checks again every 24 hours. Designed to run in a daemon thread.
    """
    import schedule

    def run_update():
        result = update_from_malwarebazaar(
            recent_only=True,
            progress_callback=progress_callback
        )
        if progress_callback:
            if result["error"]:
                progress_callback(f"Signature update failed: {result['error']}")
            else:
                progress_callback(
                    f"Signature update complete — {result['added']} new signatures "
                    f"(total: {result['total']})"
                )

    # Run immediately on start if not updated today
    if should_update_today():
        run_update()

    # Schedule daily at 3:00 AM
    schedule.every().day.at("03:00").do(run_update)

    while True:
        schedule.run_pending()
        time.sleep(60)
