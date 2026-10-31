"""
logger.py
Keeps a persistent record of every scan run and every threat found.
Used by main.py, gui.py, and registry_guard.py so nothing gets lost
once the terminal window closes.
"""

import os
import json
import time
from datetime import datetime

import paths

DATA_DIR = paths.DATA_DIR
LOG_FILE = os.path.join(DATA_DIR, "scan_history.jsonl")  # one JSON object per line
MAX_LOG_ENTRIES = 500  # auto-trim so the file never grows unbounded


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def log_scan(scan_type: str, summary: dict, elapsed: float):
    """Appends one scan's result to the history log."""
    _ensure_dir()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": scan_type,
        "scanned": summary.get("scanned", 0),
        "infected": summary.get("infected", 0),
        "suspicious": summary.get("suspicious", 0),
        "skipped": summary.get("skipped", 0),
        "elapsed_seconds": round(elapsed, 1),
        "flagged": [
            {"path": f["path"], "status": f["status"], "detail": f["detail"]}
            for f in summary.get("flagged", [])
        ],
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

    _trim_log()


def log_realtime_detection(result: dict):
    """Appends a single real-time-protection detection event."""
    _ensure_dir()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": "real-time",
        "scanned": 1,
        "infected": 1 if result["status"] == "infected" else 0,
        "suspicious": 1 if result["status"] == "suspicious" else 0,
        "skipped": 0,
        "elapsed_seconds": 0,
        "flagged": [{"path": result["path"], "status": result["status"], "detail": result["detail"]}],
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    _trim_log()


def _trim_log():
    if not os.path.exists(LOG_FILE):
        return
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    if len(lines) > MAX_LOG_ENTRIES:
        with open(LOG_FILE, "w") as f:
            f.writelines(lines[-MAX_LOG_ENTRIES:])


def read_history(limit: int = 20) -> list:
    """Returns the most recent `limit` scan entries, newest first."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    entries = [json.loads(line) for line in lines if line.strip()]
    return list(reversed(entries))[:limit]


def total_threats_found() -> int:
    history = read_history(limit=MAX_LOG_ENTRIES)
    return sum(e["infected"] + e["suspicious"] for e in history)
