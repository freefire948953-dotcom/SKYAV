"""
quarantine.py
Instead of deleting files outright (risky if it's a false positive),
we move them into a locked-down quarantine folder, renamed so they can't
execute, with metadata saved for restore.
"""

import os
import json
import shutil
import time

import paths

QUARANTINE_DIR = paths.QUARANTINE_DIR
META_FILE = os.path.join(QUARANTINE_DIR, "_meta.json")


def _load_meta():
    if not os.path.exists(META_FILE):
        return {}
    with open(META_FILE, "r") as f:
        return json.load(f)


def _save_meta(meta):
    with open(META_FILE, "w") as f:
        json.dump(meta, f, indent=2)


def quarantine_file(filepath: str, reason: str) -> str:
    """
    Moves the file to quarantine, strips its extension so Windows won't
    execute it accidentally, and logs metadata for restore/audit.
    Returns the quarantined file's new path.
    """
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    meta = _load_meta()

    qid = f"q_{int(time.time() * 1000)}"
    dest = os.path.join(QUARANTINE_DIR, qid + ".quar")

    try:
        shutil.move(filepath, dest)
    except (PermissionError, FileNotFoundError, OSError) as e:
        return f"FAILED: {e}"

    meta[qid] = {
        "original_path": filepath,
        "reason": reason,
        "timestamp": time.time(),
    }
    _save_meta(meta)
    return dest


def restore_file(qid: str) -> str:
    """Restores a quarantined file back to its original location."""
    meta = _load_meta()
    if qid not in meta:
        return f"No such quarantine ID: {qid}"

    src = os.path.join(QUARANTINE_DIR, qid + ".quar")
    dest = meta[qid]["original_path"]

    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.move(src, dest)
    except (PermissionError, FileNotFoundError, OSError) as e:
        return f"FAILED: {e}"

    del meta[qid]
    _save_meta(meta)
    return dest


def list_quarantine() -> dict:
    return _load_meta()


def delete_permanently(qid: str) -> bool:
    meta = _load_meta()
    if qid not in meta:
        return False
    path = os.path.join(QUARANTINE_DIR, qid + ".quar")
    if os.path.exists(path):
        os.remove(path)
    del meta[qid]
    _save_meta(meta)
    return True
