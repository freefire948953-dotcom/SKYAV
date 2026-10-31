"""
whitelist.py
Once a file is confirmed clean (via VirusTotal, digital signature, or manual
"Mark as Safe"), remember it forever so it never gets re-flagged. This is
what stops the same false positive (like idle.exe) from appearing on every
single scan.
"""

import os
import json
import hashlib

import paths

DATA_DIR = paths.DATA_DIR
WHITELIST_FILE = os.path.join(DATA_DIR, "whitelist.json")


def _ensure_file():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            json.dump({}, f)


def _load() -> dict:
    _ensure_file()
    with open(WHITELIST_FILE, "r") as f:
        return json.load(f)


def _save(data: dict):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(data, f, indent=2)


def sha256_of_file(filepath: str) -> str:
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return ""


def is_whitelisted(filepath: str) -> bool:
    file_hash = sha256_of_file(filepath)
    if not file_hash:
        return False
    return file_hash in _load()


def add_to_whitelist(filepath: str, reason: str = "Manually marked safe"):
    file_hash = sha256_of_file(filepath)
    if not file_hash:
        return False
    data = _load()
    data[file_hash] = {"path": filepath, "reason": reason}
    _save(data)
    return True


def remove_from_whitelist(file_hash: str) -> bool:
    data = _load()
    if file_hash in data:
        del data[file_hash]
        _save(data)
        return True
    return False


def list_whitelist() -> dict:
    return _load()
