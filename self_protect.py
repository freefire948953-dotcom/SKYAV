"""
self_protect.py
Monitors SkyAV's own critical files against tampering by malware.

A common malware technique is to target and disable the antivirus itself —
delete its executables, corrupt its config/whitelist, or replace its
signature database with an empty file. This module watches SkyAV's own
folder and alerts immediately if anything unauthorized touches it.

Uses watchdog (already a SkyAV dependency) so no new libraries needed.
"""

import os
import hashlib
import json
import platform
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import paths
import alerts

BASE_DIR       = paths.BASE_DIR
DATA_DIR       = paths.DATA_DIR
SELF_HASH_FILE = os.path.join(DATA_DIR, "self_integrity.json")

# Source/binary extensions to watch — these should NEVER change unless
# the user deliberately edits/updates SkyAV itself.
PROTECTED_EXTENSIONS = {".py", ".ico", ".png", ".bat"}

# Data files intentionally excluded from the hash baseline because SkyAV
# itself writes to them during normal operation (signature updates, scan
# results, config saves, whitelist changes, registry snapshots, YARA
# rule downloads). Watching them causes constant false-positive "tampered"
# alerts after every routine update or scan.
# If you want to protect a specific data file, add it here:
PROTECTED_DATA_FILES: set = set()

# How long (seconds) to suppress repeat alerts for the same file.
# Prevents alert floods when an editor auto-saves repeatedly.
ALERT_COOLDOWN_SECONDS = 30


def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def take_integrity_snapshot() -> dict:
    """Hashes all critical SkyAV files and saves as baseline."""
    os.makedirs(DATA_DIR, exist_ok=True)
    snapshot = {}

    # Source / exe files in BASE_DIR
    try:
        for fname in os.listdir(BASE_DIR):
            ext = os.path.splitext(fname)[1].lower()
            if ext in PROTECTED_EXTENSIONS:
                full = os.path.join(BASE_DIR, fname)
                if os.path.isfile(full):
                    snapshot[full] = _sha256(full)
    except OSError:
        pass

    # Optional data files (empty by default — see comment above)
    for fname in PROTECTED_DATA_FILES:
        full = os.path.join(DATA_DIR, fname)
        if os.path.exists(full):
            snapshot[full] = _sha256(full)

    with open(SELF_HASH_FILE, "w") as f:
        json.dump(snapshot, f, indent=2)

    return snapshot


def verify_integrity() -> list:
    """Checks current file hashes against the saved baseline.
    Returns a list of tampering alert dicts (empty = all good)."""
    if not os.path.exists(SELF_HASH_FILE):
        return []

    try:
        with open(SELF_HASH_FILE, "r") as f:
            baseline = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    results = []
    for fpath, expected_hash in baseline.items():
        if not os.path.exists(fpath):
            results.append({
                "type":    "deleted",
                "path":    fpath,
                "message": f"SkyAV file DELETED: {os.path.basename(fpath)} — possible AV tampering!",
            })
        else:
            current = _sha256(fpath)
            if current != expected_hash:
                results.append({
                    "type":    "modified",
                    "path":    fpath,
                    "message": f"SkyAV file MODIFIED: {os.path.basename(fpath)} — possible AV tampering!",
                })

    return results


class SelfProtectHandler(FileSystemEventHandler):
    """Watchdog handler that fires on file changes inside SkyAV's folders."""

    def __init__(self, on_tamper=None):
        super().__init__()
        self.on_tamper = on_tamper
        # path -> last-alert timestamp (epoch seconds) for cooldown
        self._last_alerted: dict = {}

    def _should_watch(self, path: str) -> bool:
        fname = os.path.basename(path)
        ext   = os.path.splitext(fname)[1].lower()
        return ext in PROTECTED_EXTENSIONS or fname in PROTECTED_DATA_FILES

    def _handle(self, path: str, event_type: str):
        if not self._should_watch(path):
            return

        import time
        now  = time.monotonic()
        last = self._last_alerted.get(path, 0)
        if now - last < ALERT_COOLDOWN_SECONDS:
            return  # suppress duplicate alert within cooldown window
        self._last_alerted[path] = now

        fname = os.path.basename(path)
        msg   = (f"SkyAV file {event_type}: {fname} — "
                 "possible antivirus tampering by malware!")

        alert_info = {"type": event_type, "path": path, "message": msg}

        try:
            alerts.send_threat_alert({
                "path":   path,
                "status": "infected",
                "detail": msg,
            })
        except Exception:
            pass  # never let alert failure crash the observer thread

        if self.on_tamper:
            try:
                self.on_tamper(alert_info)
            except Exception:
                pass

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "MODIFIED")

    def on_deleted(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "DELETED")


def start_self_protection(on_tamper=None) -> Observer:
    """Starts watching SkyAV's own folders. Returns the Observer instance
    (call .stop() then .join() to shut it down cleanly)."""
    # Create baseline on first run (or after a manual delete/refresh)
    if not os.path.exists(SELF_HASH_FILE):
        take_integrity_snapshot()

    handler  = SelfProtectHandler(on_tamper=on_tamper)
    observer = Observer()
    observer.schedule(handler, BASE_DIR, recursive=False)
    if DATA_DIR != BASE_DIR and os.path.isdir(DATA_DIR):
        observer.schedule(handler, DATA_DIR, recursive=False)
    observer.start()
    return observer
