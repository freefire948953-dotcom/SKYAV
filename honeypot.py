"""
honeypot.py
Places invisible 'trap' files in common ransomware attack locations.
Normal software NEVER touches these files. If ANY process modifies or
deletes them, it's almost certainly ransomware or malware attempting
to encrypt/destroy files. Triggers instant alert + process kill.

This is the same 'honeypot' technique used by enterprise AVs like
SentinelOne and CrowdStrike — we implement it at user-mode level.
"""

import os
import time
import json
import platform
import threading
import hashlib
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import paths
import alerts

IS_WINDOWS = platform.system() == "Windows"

DATA_DIR = paths.DATA_DIR
HONEYPOT_META = os.path.join(DATA_DIR, "honeypot_meta.json")

# Decoy file names that look like valuable targets to ransomware
DECOY_NAMES = [
    "Passwords_Backup.txt",
    "Financial_Report_2026.xlsx",
    "Personal_Documents.docx",
    "private_keys.pem",
    "database_backup.sql",
]

# Locations where ransomware typically starts encrypting
def get_honeypot_dirs():
    if not IS_WINDOWS:
        home = os.path.expanduser("~")
        return [home, "/tmp"]
    user = os.environ.get("USERPROFILE", "")
    return [
        os.path.join(user, "Documents"),
        os.path.join(user, "Desktop"),
        os.path.join(user, "Downloads"),
        os.path.join(user, "Pictures"),
    ]

# Harmless but realistic-looking content for each decoy
DECOY_CONTENTS = {
    "Passwords_Backup.txt": (
        "# Personal Password Backup\n"
        "# Created by SkyAV Honeypot — DO NOT MODIFY\n"
        "Gmail: [protected]\nNetflix: [protected]\nBank: [protected]\n"
    ),
    "Financial_Report_2026.xlsx": b"PK\x03\x04\x14\x00\x00\x00",  # fake xlsx header
    "Personal_Documents.docx": b"PK\x03\x04\x14\x00\x00\x00",   # fake docx header
    "private_keys.pem": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA# SkyAV Honeypot Decoy File\n"
        "-----END RSA PRIVATE KEY-----\n"
    ),
    "database_backup.sql": (
        "-- SkyAV Honeypot Decoy\n"
        "CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(255));\n"
        "INSERT INTO users VALUES (1, 'admin', '[honeypot_hash]');\n"
    ),
}


def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_meta() -> dict:
    if not os.path.exists(HONEYPOT_META):
        return {}
    with open(HONEYPOT_META, "r") as f:
        return json.load(f)


def _save_meta(meta: dict):
    _ensure_dir()
    with open(HONEYPOT_META, "w") as f:
        json.dump(meta, f, indent=2)


def deploy_honeypots() -> int:
    """Creates decoy files in all honeypot directories. Returns count placed."""
    meta = {}
    count = 0
    for directory in get_honeypot_dirs():
        if not os.path.isdir(directory):
            continue
        for name in DECOY_NAMES:
            path = os.path.join(directory, name)
            content = DECOY_CONTENTS.get(name, "SkyAV Honeypot Decoy\n")
            try:
                mode = "wb" if isinstance(content, bytes) else "w"
                with open(path, mode) as f:
                    f.write(content)
                meta[path] = _sha256(path)
                count += 1
                # Hide the file on Windows (attrib +h)
                if IS_WINDOWS:
                    os.system(f'attrib +h "{path}" >nul 2>&1')
            except (PermissionError, OSError):
                continue
    _save_meta(meta)
    return count


def remove_honeypots():
    """Removes all deployed decoy files."""
    meta = _load_meta()
    for path in meta:
        try:
            if IS_WINDOWS:
                os.system(f'attrib -h "{path}" >nul 2>&1')
            os.remove(path)
        except Exception:
            pass
    _save_meta({})


def _find_writer(path: str) -> str:
    """Best-effort attempt to identify which process last wrote to a path."""
    try:
        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            try:
                files = proc.open_files()
                if files and any(f.path.lower() == path.lower() for f in files):
                    return f"{proc.info['name']} (PID {proc.info['pid']})"
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except Exception:
        pass
    return "Unknown process"


class HoneypotHandler(FileSystemEventHandler):
    def __init__(self, on_trigger=None):
        super().__init__()
        self.meta = _load_meta()
        self.on_trigger = on_trigger
        self._alerted = set()  # avoid repeat alerts for same file

    def _handle(self, path: str, event_type: str):
        path_lower = path.lower()
        if not any(path_lower == k.lower() for k in self.meta):
            return
        if path in self._alerted:
            return
        self._alerted.add(path)

        writer = _find_writer(path)
        alert = {
            "path": path,
            "event": event_type,
            "writer": writer,
            "message": (
                f"🚨 RANSOMWARE/MALWARE ALERT\n"
                f"Honeypot file {os.path.basename(path)} was {event_type}!\n"
                f"Likely process: {writer}\n"
                f"This is a strong indicator of ransomware or destructive malware."
            )
        }

        alerts.send_threat_alert({
            "path": path,
            "status": "infected",
            "detail": f"Honeypot triggered ({event_type}) by {writer} — possible ransomware",
        })

        if self.on_trigger:
            self.on_trigger(alert)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "MODIFIED")

    def on_deleted(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "DELETED")

    def on_moved(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "MOVED/RENAMED")


def start_honeypot_guard(on_trigger=None) -> Observer:
    """
    Starts watching all honeypot directories.
    Returns the Observer (call observer.stop() to stop it).
    """
    meta = _load_meta()
    if not meta:
        deploy_honeypots()
        meta = _load_meta()

    watch_dirs = set(os.path.dirname(p) for p in meta)
    handler = HoneypotHandler(on_trigger=on_trigger)
    observer = Observer()
    for d in watch_dirs:
        if os.path.isdir(d):
            observer.schedule(handler, d, recursive=False)
    observer.start()
    return observer
