"""
download_guard.py
Watches the user's Downloads folder in real time. The moment a NEW file
finishes downloading, it's scanned immediately (signature + heuristics).
If it's infected or suspicious, it gets quarantined/deleted before the
user has a realistic chance to open it.

Handles the fact that browsers write to a temp name first
(.crdownload for Chrome/Edge, .part for Firefox) and rename to the final
name only once the download is complete — we ignore the temp files and
only act once the final, real file appears.
"""

import os
import time
import platform
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import scanner
import quarantine
import signatures
import alerts

IS_WINDOWS = platform.system() == "Windows"

# Browsers' in-progress download file extensions — never scan/act on these,
# they're incomplete and will either finish (rename) or vanish (cancelled).
IN_PROGRESS_EXTENSIONS = {".crdownload", ".part", ".partial", ".download", ".tmp"}

# How long (seconds) a file's size must stay unchanged before we consider
# the download "settled" enough to scan safely.
STABLE_CHECK_DELAY = 1.0


def get_downloads_folder() -> str:
    if IS_WINDOWS:
        user = os.environ.get("USERPROFILE", "")
        return os.path.join(user, "Downloads")
    else:
        return os.path.join(os.path.expanduser("~"), "Downloads")


def _file_is_stable(path: str, wait: float = STABLE_CHECK_DELAY) -> bool:
    """Returns True if the file's size hasn't changed after `wait` seconds
    (i.e. nothing is still actively writing to it)."""
    try:
        size1 = os.path.getsize(path)
        time.sleep(wait)
        size2 = os.path.getsize(path)
        return size1 == size2 and size1 > 0
    except (FileNotFoundError, OSError):
        return False


class DownloadGuardHandler(FileSystemEventHandler):
    def __init__(self, on_verdict=None, auto_action: bool = True):
        """
        on_verdict: optional callback(dict) called with the scan result for
                    every file checked (clean or not) — useful for logging.
        auto_action: if True, automatically quarantines infected/suspicious
                     files. If False, only reports (caller decides what to do).
        """
        super().__init__()
        self.on_verdict = on_verdict
        self.auto_action = auto_action
        self._processed = set()

    def _should_ignore(self, path: str) -> bool:
        ext = os.path.splitext(path)[1].lower()
        return ext in IN_PROGRESS_EXTENSIONS

    def _handle_new_file(self, path: str):
        if self._should_ignore(path):
            return
        if path in self._processed:
            return
        self._processed.add(path)

        # Run the check in a background thread so we never block the
        # watchdog event loop (hashing/scanning a large file takes time).
        threading.Thread(target=self._scan_and_act, args=(path,), daemon=True).start()

    def _scan_and_act(self, path: str):
        if not _file_is_stable(path):
            # Still being written (or already gone) — skip for now.
            return
        if not os.path.exists(path):
            return

        sig_db = signatures.load_signatures()
        result = scanner.scan_single_file(path, sig_db, auto_quarantine=False)

        if self.on_verdict:
            self.on_verdict(result)

        if result["status"] in ("infected", "suspicious"):
            alerts.send_threat_alert(result)
            if self.auto_action:
                quarantine.quarantine_file(path, result["detail"])

    def on_created(self, event):
        if not event.is_directory:
            self._handle_new_file(event.src_path)

    def on_moved(self, event):
        # Browsers often download as "file.ext.crdownload" then RENAME
        # (moved) to "file.ext" once complete — this is the event that
        # actually matters most.
        if not event.is_directory:
            self._handle_new_file(event.dest_path)


def start_download_guard(on_verdict=None, auto_action: bool = True) -> Observer:
    """Starts watching the Downloads folder. Returns the Observer (call .stop() to end)."""
    folder = get_downloads_folder()
    os.makedirs(folder, exist_ok=True)

    handler = DownloadGuardHandler(on_verdict=on_verdict, auto_action=auto_action)
    observer = Observer()
    observer.schedule(handler, folder, recursive=False)
    observer.start()
    return observer
