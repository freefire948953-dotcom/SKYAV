"""
monitor.py
Real-time protection layer. Watches key folders continuously and scans
any new or modified file the instant it appears — this is what makes an
AV "active" instead of just a manual scanner.

Requires: pip install watchdog
"""

import os
import time
import platform
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import signatures
import scanner
import quarantine
import alerts


class ThreatHandler(FileSystemEventHandler):
    def __init__(self, auto_quarantine: bool = True, on_detect=None):
        super().__init__()
        self.auto_quarantine = auto_quarantine
        self.on_detect = on_detect
        self.sig_db = signatures.load_signatures()
        self._recent = {}  # debounce: avoid scanning the same file 10x in a second

    def _should_process(self, path: str) -> bool:
        now = time.time()
        last = self._recent.get(path, 0)
        if now - last < 1.5:
            return False
        self._recent[path] = now
        return True

    def _handle(self, path: str):
        if not os.path.isfile(path):
            return
        if not self._should_process(path):
            return

        # Give the OS a moment to finish writing the file before we hash it
        time.sleep(0.3)

        result = scanner.scan_single_file(path, self.sig_db, auto_quarantine=False)

        if result["status"] in ("infected", "suspicious"):
            if self.auto_quarantine:
                quarantine.quarantine_file(path, result["detail"])
                result["detail"] += " [QUARANTINED]"
            alerts.send_threat_alert(result)
            if self.on_detect:
                self.on_detect(result)
            else:
                print(f"\n🚨 [{result['status'].upper()}] {path}\n   -> {result['detail']}")

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._handle(event.dest_path)


def get_watch_paths():
    system = platform.system()
    if system == "Windows":
        user = os.environ.get("USERPROFILE", "")
        return [
            os.path.join(user, "Downloads"),
            os.path.join(user, "AppData", "Local", "Temp"),
            os.path.join(user, "AppData", "Roaming"),
            os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Temp"),
            os.path.join(user, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            os.path.join(user, "Desktop"),
        ]
    else:
        home = os.path.expanduser("~")
        return ["/tmp", os.path.join(home, "Downloads")]


def start_monitor(paths: list = None, auto_quarantine: bool = True, on_detect=None):
    """
    Blocking call — starts watching the given paths (or default hotspots)
    and scans every new/modified file in real time. Ctrl+C to stop.
    """
    watch_paths = paths or get_watch_paths()
    watch_paths = [p for p in watch_paths if os.path.exists(p)]

    if not watch_paths:
        print("No valid paths to watch.")
        return

    handler = ThreatHandler(auto_quarantine=auto_quarantine, on_detect=on_detect)
    observer = Observer()

    for p in watch_paths:
        observer.schedule(handler, p, recursive=True)
        print(f"👁  Watching: {p}")

    observer.start()
    print(f"\nSkyAV Real-Time Protection is ACTIVE. (auto-quarantine={auto_quarantine})")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nReal-time protection stopped.")
    observer.join()


if __name__ == "__main__":
    start_monitor()
