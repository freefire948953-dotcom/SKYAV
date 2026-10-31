"""
usb_guard.py
Monitors for new USB/removable drives being plugged in and automatically
scans them the moment they're connected — before the user opens any files.

USB drives are one of the most common malware infection vectors (autorun
attacks, infected executables disguised as legitimate files, etc.)

Windows-only via win32api. Safe no-op on other platforms.
"""

import os
import time
import platform
import threading

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import ctypes


def get_removable_drives() -> set:
    """Returns a set of drive letters for currently connected removable drives."""
    if not IS_WINDOWS:
        return set()

    drives = set()
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            letter = chr(65 + i) + ":\\"
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(letter)
            # DRIVE_REMOVABLE = 2
            if drive_type == 2:
                drives.add(letter)
    return drives


def start_usb_guard(on_new_drive=None, poll_interval: float = 3.0):
    """
    Polls for new removable drives every poll_interval seconds.
    Calls on_new_drive(drive_letter) when a new USB is detected.
    Blocking — run in a daemon thread.
    """
    known_drives = get_removable_drives()
    print(f"USB Guard active. Currently connected removable drives: {known_drives or 'none'}")

    while True:
        time.sleep(poll_interval)
        current = get_removable_drives()
        new_drives = current - known_drives

        for drive in new_drives:
            print(f"New removable drive detected: {drive}")
            if on_new_drive:
                threading.Thread(
                    target=on_new_drive, args=(drive,), daemon=True
                ).start()

        known_drives = current
