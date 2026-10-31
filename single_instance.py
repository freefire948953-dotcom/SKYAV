"""
single_instance.py
Prevents multiple copies of the SkyAV GUI from running at once — without
this, launching the app repeatedly (double-clicking the shortcut/exe
multiple times) spawns a new background process and a new tray icon every
time, cluttering the system tray with duplicates that never go away until
each one is manually closed.

Uses a named Windows mutex: the OS itself guarantees only one process can
hold it, so this works reliably even across completely separate process
launches (unlike a lock file, which can be left behind if a process crashes).
"""

import platform

IS_WINDOWS = platform.system() == "Windows"

_mutex_handle = None


def is_already_running() -> bool:
    """
    Call this once at startup. Returns True if another instance is already
    running (caller should exit without doing anything further). Returns
    False if this is the only instance (safe to proceed) — and holds the
    lock for the lifetime of this process.
    """
    global _mutex_handle

    if not IS_WINDOWS:
        return False  # single-instance enforcement is Windows-only for now

    import ctypes

    ERROR_ALREADY_EXISTS = 183
    mutex_name = "Global\\SkyAV_SingleInstance_Mutex"

    _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
    last_error = ctypes.windll.kernel32.GetLastError()

    return last_error == ERROR_ALREADY_EXISTS
