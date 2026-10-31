"""
paths.py
Every module that stores persistent data (signatures.json, quarantine files,
scan history, whitelist, config) needs to know where "next to the app" is.

When running as a normal .py script, that's simply the script's own folder.
But when packaged into a single .exe (PyInstaller/Nuitka), the running
process is extracted into a TEMPORARY folder that gets deleted when the
app closes — so anything saved there (quarantine, whitelist, scan history)
would vanish on every restart. This module detects that case and points
persistent storage at the folder the .exe itself lives in instead, so data
survives across runs either way.
"""

import os
import sys


def get_base_dir() -> str:
    if getattr(sys, "frozen", False):
        # Running as a packaged executable (PyInstaller/Nuitka) —
        # use the folder the .exe itself is in, not the temp extraction dir.
        return os.path.dirname(os.path.abspath(sys.executable))
    else:
        # Running as a normal .py script
        return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = get_base_dir()
DATA_DIR = os.path.join(BASE_DIR, "data")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
