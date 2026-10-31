"""
scanner.py
Core scan engine — combines signature matching + heuristic analysis.
Supports Quick / Full / Custom scan modes, just like Windows Defender.
"""

import os
import hashlib
import platform

import signatures
import heuristics
import quarantine
import whitelist
import signature_check
import paths

# Folders to never scan/flag as part of our own code — heuristic keyword
# matching would otherwise flag our own detection logic (it contains the
# exact strings it's designed to look for, on purpose). We exclude BOTH:
#   1. paths.BASE_DIR — wherever the running .exe actually lives (handles
#      the compiled/frozen case correctly, since __file__ isn't reliable there)
#   2. the raw source folder — handles running from plain .py source,
#      including the case where source and a compiled build sit side by side
#      on a dev machine (as they do during development/testing)
SELF_DIRS = {paths.BASE_DIR, os.path.dirname(os.path.abspath(__file__))}

# Common malware hotspots — used for Quick Scan
def get_quick_scan_paths():
    system = platform.system()
    if system == "Windows":
        user = os.environ.get("USERPROFILE", "")
        return [
            os.path.join(user, "AppData", "Local", "Temp"),
            os.path.join(user, "AppData", "Roaming"),
            os.path.join(user, "Downloads"),
            os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Temp"),
            os.path.join(user, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        ]
    else:
        # Linux/Mac fallback for testing in non-Windows environments
        home = os.path.expanduser("~")
        return [
            "/tmp",
            os.path.join(home, "Downloads"),
        ]


def sha256_of_file(filepath: str, block_size: int = 65536) -> str:
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(block_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return ""


def scan_single_file(filepath: str, sig_db: dict, auto_quarantine: bool = False, skip_heuristics: bool = False) -> dict:
    """Runs both signature + heuristic checks on one file."""
    result = {
        "path": filepath,
        "status": "clean",
        "detail": "",
    }

    file_hash = sha256_of_file(filepath)
    if not file_hash:
        result["status"] = "skipped"
        result["detail"] = "unreadable"
        return result

    # 0. Whitelist — already confirmed safe before (via VT, signature, or manual mark)
    wl = whitelist.list_whitelist()
    if file_hash in wl:
        result["status"] = "clean"
        result["detail"] = f"Whitelisted: {wl[file_hash]['reason']}"
        return result

    # 1. Signature match (exact known malware)
    if file_hash in sig_db:
        result["status"] = "infected"
        result["detail"] = f"Known malware: {sig_db[file_hash]}"
        if auto_quarantine:
            quarantine.quarantine_file(filepath, result["detail"])
            result["detail"] += " [QUARANTINED]"
        return result

    # 2. Digital signature check — trusted publisher = auto-clean, skip heuristics
    ext = os.path.splitext(filepath)[1].lower()
    if ext in (".exe", ".dll", ".sys", ".msi"):
        sig_result = signature_check.verify_signature(filepath)
        if sig_result["status"] == "trusted":
            publisher = sig_result["publisher"] or "verified publisher"
            whitelist.add_to_whitelist(filepath, f"Trusted digital signature ({publisher})")
            result["status"] = "clean"
            result["detail"] = f"Trusted signature: {publisher}"
            return result

    # 3. Heuristic check (unknown/zero-day suspicious behavior) — skipped for
    # files inside noisy package-manager directories (see skip_heuristics)
    if not skip_heuristics:
        h_result = heuristics.scan_file_heuristically(filepath)
        if h_result["suspicious"]:
            result["status"] = "suspicious"
            result["detail"] = "; ".join(h_result["reasons"])
            if auto_quarantine:
                quarantine.quarantine_file(filepath, result["detail"])
                result["detail"] += " [QUARANTINED]"

    return result


# Folders that are overwhelmingly full of legitimate third-party library code
# (networking, subprocess, shell helpers are all completely normal there).
# Signature matching (exact hash) still applies everywhere — only the
# loose behavioral heuristics/YARA are skipped inside these, to avoid
# flooding a developer's machine with false positives from pip/npm packages.
LOW_PRIORITY_DIR_NAMES = {
    "venv", ".venv", "env", "site-packages", "node_modules",
    ".git", "__pycache__", "dist-info", "egg-info",
}


def _is_low_priority_path(path: str) -> bool:
    parts = os.path.normpath(path).split(os.sep)
    return any(p.lower() in LOW_PRIORITY_DIR_NAMES or p.lower().endswith((".dist-info", ".egg-info"))
               for p in parts)


def scan_paths(paths: list, auto_quarantine: bool = False, progress_callback=None) -> dict:
    """
    Walks through the given paths, scans every file.
    Returns a summary dict with counts and a list of flagged files.
    """
    sig_db = signatures.load_signatures()
    summary = {
        "scanned": 0,
        "infected": 0,
        "suspicious": 0,
        "skipped": 0,
        "flagged": [],
    }

    for base_path in paths:
        if not os.path.exists(base_path):
            continue
        for root, dirs, files in os.walk(base_path):
            # Never scan our own installation folder or Python bytecode cache
            if any(os.path.abspath(root).startswith(d) for d in SELF_DIRS):
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d != "__pycache__"]

            low_priority = _is_low_priority_path(root)

            for fname in files:
                fpath = os.path.join(root, fname)
                result = scan_single_file(fpath, sig_db, auto_quarantine, skip_heuristics=low_priority)
                summary["scanned"] += 1

                if result["status"] == "infected":
                    summary["infected"] += 1
                    summary["flagged"].append(result)
                elif result["status"] == "suspicious":
                    summary["suspicious"] += 1
                    summary["flagged"].append(result)
                elif result["status"] == "skipped":
                    summary["skipped"] += 1

                if progress_callback:
                    progress_callback(summary["scanned"], fpath)

    return summary


def quick_scan(auto_quarantine: bool = False, progress_callback=None) -> dict:
    return scan_paths(get_quick_scan_paths(), auto_quarantine, progress_callback)


def full_scan(auto_quarantine: bool = False, progress_callback=None) -> dict:
    system = platform.system()
    if system == "Windows":
        # Scan all fixed drives A-Z that exist
        roots = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
    else:
        roots = ["/"]
    return scan_paths(roots, auto_quarantine, progress_callback)


def custom_scan(path: str, auto_quarantine: bool = False, progress_callback=None) -> dict:
    return scan_paths([path], auto_quarantine, progress_callback)
