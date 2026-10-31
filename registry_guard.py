"""
registry_guard.py
Malware almost always tries to survive a reboot by adding itself to a
Windows "Run" registry key or the Startup folder. This module snapshots
those locations and alerts on any NEW entry that appears — which is
exactly how real AVs catch persistence attempts.

Windows-only (uses winreg). Safe no-op on other platforms for testing.
"""

import os
import json
import platform
import time
import subprocess
import hashlib

import paths

DATA_DIR = paths.DATA_DIR
SNAPSHOT_FILE = os.path.join(DATA_DIR, "registry_snapshot.json")

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import winreg

RUN_KEYS = [
    (r"HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (r"HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (r"HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (r"HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

HIVE_MAP = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE} if IS_WINDOWS else {}


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _read_run_key(hive_name: str, subkey: str) -> dict:
    """Returns {value_name: command} for one registry Run key."""
    entries = {}
    if not IS_WINDOWS:
        return entries
    try:
        hive = HIVE_MAP[hive_name]
        with winreg.OpenKey(hive, subkey) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    entries[f"{hive_name}\\{subkey}\\{name}"] = str(value)
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    return entries


def get_startup_folder_files() -> dict:
    """Returns {filepath: last_modified_time} for both user and all-users Startup folders."""
    entries = {}
    if not IS_WINDOWS:
        return entries

    user = os.environ.get("USERPROFILE", "")
    programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")

    folders = [
        os.path.join(user, "AppData", "Roaming", "Microsoft", "Windows",
                     "Start Menu", "Programs", "Startup"),
        os.path.join(programdata, "Microsoft", "Windows", "Start Menu",
                     "Programs", "Startup"),
    ]
    for folder in folders:
        if os.path.isdir(folder):
            for fname in os.listdir(folder):
                fpath = os.path.join(folder, fname)
                if os.path.isfile(fpath):
                    entries[fpath] = os.path.getmtime(fpath)
    return entries


def get_scheduled_tasks() -> dict:
    """
    Returns {task_name: command} for all Windows Scheduled Tasks.
    Malware frequently uses 'schtasks /create' as a persistence mechanism
    instead of (or in addition to) the registry Run keys.
    """
    tasks = {}
    if not IS_WINDOWS:
        return tasks
    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            text=True, stderr=subprocess.DEVNULL, timeout=20
        )
        lines = output.strip().split("\n")
        if len(lines) < 2:
            return tasks
        header = [h.strip('"') for h in lines[0].split('","')]
        try:
            name_idx = header.index("TaskName")
            cmd_idx = header.index("Task To Run")
        except ValueError:
            return tasks
        for line in lines[1:]:
            fields = [f.strip('"') for f in line.split('","')]
            if len(fields) > max(name_idx, cmd_idx):
                tasks[fields[name_idx]] = fields[cmd_idx]
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass
    return tasks


def get_hosts_file_hash() -> str:
    """
    Hashes the Windows hosts file. Malware sometimes edits this file to
    redirect legitimate domains (e.g. bank websites, Windows Update) to
    malicious servers. Any change here is worth flagging.
    """
    if not IS_WINDOWS:
        return ""
    hosts_path = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32", "drivers", "etc", "hosts")
    try:
        with open(hosts_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def get_hosts_file_content() -> str:
    if not IS_WINDOWS:
        return ""
    hosts_path = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32", "drivers", "etc", "hosts")
    try:
        with open(hosts_path, "r", errors="ignore") as f:
            return f.read()
    except (FileNotFoundError, PermissionError, OSError):
        return ""



def take_snapshot() -> dict:
    """Captures the current state of all Run keys + Startup folders + Scheduled Tasks + hosts file."""
    snapshot = {"registry": {}, "startup_files": {}, "scheduled_tasks": {}, "hosts_hash": ""}
    for hive_name, subkey in RUN_KEYS:
        snapshot["registry"].update(_read_run_key(hive_name, subkey))
    snapshot["startup_files"] = get_startup_folder_files()
    snapshot["scheduled_tasks"] = get_scheduled_tasks()
    snapshot["hosts_hash"] = get_hosts_file_hash()
    return snapshot


def save_baseline():
    """Call this once to establish 'what's normal' on this PC."""
    _ensure_dir()
    snapshot = take_snapshot()
    with open(SNAPSHOT_FILE, "w") as f:
        json.dump(snapshot, f, indent=2)
    reg_count = len(snapshot["registry"])
    startup_count = len(snapshot["startup_files"])
    print(f"Baseline saved: {reg_count} registry autorun entries, {startup_count} startup files.")
    return snapshot


def load_baseline() -> dict:
    if not os.path.exists(SNAPSHOT_FILE):
        return None
    with open(SNAPSHOT_FILE, "r") as f:
        return json.load(f)


def check_for_changes() -> list:
    """
    Compares current state against the saved baseline.
    Returns a list of alert dicts for anything NEW that wasn't there before.
    """
    baseline = load_baseline()
    if baseline is None:
        return [{"type": "error", "message": "No baseline set. Run: python main.py --guard-baseline first."}]

    current = take_snapshot()
    alerts = []

    # New registry autorun entries
    for key, value in current["registry"].items():
        if key not in baseline["registry"]:
            alerts.append({
                "type": "new_registry_autorun",
                "message": f"NEW autorun registry entry: {key} -> {value}",
            })
        elif baseline["registry"][key] != value:
            alerts.append({
                "type": "modified_registry_autorun",
                "message": f"MODIFIED autorun entry: {key} changed to -> {value}",
            })

    # New startup folder files
    for path, mtime in current["startup_files"].items():
        if path not in baseline["startup_files"]:
            alerts.append({
                "type": "new_startup_file",
                "message": f"NEW file in Startup folder: {path}",
            })

    # New/changed Scheduled Tasks
    baseline_tasks = baseline.get("scheduled_tasks", {})
    for task_name, command in current.get("scheduled_tasks", {}).items():
        if task_name not in baseline_tasks:
            alerts.append({
                "type": "new_scheduled_task",
                "message": f"NEW Scheduled Task: {task_name} -> {command}",
            })
        elif baseline_tasks[task_name] != command:
            alerts.append({
                "type": "modified_scheduled_task",
                "message": f"MODIFIED Scheduled Task: {task_name} now runs -> {command}",
            })

    # Hosts file tampering (DNS redirection attacks)
    baseline_hosts_hash = baseline.get("hosts_hash", "")
    current_hosts_hash = current.get("hosts_hash", "")
    if baseline_hosts_hash and current_hosts_hash and baseline_hosts_hash != current_hosts_hash:
        alerts.append({
            "type": "hosts_file_modified",
            "message": "Windows hosts file was MODIFIED — could indicate DNS redirection/hijacking. "
                       "Check System32\\drivers\\etc\\hosts manually.",
        })

    return alerts


def start_guard(interval_seconds: int = 30, on_alert=None):
    """
    Blocking loop — checks for new persistence entries every `interval_seconds`.
    Call save_baseline() once before starting this for the first time.
    """
    if load_baseline() is None:
        print("No baseline found — creating one now...")
        save_baseline()

    print(f"\n🛡  Registry/Startup Guard is ACTIVE (checking every {interval_seconds}s).")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            alerts = check_for_changes()
            for alert in alerts:
                if on_alert:
                    on_alert(alert)
                else:
                    print(f"🚨 {alert['message']}")
            if alerts:
                # Update baseline so we don't re-alert the same entry forever
                save_baseline()
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("\nRegistry/Startup Guard stopped.")
