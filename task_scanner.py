"""
task_scanner.py
Lists Windows Scheduled Tasks and flags ones that look like malware
persistence (running from Temp/AppData, hidden, or pointing to a script
interpreter with an encoded/suspicious command).
"""

import subprocess
import platform

IS_WINDOWS = platform.system() == "Windows"

SUSPICIOUS_PATH_HINTS = (
    "\\temp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\downloads\\",
)

SUSPICIOUS_COMMAND_HINTS = (
    "powershell -enc", "powershell.exe -e ", "-windowstyle hidden",
    "iex(", "invoke-expression", "downloadstring", "bitstransfer",
)


def _run_schtasks() -> str:
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return result.stdout
    except Exception:
        return ""


def _parse_tasks(raw: str) -> list:
    """Splits schtasks LIST /v output into one dict per task."""
    tasks = []
    current = {}
    for line in raw.splitlines():
        if not line.strip():
            if current:
                tasks.append(current)
                current = {}
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            current[key.strip()] = value.strip()
    if current:
        tasks.append(current)
    return tasks


def list_scheduled_tasks() -> list:
    """Returns list of dicts with TaskName, Run As User, Task To Run, Status, etc."""
    if not IS_WINDOWS:
        return []
    raw = _run_schtasks()
    return _parse_tasks(raw)


def flag_suspicious_tasks(tasks: list = None) -> list:
    """Adds is_suspicious + reasons to each task based on its 'Task To Run' command."""
    if tasks is None:
        tasks = list_scheduled_tasks()

    for task in tasks:
        cmd = task.get("Task To Run", "").lower()
        reasons = []

        if any(hint in cmd for hint in SUSPICIOUS_PATH_HINTS):
            reasons.append("Runs a program from a Temp/AppData/Downloads folder.")

        if any(hint in cmd for hint in SUSPICIOUS_COMMAND_HINTS):
            reasons.append("Command contains a pattern commonly used to hide/obfuscate malicious scripts.")

        task["is_suspicious"] = len(reasons) > 0
        task["reasons"] = reasons

    return tasks


def get_flagged_only() -> list:
    """Convenience: returns only the suspicious tasks."""
    return [t for t in flag_suspicious_tasks() if t["is_suspicious"]]
