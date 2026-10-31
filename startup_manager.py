"""
startup_manager.py
Lists all programs configured to launch at Windows startup (registry Run
keys + Startup folder shortcuts), and lets the user disable any of them.
Malware very commonly persists by adding itself here.
"""

import os
import platform

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import winreg

REGISTRY_RUN_KEYS = [
    (r"HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (r"HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\Run"),
]

_HIVE_MAP = {
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER if IS_WINDOWS else None,
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE if IS_WINDOWS else None,
}


def _startup_folder_paths():
    user = os.environ.get("USERPROFILE", "")
    programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
    return [
        os.path.join(user, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(programdata, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"),
    ]


def list_startup_items() -> list:
    """
    Returns a list of dicts:
      {source: "registry"|"folder", hive, key_path, name, command, location}
    """
    items = []

    if IS_WINDOWS:
        for hive_name, key_path in REGISTRY_RUN_KEYS:
            hive = _HIVE_MAP[hive_name]
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            items.append({
                                "source": "registry",
                                "hive": hive_name,
                                "key_path": key_path,
                                "name": name,
                                "command": value,
                            })
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                continue

        for folder in _startup_folder_paths():
            if not os.path.isdir(folder):
                continue
            for fname in os.listdir(folder):
                full = os.path.join(folder, fname)
                if os.path.isfile(full):
                    items.append({
                        "source": "folder",
                        "name": fname,
                        "command": full,
                        "folder": folder,
                    })

    return items


def disable_startup_item(item: dict) -> bool:
    """Removes a registry Run entry or deletes a Startup-folder shortcut. Returns success bool."""
    try:
        if item["source"] == "registry":
            hive = _HIVE_MAP[item["hive"]]
            with winreg.OpenKey(hive, item["key_path"], 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, item["name"])
            return True
        elif item["source"] == "folder":
            os.remove(item["command"])
            return True
    except (OSError, FileNotFoundError, PermissionError):
        return False
    return False


# Locations a legitimate startup entry's target normally lives in.
# Anything pointing outside these (e.g. Temp, Downloads, AppData\Roaming
# root) is worth a second look, though not proof of malware by itself.
COMMON_TRUSTED_DIRS = ("program files", "windows\\system32", "windows\\syswow64")
SUSPICIOUS_DIRS = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\")


def flag_suspicious(items: list) -> list:
    """Adds an 'is_suspicious' bool + reason to each item based on its target path."""
    for item in items:
        cmd_lower = item["command"].lower()
        item["is_suspicious"] = False
        item["reason"] = ""
        if any(d in cmd_lower for d in SUSPICIOUS_DIRS):
            item["is_suspicious"] = True
            item["reason"] = "Runs from a Temp/Downloads folder — unusual for legitimate startup software."
        elif not any(d in cmd_lower for d in COMMON_TRUSTED_DIRS) and cmd_lower.strip():
            # Not necessarily bad, just not in a well-known trusted directory.
            item["reason"] = "Not in Program Files or System32 — verify you recognize this."
    return items
