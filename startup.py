"""
startup.py
Registers SkyAV with Windows Task Scheduler so it:
  1. Launches automatically at Windows login (with the GUI in tray)
  2. Runs a Quick Scan at every startup (like Defender's boot scan,
     but at user login rather than true pre-boot — Python can't run
     before Windows loads, so this is the closest equivalent)
  3. Runs a daily signature update at 3:00 AM

All done via Windows' built-in 'schtasks' command — no admin required
for per-user tasks.
"""

import os
import platform
import subprocess

IS_WINDOWS = platform.system() == "Windows"


def _get_exe_path() -> str:
    """Returns the path to the Python interpreter or compiled exe."""
    import sys
    if getattr(sys, "frozen", False):
        return sys.executable
    # Running from source — use pythonw.exe to avoid console window
    python_dir = os.path.dirname(sys.executable)
    pythonw = os.path.join(python_dir, "pythonw.exe")
    if os.path.exists(pythonw):
        return pythonw
    return sys.executable


def _get_main_path() -> str:
    import sys
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")


def register_startup(enable: bool = True) -> tuple:
    """
    Registers (or removes) the SkyAV auto-start task via Task Scheduler.
    Returns (success: bool, message: str)
    """
    if not IS_WINDOWS:
        return False, "Task Scheduler integration is Windows-only"

    task_name = "SkyAV_AutoStart"
    exe = _get_exe_path()
    main = _get_main_path()

    if not enable:
        try:
            subprocess.run(
                ["schtasks", "/delete", "/tn", task_name, "/f"],
                capture_output=True, check=False
            )
            return True, "SkyAV removed from Windows startup"
        except Exception as e:
            return False, str(e)

    if getattr(__import__("sys"), "frozen", False):
        cmd = f'"{exe}" --gui'
    else:
        cmd = f'"{exe}" "{main}" --gui'

    try:
        result = subprocess.run([
            "schtasks", "/create",
            "/tn", task_name,
            "/tr", cmd,
            "/sc", "ONLOGON",
            "/rl", "HIGHEST",
            "/f",   # overwrite if exists
        ], capture_output=True, text=True)

        if result.returncode == 0:
            return True, "SkyAV will now start automatically at Windows login"
        else:
            return False, result.stderr.strip() or result.stdout.strip()
    except Exception as e:
        return False, str(e)


def register_boot_scan(enable: bool = True) -> tuple:
    """
    Registers (or removes) a Quick Scan task that runs at every login.
    """
    if not IS_WINDOWS:
        return False, "Task Scheduler integration is Windows-only"

    task_name = "SkyAV_BootScan"
    exe = _get_exe_path()
    main = _get_main_path()

    if not enable:
        try:
            subprocess.run(
                ["schtasks", "/delete", "/tn", task_name, "/f"],
                capture_output=True, check=False
            )
            return True, "Boot-time scan removed"
        except Exception as e:
            return False, str(e)

    if getattr(__import__("sys"), "frozen", False):
        cmd = f'"{exe}" --quick --auto-quarantine'
    else:
        cmd = f'"{exe}" "{main}" --quick --auto-quarantine'

    try:
        result = subprocess.run([
            "schtasks", "/create",
            "/tn", task_name,
            "/tr", cmd,
            "/sc", "ONLOGON",
            "/delay", "0001:00",  # 1 minute delay after login
            "/rl", "HIGHEST",
            "/f",
        ], capture_output=True, text=True)

        if result.returncode == 0:
            return True, "Boot-time scan registered — Quick Scan will run 1 minute after every login"
        else:
            return False, result.stderr.strip() or result.stdout.strip()
    except Exception as e:
        return False, str(e)


def register_daily_update(enable: bool = True) -> tuple:
    """
    Registers (or removes) the daily 3 AM signature update task.
    """
    if not IS_WINDOWS:
        return False, "Task Scheduler integration is Windows-only"

    task_name = "SkyAV_DailyUpdate"
    exe = _get_exe_path()
    main = _get_main_path()

    if not enable:
        try:
            subprocess.run(
                ["schtasks", "/delete", "/tn", task_name, "/f"],
                capture_output=True, check=False
            )
            return True, "Daily signature update task removed"
        except Exception as e:
            return False, str(e)

    if getattr(__import__("sys"), "frozen", False):
        cmd = f'"{exe}" --update'
    else:
        cmd = f'"{exe}" "{main}" --update'

    try:
        result = subprocess.run([
            "schtasks", "/create",
            "/tn", task_name,
            "/tr", cmd,
            "/sc", "DAILY",
            "/st", "03:00",
            "/rl", "HIGHEST",
            "/f",
        ], capture_output=True, text=True)

        if result.returncode == 0:
            return True, "Daily signature update scheduled at 3:00 AM"
        else:
            return False, result.stderr.strip() or result.stdout.strip()
    except Exception as e:
        return False, str(e)


def get_status() -> dict:
    """Returns which SkyAV scheduled tasks are currently registered."""
    if not IS_WINDOWS:
        return {"startup": False, "boot_scan": False, "daily_update": False}

    tasks = {}
    for key, name in [("startup", "SkyAV_AutoStart"),
                       ("boot_scan", "SkyAV_BootScan"),
                       ("daily_update", "SkyAV_DailyUpdate")]:
        result = subprocess.run(
            ["schtasks", "/query", "/tn", name],
            capture_output=True, text=True
        )
        tasks[key] = result.returncode == 0

    return tasks
