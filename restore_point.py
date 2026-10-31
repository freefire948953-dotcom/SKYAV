"""
restore_point.py
Creates a Windows System Restore Point before risky actions (like quarantine
or auto-delete during a scan), so the user has an easy rollback option if
something legitimate gets removed by mistake.
"""

import subprocess
import platform

IS_WINDOWS = platform.system() == "Windows"


def create_restore_point(description: str = "SkyAV protective checkpoint") -> dict:
    """
    Creates a System Restore Point via PowerShell's Checkpoint-Computer.
    Returns {"success": bool, "message": str}.

    Notes:
      - Requires System Restore to be enabled on the system drive.
      - Windows limits automatic restore points to one per 24 hours by
        default for the same RestorePointType; this may cause a "skipped"
        result if one was already made recently, which is normal.
      - Must be run with administrator privileges.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "System Restore is a Windows-only feature."}

    ps_command = (
        f"Checkpoint-Computer -Description '{description}' "
        f"-RestorePointType 'MODIFY_SETTINGS'"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True, text=True, timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            return {"success": True, "message": "Restore point created successfully."}
        else:
            error = result.stderr.strip() or "Unknown error (may need Administrator rights, or one was already created in the last 24 hours)."
            return {"success": False, "message": error}
    except FileNotFoundError:
        return {"success": False, "message": "PowerShell not found."}
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "Timed out creating restore point."}
    except Exception as e:
        return {"success": False, "message": f"{type(e).__name__}: {e}"}
