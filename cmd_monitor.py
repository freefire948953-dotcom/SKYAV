"""
cmd_monitor.py
Real-time Command Line Monitor for SkyAV.

Watches every new process launched on the system and:
  1. Captures the full command line (including encoded/obfuscated ones)
  2. Decodes base64-encoded PowerShell payloads automatically
  3. Flags suspicious patterns (malware, privilege escalation, data theft)
  4. Fires an alert + callback so the GUI can display it instantly

Uses WMI (Windows Management Instrumentation) — built into Windows,
no extra install needed beyond the 'wmi' Python package.
"""

import re
import base64
import threading
import platform
import subprocess

IS_WINDOWS = platform.system() == "Windows"

# ── Suspicious pattern definitions ────────────────────────────────────────────

SUSPICIOUS_PATTERNS = [
    # Encoded / obfuscated PowerShell
    (r"powershell.*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", "high",
     "Encoded PowerShell command (possible malware hiding its payload)"),

    # Download cradles
    (r"(downloadstring|downloadfile|webclient|invoke-webrequest|curl|wget).*http",
     "high", "Network download from a script (common malware dropper technique)"),

    # Invoke-Expression / IEX
    (r"(iex|invoke-expression)\s*[\(\$]", "high",
     "IEX / Invoke-Expression — executes arbitrary code at runtime"),

    # Hidden window tricks
    (r"powershell.*-windowstyle\s+hidden", "high",
     "PowerShell launched with hidden window — often used to conceal malicious activity"),

    # Bypass execution policy
    (r"powershell.*-executionpolicy\s+(bypass|unrestricted)", "medium",
     "Execution policy bypass — scripts can run without restriction"),

    # Add user / privilege escalation
    (r"net\s+user\s+\S+\s+\S+\s*/add", "high",
     "New user account being created — possible privilege escalation"),
    (r"net\s+localgroup\s+(administrators|admin)\s+.*\/add", "high",
     "User added to Administrators group"),

    # Registry persistence
    (r"reg\s+(add|delete).*\\(run|runonce|services)", "high",
     "Registry persistence key being modified"),

    # Scheduled task creation
    (r"schtasks\s+/create", "medium",
     "Scheduled task being created — common malware persistence technique"),

    # Shadow copy deletion (ransomware)
    (r"(vssadmin|wmic)\s+.*shadow.*delete", "high",
     "Shadow copy deletion — classic ransomware anti-recovery step"),
    (r"bcdedit.*recoveryenabled.*no", "high",
     "Windows recovery disabled — ransomware indicator"),

    # AMSI bypass
    (r"amsiutils|amsi\.dll.*patch|amsicontext", "high",
     "AMSI (Antimalware Scan Interface) bypass attempt"),

    # Credential dumping
    (r"(mimikatz|sekurlsa|lsadump|procdump.*lsass)", "high",
     "Credential dumping tool detected"),
    (r"tasklist.*lsass|process.*lsass", "medium",
     "Accessing LSASS process — possible credential theft"),

    # Certutil abuse (download/decode)
    (r"certutil.*(urlcache|decode|-f\s+http)", "high",
     "Certutil used to download or decode files — common LOLBIN abuse"),

    # WScript / CScript (script execution)
    (r"(wscript|cscript)\s+.*\.(vbs|js|wsf|hta)", "medium",
     "Script interpreter running a script file"),

    # Suspicious cmd chains
    (r"cmd.*\/c.*&&.*&&", "medium",
     "Chained CMD commands — may be hiding malicious steps"),

    # BITS transfer (download)
    (r"bitsadmin.*/transfer", "medium",
     "BITS transfer job — can be used to stealthily download files"),

    # Disable Windows Defender
    (r"set-mppreference.*disablerealtimemonitoring.*\$true", "high",
     "Windows Defender real-time protection being disabled"),
    (r"sc\s+(stop|delete)\s+(windefend|mpsvc|wscsvc)", "high",
     "Security service being stopped or deleted"),
]

# Compile all patterns once at import time for speed
_COMPILED = [
    (re.compile(pat, re.IGNORECASE), sev, desc)
    for pat, sev, desc in SUSPICIOUS_PATTERNS
]


# ── Decoder ───────────────────────────────────────────────────────────────────

def decode_command(cmdline: str) -> dict:
    """
    Tries to decode encoded/obfuscated content inside a command line.
    Returns:
      {
        "original":  <original cmdline>,
        "decoded":   <decoded payload or None>,
        "method":    <"base64-utf16" | "base64-utf8" | None>,
      }
    """
    result = {"original": cmdline, "decoded": None, "method": None}

    # Look for -enc / -e / -EncodedCommand followed by a base64 blob
    enc_match = re.search(
        r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})",
        cmdline, re.IGNORECASE
    )
    if enc_match:
        b64 = enc_match.group(1)
        # PowerShell uses UTF-16LE encoding
        for method, encoding in (("base64-utf16", "utf-16-le"), ("base64-utf8", "utf-8")):
            try:
                padded = b64 + "=" * (-len(b64) % 4)
                decoded = base64.b64decode(padded).decode(encoding).strip()
                if decoded and any(c.isalpha() for c in decoded):
                    result["decoded"] = decoded
                    result["method"]  = method
                    break
            except Exception:
                continue

    return result


# ── Scanner ───────────────────────────────────────────────────────────────────

def scan_command(cmdline: str) -> dict:
    """
    Scans a command line string for suspicious patterns.
    Returns:
      {
        "cmdline":   <original>,
        "hits":      [{"severity": .., "description": ..}, ...],
        "max_severity": "high"|"medium"|"clean",
        "decode":    {original, decoded, method}  — only when encoded
      }
    """
    hits = []
    for pattern, severity, description in _COMPILED:
        if pattern.search(cmdline):
            hits.append({"severity": severity, "description": description})

    max_sev = "clean"
    if any(h["severity"] == "high"   for h in hits): max_sev = "high"
    elif any(h["severity"] == "medium" for h in hits): max_sev = "medium"

    return {
        "cmdline":       cmdline,
        "hits":          hits,
        "max_severity":  max_sev,
        "decode":        decode_command(cmdline),
    }


# ── WMI Process Monitor ───────────────────────────────────────────────────────

class CmdMonitor:
    """
    Watches for new processes via WMI and scans their command lines.
    Fires on_alert(result_dict) for every suspicious command.
    Fires on_event(proc_dict) for EVERY new process (even clean ones),
    so the GUI can show a live feed if desired.
    """

    def __init__(self, on_alert=None, on_event=None, only_suspicious=True):
        """
        on_alert(result): called when a suspicious command is detected.
        on_event(result): called for every process (only when only_suspicious=False).
        only_suspicious:  if True, on_event is only called for hits.
        """
        self.on_alert        = on_alert
        self.on_event        = on_event
        self.only_suspicious = only_suspicious
        self._stop_event     = threading.Event()
        self._thread         = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()

    def _run(self):
        if not IS_WINDOWS:
            return

        try:
            import pythoncom
            import wmi
            pythoncom.CoInitialize()
        except ImportError:
            if self.on_alert:
                self.on_alert({
                    "cmdline": "",
                    "hits": [{"severity": "medium",
                              "description": "wmi package not installed — run: pip install wmi pywin32"}],
                    "max_severity": "medium",
                    "decode": {"original": "", "decoded": None, "method": None},
                    "process_name": "SYSTEM",
                    "pid": 0,
                })
            return

        try:
            c = wmi.WMI()
            watcher = c.Win32_Process.watch_for("creation")

            while not self._stop_event.is_set():
                try:
                    proc = watcher(timeout_ms=1000)
                    if proc is None:
                        continue
                    cmdline = proc.CommandLine or ""
                    name    = proc.Name        or "unknown"
                    pid     = proc.ProcessId   or 0

                    # Only scan processes that could carry commands
                    if not any(exe in name.lower() for exe in
                               ("powershell", "cmd", "wscript", "cscript",
                                "mshta", "rundll32", "regsvr32", "certutil",
                                "bitsadmin", "wmic", "msiexec", "python",
                                "node", "ruby", "perl")):
                        # Still check the full cmdline for patterns
                        if not cmdline:
                            continue

                    result = scan_command(cmdline)
                    result["process_name"] = name
                    result["pid"]          = pid

                    if result["max_severity"] != "clean":
                        if self.on_alert:
                            self.on_alert(result)
                    if not self.only_suspicious and self.on_event:
                        self.on_event(result)

                except Exception:
                    # watcher timeout or transient WMI hiccup — just loop
                    continue

        except Exception as e:
            if self.on_alert:
                self.on_alert({
                    "cmdline": "",
                    "hits": [{"severity": "medium",
                              "description": f"CMD Monitor error: {e}"}],
                    "max_severity": "medium",
                    "decode": {"original": "", "decoded": None, "method": None},
                    "process_name": "SYSTEM",
                    "pid": 0,
                })
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass


# ── Convenience: scan a single command right now ──────────────────────────────

def scan_one(cmdline: str) -> dict:
    """Scan a single command line string and return the result dict."""
    return scan_command(cmdline)
