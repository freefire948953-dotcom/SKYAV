"""
yara_scanner.py
YARA is the pattern-matching engine real antivirus companies use — one
well-written rule can catch thousands of variants of the same malware
family (unlike our simple hash signatures, which only match one exact file).

Rules live in data/rules.yar — you can add more over time, or download
public rule sets (e.g. from https://github.com/Yara-Rules/rules) and drop
them into that file.

Requires: pip install yara-python
"""

import os
import yara

import paths

DATA_DIR = paths.DATA_DIR
RULES_FILE = os.path.join(DATA_DIR, "rules.yar")

# A starter set of rules covering common, well-documented malware behaviors.
# These are intentionally generic pattern-based rules (safe to ship) — not
# copies of any specific malware's code.
DEFAULT_RULES = r"""
rule Suspicious_PowerShell_Download : downloader
{
    meta:
        description = "PowerShell command that downloads and executes remote content"
        severity = "high"
    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "IEX" nocase
        $dl4 = "Invoke-Expression" nocase
        $net = "Net.WebClient" nocase
    condition:
        $net and 1 of ($dl1, $dl2, $dl3, $dl4)
}

rule Suspicious_Base64_PowerShell : obfuscation
{
    meta:
        description = "Base64-encoded PowerShell command (-enc/-e flag) — common obfuscation for malicious scripts"
        severity = "high"
    strings:
        $enc1 = "-enc " nocase fullword
        $enc2 = "-EncodedCommand" nocase fullword
        $enc3 = " -e " nocase fullword
        $ps = "powershell" nocase
    condition:
        $ps and 1 of ($enc1, $enc2, $enc3)
}

rule Generic_Process_Injection : injection
{
    meta:
        description = "Binary combines classic process-injection API calls"
        severity = "high"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
    condition:
        2 of ($a, $b, $c, $d)
}

rule Generic_Keylogger_Indicators : spyware
{
    meta:
        description = "Combines keyboard hooking APIs with file-writing — common keylogger pattern"
        severity = "medium"
    strings:
        $hook1 = "SetWindowsHookExA"
        $hook2 = "SetWindowsHookExW"
        $key1 = "GetAsyncKeyState"
        $key2 = "GetKeyboardState"
        $log = "keylog" nocase
    condition:
        (1 of ($hook1, $hook2) and 1 of ($key1, $key2)) or $log
}

rule Suspicious_Persistence_RunKey : persistence
{
    meta:
        description = "Code that writes to the Windows Run registry key for auto-start persistence"
        severity = "medium"
    strings:
        $run1 = "CurrentVersion\\Run" nocase
        $run2 = "RegSetValueEx"
    condition:
        all of them
}

rule Suspicious_Reverse_Shell_Strings : rat
{
    meta:
        description = "Strings commonly found in reverse-shell / RAT command handlers"
        severity = "high"
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "/bin/sh" nocase
        $s3 = "WScript.Shell" nocase
        $net1 = "connect"
        $net2 = "recv"
        $net3 = "send"
    condition:
        1 of ($s1, $s2, $s3) and 1 of ($net1, $net2, $net3)
}

rule Suspicious_AntiVM_Checks : evasion
{
    meta:
        description = "Checks for virtual machine / sandbox artifacts — common malware evasion technique"
        severity = "medium"
    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "SbieDll" nocase
        $vm4 = "sandboxie" nocase
        $dbg = "IsDebuggerPresent"
    condition:
        2 of them
}
"""


def _ensure_rules_file():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, "w") as f:
            f.write(DEFAULT_RULES)


_compiled_rules = None


def _get_compiled_rules():
    global _compiled_rules
    if _compiled_rules is None:
        _ensure_rules_file()
        try:
            _compiled_rules = yara.compile(filepath=RULES_FILE)
        except yara.Error as e:
            print(f"⚠ YARA rule compile error: {e}")
            _compiled_rules = False
    return _compiled_rules


def scan_file(filepath: str) -> list:
    """
    Returns a list of matched rule names + metadata, e.g.:
    [{"rule": "Suspicious_PowerShell_Download", "severity": "high", "description": "..."}]
    Empty list = no YARA matches.
    """
    rules = _get_compiled_rules()
    if not rules:
        return []

    try:
        matches = rules.match(filepath, timeout=10)
    except (yara.Error, OSError):
        return []

    results = []
    for m in matches:
        results.append({
            "rule": m.rule,
            "severity": m.meta.get("severity", "unknown"),
            "description": m.meta.get("description", ""),
        })
    return results


def reload_rules():
    """Call this after editing data/rules.yar to pick up changes without restarting."""
    global _compiled_rules
    _compiled_rules = None
    return _get_compiled_rules() is not False
