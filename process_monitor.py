"""
process_monitor.py
Checks currently RUNNING processes (not just files on disk) for RAT-like
behavior — this catches malware that's already executing, disguises itself
after launch, or was dropped by something we never scanned.
"""

import os
import psutil
import pe_analyzer
import whitelist

# Common legitimate Windows process names — used to detect typosquatting
# (e.g. "svch0st.exe" pretending to be "svchost.exe")
SYSTEM_PROCESS_NAMES = {
    "svchost.exe", "explorer.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe",
    "dwm.exe", "conhost.exe", "rundll32.exe",
}

SUSPICIOUS_PATH_FRAGMENTS = [
    "\\appdata\\local\\temp", "\\appdata\\roaming", "\\windows\\temp",
    "\\downloads\\", "\\programdata\\",
]

# Trusted locations — processes running from here are almost certainly
# legitimate system software or properly installed applications.
# Even if their PE imports look suspicious, we skip the heuristic
# analysis (signature/hash matching still applies).
TRUSTED_PATH_FRAGMENTS = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\systemapps\\",
    "\\windows\\servicing\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\driverstore\\filerepository\\",  # hardware drivers like Realtek
    "\\microsoft\\windows defender\\",
    "\\windows defender\\",
]


def _is_trusted_location(path: str) -> bool:
    p = path.lower().replace("/", "\\")
    return any(frag in p for frag in TRUSTED_PATH_FRAGMENTS)

# Ports commonly associated with known RAT families (not exhaustive —
# RATs can use any port, this is just one extra signal among several)
KNOWN_RAT_DEFAULT_PORTS = {1177, 5552, 1604, 4782, 6606, 7707, 8808, 3460, 5150}


def _looks_like_typosquat(name: str) -> bool:
    """Detects near-matches to real system process names (svch0st vs svchost)."""
    name_lower = name.lower()
    if name_lower in SYSTEM_PROCESS_NAMES:
        return False  # it's the real thing
    for real_name in SYSTEM_PROCESS_NAMES:
        base = real_name.replace(".exe", "")
        if base in name_lower and name_lower != real_name:
            # e.g. "svchost1.exe", "svch0st.exe", "svchost .exe"
            return True
    return False


def scan_running_processes() -> list:
    """
    Returns a list of flagged processes with reasons. Each item:
    {pid, name, path, reasons, score}
    """
    flagged = []

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
            pid = info["pid"]
            name = info["name"] or ""
            path = info["exe"] or ""

            # Skip processes the user has already confirmed safe
            if path and whitelist.is_whitelisted(path):
                continue

            # Skip processes running from trusted system locations
            # (System32, Program Files, hardware driver store, Defender etc.)
            # Their PE imports naturally contain sensitive APIs — that's normal.
            if path and _is_trusted_location(path):
                continue

            reasons = []
            score = 0

            # 1. Typosquatting known system process names
            if _looks_like_typosquat(name):
                reasons.append(f"Name mimics a system process ('{name}' looks like a real Windows process)")
                score += 3

            # 2. Running from a suspicious location
            if path:
                path_lower = path.lower()
                for frag in SUSPICIOUS_PATH_FRAGMENTS:
                    if frag in path_lower:
                        reasons.append(f"Running from suspicious location: {frag.strip(chr(92))}")
                        score += 2
                        break

            # 3. Suspicious outbound network connections
            try:
                conns = proc.net_connections(kind="inet") if hasattr(proc, "net_connections") else proc.connections(kind="inet")
                remote_ports = {c.raddr.port for c in conns if c.raddr}
                rat_ports_hit = remote_ports & KNOWN_RAT_DEFAULT_PORTS
                if rat_ports_hit:
                    reasons.append(f"Connected to port(s) commonly used by known RATs: {rat_ports_hit}")
                    score += 3
                elif len(remote_ports) > 3 and path and any(f in path.lower() for f in SUSPICIOUS_PATH_FRAGMENTS):
                    reasons.append(f"Multiple outbound connections ({len(remote_ports)}) from a suspicious-path process")
                    score += 2
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # 4. Static PE analysis on the actual binary (keylogging+network+injection combo)
            if path and os.path.isfile(path):
                pe_result = pe_analyzer.analyze_pe(path)
                if pe_result["rat_score"] >= 4:
                    reasons.append(f"Binary imports suggest RAT-like capabilities: "
                                    f"{', '.join(pe_result['capabilities'].keys())}")
                    score += pe_result["rat_score"]

            if score >= 5:
                flagged.append({
                    "pid": pid,
                    "name": name,
                    "path": path or "(unknown)",
                    "reasons": reasons,
                    "score": score,
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return sorted(flagged, key=lambda x: -x["score"])


def kill_process(pid: int) -> bool:
    """Terminates a flagged process by PID. Returns True on success."""
    try:
        p = psutil.Process(pid)
        p.terminate()
        p.wait(timeout=3)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
        try:
            psutil.Process(pid).kill()
            return True
        except Exception:
            return False
