"""
heuristics.py
Behavior/pattern-based detection for malware that has NO known signature yet
(zero-days, modified viruses, etc.) This is what makes an AV "smart" instead
of just a hash-matcher.
"""

import os
import math
import re

import pe_analyzer
import yara_scanner
import macro_scanner

SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".dll", ".jar"}

# Double extension tricks like "invoice.pdf.exe" — only flag when the FIRST
# extension is a common document/media type (genuine disguise), not generic
# words like "min" (jquery.min.js) or version numbers (pip3.12.exe)
DISGUISE_PRONE_EXTS = r"pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif|zip|rar|mp3|mp4|csv"
DOUBLE_EXT_PATTERN = re.compile(
    rf"\.({DISGUISE_PRONE_EXTS})\.(exe|scr|bat|cmd|vbs|js|ps1)$", re.IGNORECASE
)

# Keyword/pattern check only makes sense for script-type files — compiled
# binaries (.exe/.dll/.pyd) legitimately contain Windows API name strings
# (e.g. pywin32), so checking them there causes constant false positives.
SCRIPT_EXTENSIONS = {".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".py", ".psm1"}

# Locations malware commonly hides in / auto-starts from
SUSPICIOUS_LOCATIONS = [
    "appdata\\roaming",
    "appdata\\local\\temp",
    "windows\\temp",
    "startup",
    "programdata",
]

# Strings often found in malicious scripts/macros
SUSPICIOUS_KEYWORDS = [
    b"powershell -enc",
    b"powershell.exe -e ",
    b"cmd.exe /c",
    b"CreateRemoteThread",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"RegSetValueEx",
    b"schtasks /create",
    b"reg add",
    b"Invoke-Expression",
    b"DownloadString",
    b"WScript.Shell",
]


def shannon_entropy(data: bytes) -> float:
    """High entropy (~7.5-8.0) usually means packed/encrypted/obfuscated code."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def scan_file_heuristically(filepath: str, read_bytes: int = 65536) -> dict:
    """
    Returns a dict: {suspicious: bool, score: int, reasons: [str]}
    Score >= 3 is treated as suspicious in the scanner.
    """
    reasons = []
    score = 0
    lower_path = filepath.lower()
    ext = os.path.splitext(filepath)[1].lower()

    # 1. Double extension trick
    if DOUBLE_EXT_PATTERN.search(filepath):
        reasons.append("Double file extension (disguise trick)")
        score += 3

    # 2. Executable sitting in a suspicious auto-run location
    if ext in SUSPICIOUS_EXTENSIONS:
        for loc in SUSPICIOUS_LOCATIONS:
            if loc in lower_path.replace("/", "\\"):
                reasons.append(f"Executable file located in suspicious path ({loc})")
                score += 2
                break

    # 3. Read file content (bounded, so large files don't slow things down)
    try:
        with open(filepath, "rb") as f:
            data = f.read(read_bytes)
    except (PermissionError, FileNotFoundError, OSError):
        return {"suspicious": False, "score": 0, "reasons": ["Could not read file"]}

    # 4. High entropy = likely packed/encrypted payload
    if len(data) > 256:
        ent = shannon_entropy(data)
        if ent > 7.5 and ext in SUSPICIOUS_EXTENSIONS:
            reasons.append(f"High entropy ({ent:.2f}) — possibly packed/encrypted code")
            score += 2

    # 5. Suspicious keyword/string matches — script files only (see comment above)
    if ext in SCRIPT_EXTENSIONS:
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in data:
                reasons.append(f"Suspicious code pattern found: {kw.decode(errors='ignore')}")
                score += 2

    # 6. Static PE import analysis (RAT-capability combos) — exe/dll only
    if ext in (".exe", ".dll"):
        pe_result = pe_analyzer.analyze_pe(filepath)
        if pe_result["rat_score"] >= 4:
            reasons.extend(pe_result["reasons"])
            score += pe_result["rat_score"]

    # 7. YARA rule matching — industry-standard pattern detection.
    # IMPORTANT: only run this on script/source files, never compiled
    # binaries (.exe/.dll/.pyd/.sys) — a compiled binary's import table
    # naturally contains literal strings like "VirtualAllocEx" for ANY
    # legitimate use of that Windows API, so string-matching binaries
    # causes constant false positives. pe_analyzer.py already handles
    # binaries correctly via proper import-table parsing.
    if ext in SCRIPT_EXTENSIONS:
        yara_matches = yara_scanner.scan_file(filepath)
        for match in yara_matches:
            weight = 3 if match["severity"] == "high" else 2
            reasons.append(f"YARA rule matched: {match['rule']} ({match['description']})")
            score += weight

    # 8. Office document macro analysis (.docx, .xlsm, .pptm etc.)
    if ext in macro_scanner.MACRO_CAPABLE_EXTENSIONS:
        macro_result = macro_scanner.scan_document(filepath)
        if macro_result["is_suspicious"]:
            reasons.extend(macro_result["reasons"])
            score += 3

    return {
        "suspicious": score >= 3,
        "score": score,
        "reasons": reasons,
    }
