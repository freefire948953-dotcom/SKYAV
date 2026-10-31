"""
pe_analyzer.py
Static analysis of Windows executables (.exe/.dll) — looks at which Windows
API functions a file IMPORTS, without ever running it. This is how real AVs
spot RATs/spyware even when the file has never been seen before: legitimate
apps rarely combine keylogging + screen capture + covert networking + hidden
windows in one binary, but that combo is a RAT's whole job description.

Requires: pip install pefile
"""

import pefile

# Categories of "capability" APIs. A file importing ONE of these is usually
# fine (tons of legit software uses SetWindowsHookEx, for example). It's the
# COMBINATION across categories that's the real signal.
CAPABILITY_APIS = {
    "keylogging": {
        "GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
        "GetKeyboardState", "MapVirtualKeyA", "MapVirtualKeyW",
    },
    "screen_capture": {
        "BitBlt", "GetDC", "GetWindowDC", "CreateCompatibleBitmap", "CreateCompatibleDC",
        "GetDIBits",
    },
    "webcam_mic": {
        "capCreateCaptureWindowA", "capCreateCaptureWindowW", "waveInOpen", "waveInStart",
    },
    "covert_network": {
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "HttpSendRequestA", "HttpSendRequestW", "WSAStartup", "connect", "send", "recv",
        "URLDownloadToFileA", "URLDownloadToFileW",
    },
    "process_injection": {
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "NtUnmapViewOfSection",
        "SetThreadContext", "QueueUserAPC", "OpenProcess",
    },
    "persistence": {
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    },
    "hidden_window": {
        "ShowWindow",  # combined with others this is more meaningful
    },
    "anti_analysis": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA",
        "GetTickCount", "QueryPerformanceCounter",  # timing-based sandbox evasion
    },
    "credential_theft": {
        "CryptUnprotectData", "PFXImportCertStore", "CertOpenSystemStoreA", "CertOpenSystemStoreW",
    },
}


def analyze_pe(filepath: str) -> dict:
    """
    Returns {is_pe, capabilities: {category: [apis found]}, rat_score, verdict, reasons}
    rat_score >= 3 (i.e. 3+ distinct suspicious capability categories combined)
    is treated as a strong RAT/spyware indicator.
    """
    result = {"is_pe": False, "capabilities": {}, "rat_score": 0, "reasons": []}

    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except pefile.PEFormatError:
        return result  # not a PE file (not .exe/.dll) — nothing to analyze
    except Exception:
        return result

    result["is_pe"] = True

    imported_funcs = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    try:
                        imported_funcs.add(imp.name.decode(errors="ignore"))
                    except Exception:
                        pass

    for category, apis in CAPABILITY_APIS.items():
        found = imported_funcs & apis
        if found:
            result["capabilities"][category] = sorted(found)

    # Score: each distinct capability category present adds 1.
    # process_injection and credential_theft are weighted higher — they're
    # rarely legitimate outside of security tools themselves.
    score = 0
    for category in result["capabilities"]:
        if category in ("process_injection", "credential_theft"):
            score += 2
        else:
            score += 1
    result["rat_score"] = score

    if score >= 4:
        result["reasons"].append(
            f"Combines {len(result['capabilities'])} suspicious capability categories: "
            f"{', '.join(result['capabilities'].keys())} — classic RAT/spyware profile"
        )
    elif score >= 2:
        result["reasons"].append(
            f"Some suspicious capabilities present: {', '.join(result['capabilities'].keys())} "
            f"(may still be legitimate — e.g. remote-support or admin tools)"
        )

    # Also flag PE-level red flags: no imports at all (packed/encrypted payload)
    if not imported_funcs and hasattr(pe, "DIRECTORY_ENTRY_IMPORT") is False:
        result["reasons"].append("No readable imports — likely packed/obfuscated")
        result["rat_score"] += 1

    try:
        pe.close()
    except Exception:
        pass

    return result
