"""
macro_scanner.py
Scans Office documents (.doc, .docx, .xls, .xlsm, .ppt, .pptm, etc.) for
malicious VBA macros — one of the most common real-world infection vectors
(an email attachment with "Enable Macros" that silently installs malware).

Requires: pip install oletools
"""

import os
from oletools.olevba import VBA_Parser

MACRO_CAPABLE_EXTENSIONS = {
    ".doc", ".docm", ".docx", ".dot", ".dotm",
    ".xls", ".xlsm", ".xlsb", ".xlt", ".xltm",
    ".ppt", ".pptm", ".pps", ".ppsm",
}

# Suspicious VBA keywords oletools' own analyzer flags as "AutoExec",
# "Suspicious", or "IOC" — we surface the ones that matter most.
HIGH_RISK_KEYWORDS = {
    "Shell", "WScript.Shell", "CreateObject", "Environ", "CreateProcessA",
    "URLDownloadToFileA", "Run", "RegWrite", "ShellExecute",
}


def scan_document(filepath: str) -> dict:
    """
    Returns {has_macros, is_suspicious, indicators, reasons}
    """
    result = {"has_macros": False, "is_suspicious": False, "indicators": [], "reasons": []}

    ext = os.path.splitext(filepath)[1].lower()
    if ext not in MACRO_CAPABLE_EXTENSIONS:
        return result

    try:
        vba_parser = VBA_Parser(filepath)
    except Exception:
        return result

    # oletools falls back to treating anything it can't parse as OLE/OOXML
    # as generic "Text" and assumes it *might* be raw VBA source — which
    # causes false positives on any corrupt/renamed file. Only trust the
    # macro detection for files it actually recognized as real documents.
    if vba_parser.type not in ("OLE", "OpenXML", "PPT", "Word2003_XML", "MHTML"):
        vba_parser.close()
        return result

    if not vba_parser.detect_vba_macros():
        vba_parser.close()
        return result

    result["has_macros"] = True
    score = 0

    try:
        for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
            if not vba_code:
                continue
            for keyword in HIGH_RISK_KEYWORDS:
                if keyword in vba_code:
                    result["indicators"].append(keyword)
                    score += 1

        # Use oletools' built-in analyzer for a second opinion (AutoExec triggers etc.)
        try:
            analysis = vba_parser.analyze_macros()
            for kw_type, keyword, description in analysis:
                if kw_type in ("AutoExec", "Suspicious", "IOC"):
                    result["indicators"].append(keyword)
                    score += 2 if kw_type == "AutoExec" else 1
        except Exception:
            pass

    except Exception:
        pass
    finally:
        vba_parser.close()

    result["indicators"] = list(set(result["indicators"]))

    if score >= 3:
        result["is_suspicious"] = True
        result["reasons"].append(
            f"Document contains VBA macro with suspicious behavior: {', '.join(result['indicators'][:6])}"
        )
    elif result["has_macros"]:
        result["reasons"].append("Document contains macros (not necessarily malicious — verify the source)")

    return result
