"""
cmd_analyzer.py  —  AI-powered Command Analyzer for SkyAV
Features:
  • Full AI analysis with MITRE ATT&CK mapping
  • Risk Score 0-100
  • Similar malware examples
  • Fix / Remediation steps
  • VirusTotal IOC check (URLs, hashes, IPs from command)
  • Command history (saved to data/cmd_history.json)
  • Export report to .txt
  • Batch analyze support
"""

import os, re, json, hashlib, datetime, requests

import paths

API_KEY     = os.environ.get("GEMINI_API_KEY", "")
API_URL     = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-3.6-flash:generateContent?key=" + API_KEY
)
HISTORY_FILE = os.path.join(paths.DATA_DIR, "cmd_history.json")

# ── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an elite Windows forensics and threat intelligence analyst embedded in a custom antivirus called SkyAV.

The user gives you a command line (possibly encoded/obfuscated). Produce a structured security report using EXACTLY these section headers on their own lines:

COMMAND BREAKDOWN
[Break down every token: executable, each flag, each argument. Explain what each part means.]

WHAT IT DOES
[Plain-English explanation of the full effect of running this command on a Windows system.]

WHERE IT AFFECTS THE PC
[List specific registry keys, file paths, services, network connections, processes, or memory regions touched.]

MITRE ATT&CK MAPPING
[Map to relevant MITRE ATT&CK technique IDs and names. Format: T1234 – Technique Name: one-line reason. List all that apply.]

RISK SCORE
[A single integer 0-100 on its own line, then one sentence justification. 0=harmless, 100=catastrophic.]

SIMILAR MALWARE / REAL-WORLD ABUSE
[Name 2-3 real malware families or threat actors known to use this technique. Explain briefly how.]

PROS / LEGITIMATE USES
[When would a legitimate sysadmin or developer run this?]

CONS / RISKS
[What damage could an attacker cause with this exact command?]

REMEDIATION
[Step-by-step actions to undo or contain the damage if this was run maliciously. Be specific — registry keys to delete, services to stop, files to remove.]

SAFETY VERDICT
[Exactly one of: ✅ SAFE | ⚠ USE WITH CAUTION | 🚨 DANGEROUS]
[One sentence verdict.]

Be precise and technical. Use bullet points inside sections. Keep each section concise (3-6 bullets max). Total under 550 words."""


# ── IOC EXTRACTOR ─────────────────────────────────────────────────────────────
_URL_RE  = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MD5_RE  = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

def extract_iocs(cmdline: str) -> dict:
    return {
        "urls":    list(set(_URL_RE.findall(cmdline))),
        "ips":     list(set(_IP_RE.findall(cmdline))),
        "hashes":  list(set(
            _SHA256_RE.findall(cmdline) +
            _SHA1_RE.findall(cmdline) +
            _MD5_RE.findall(cmdline)
        )),
    }


# ── VIRUSTOTAL IOC CHECK ───────────────────────────────────────────────────────
def check_vt_iocs(iocs: dict, vt_api_key: str = None) -> list:
    """
    Checks URLs, IPs, and hashes against VirusTotal.
    Returns a list of result dicts.
    Falls back gracefully if no VT key or network error.
    """
    key = vt_api_key or os.environ.get("VT_API_KEY", "")
    if not key:
        return [{"ioc": "(none)", "type": "info",
                 "result": "VirusTotal key not set — skipped. Set VT Key in SkyAV Tools."}]

    results = []
    headers = {"x-apikey": key}

    def _vt_get(url, ioc, ioc_type):
        try:
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                mal   = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                verdict = "🚨 MALICIOUS" if mal > 0 else "✅ CLEAN"
                results.append({
                    "ioc": ioc, "type": ioc_type,
                    "result": f"{verdict} — {mal}/{total} engines flagged"
                })
            elif r.status_code == 404:
                results.append({"ioc": ioc, "type": ioc_type, "result": "Not found in VT database"})
            else:
                results.append({"ioc": ioc, "type": ioc_type, "result": f"VT error {r.status_code}"})
        except Exception as e:
            results.append({"ioc": ioc, "type": ioc_type, "result": f"VT check failed: {e}"})

    for url in iocs.get("urls", [])[:3]:
        encoded = requests.utils.quote(url, safe="")
        _vt_get(f"https://www.virustotal.com/api/v3/urls/{encoded}", url, "URL")

    for ip in iocs.get("ips", [])[:3]:
        _vt_get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", ip, "IP")

    for h in iocs.get("hashes", [])[:3]:
        _vt_get(f"https://www.virustotal.com/api/v3/files/{h}", h, "Hash")

    return results if results else [{"ioc": "(none found)", "type": "info", "result": "No URLs/IPs/hashes extracted from this command"}]


# ── DECODE ────────────────────────────────────────────────────────────────────
def decode_command(cmdline: str) -> dict:
    result = {"original": cmdline, "decoded": None, "method": None}
    enc_match = re.search(r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})", cmdline, re.IGNORECASE)
    if enc_match:
        b64 = enc_match.group(1)
        for method, enc in (("base64-utf16", "utf-16-le"), ("base64-utf8", "utf-8")):
            try:
                padded  = b64 + "=" * (-len(b64) % 4)
                decoded = __import__("base64").b64decode(padded).decode(enc).strip()
                if decoded and any(c.isalpha() for c in decoded):
                    result["decoded"] = decoded
                    result["method"]  = method
                    break
            except Exception:
                continue
    return result


# ── RISK SCORE EXTRACTOR ──────────────────────────────────────────────────────
def extract_risk_score(analysis: str) -> int:
    """Pull the integer from the RISK SCORE section."""
    in_section = False
    for line in analysis.splitlines():
        if "RISK SCORE" in line:
            in_section = True
            continue
        if in_section:
            m = re.search(r"\b(\d{1,3})\b", line)
            if m:
                return min(int(m.group(1)), 100)
            if line.strip() and not line.strip().startswith("#"):
                break
    return -1


# ── MAIN ANALYZE ─────────────────────────────────────────────────────────────
def analyze(cmdline: str, decoded: str = None,
            vt_api_key: str = None, timeout: int = 40) -> dict:
    """
    Full analysis. Returns:
    {
      "cmdline": str,
      "decoded": str | None,
      "analysis": str,          # full AI text
      "risk_score": int,        # 0-100, -1 if not found
      "iocs": dict,
      "vt_results": list,
      "verdict": str,           # ✅ / ⚠ / 🚨 line
      "timestamp": str,
    }
    """
    result = {
        "cmdline":    cmdline,
        "decoded":    decoded,
        "analysis":   "",
        "risk_score": -1,
        "iocs":       {},
        "vt_results": [],
        "verdict":    "",
        "timestamp":  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    if not API_KEY:
        result["analysis"] = "[CMD Analyzer unavailable — GEMINI_API_KEY not set]"
        return result

    prompt = f"Analyze this Windows command:\n\n{cmdline}"
    if decoded and decoded != cmdline:
        prompt += f"\n\nDecoded payload:\n{decoded}"

    try:
        r = requests.post(
            API_URL,
            headers={"Content-Type": "application/json"},
            json={
                "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents":           [{"parts": [{"text": prompt}]}],
                "generationConfig":   {"maxOutputTokens": 1000},
            },
            timeout=timeout,
        )
        if r.status_code == 200:
            result["analysis"] = r.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        else:
            result["analysis"] = f"[API error {r.status_code}]"
            return result
    except requests.Timeout:
        result["analysis"] = "[Timed out — check internet connection]"
        return result
    except Exception as e:
        result["analysis"] = f"[Error: {e}]"
        return result

    # Extract risk score
    result["risk_score"] = extract_risk_score(result["analysis"])

    # Extract verdict line
    for line in result["analysis"].splitlines():
        if any(x in line for x in ("✅", "⚠", "🚨")):
            result["verdict"] = line.strip()
            break

    # IOC extraction + VT check
    iocs = extract_iocs(cmdline)
    if decoded:
        extra = extract_iocs(decoded)
        for k in iocs:
            iocs[k] = list(set(iocs[k] + extra.get(k, [])))
    result["iocs"]       = iocs
    result["vt_results"] = check_vt_iocs(iocs, vt_api_key)

    return result


# ── HISTORY ──────────────────────────────────────────────────────────────────
def _load_history() -> list:
    os.makedirs(paths.DATA_DIR, exist_ok=True)
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_to_history(result: dict):
    history = _load_history()
    entry = {
        "timestamp":  result.get("timestamp", ""),
        "cmdline":    result.get("cmdline", ""),
        "decoded":    result.get("decoded"),
        "risk_score": result.get("risk_score", -1),
        "verdict":    result.get("verdict", ""),
        "analysis":   result.get("analysis", ""),
        "vt_results": result.get("vt_results", []),
    }
    history.insert(0, entry)
    history = history[:100]   # keep last 100
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)

def get_history() -> list:
    return _load_history()

def clear_history():
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)


# ── EXPORT ───────────────────────────────────────────────────────────────────
def export_report(result: dict, filepath: str) -> bool:
    """Saves the full analysis report as a plain-text file."""
    try:
        lines = [
            "=" * 70,
            "  SkyAV AI Command Analyzer Report",
            f"  Generated: {result.get('timestamp', '')}",
            "=" * 70,
            "",
            f"COMMAND:  {result.get('cmdline', '')}",
        ]
        if result.get("decoded"):
            lines += ["", f"DECODED ({result.get('decode_method','base64')}):", result["decoded"]]
        risk = result.get("risk_score", -1)
        if risk >= 0:
            lines += ["", f"RISK SCORE: {risk}/100"]
        if result.get("verdict"):
            lines += [f"VERDICT:    {result['verdict']}"]
        vt = result.get("vt_results", [])
        if vt:
            lines += ["", "VIRUSTOTAL RESULTS:"]
            for v in vt:
                lines.append(f"  [{v['type']}] {v['ioc']}  →  {v['result']}")
        lines += ["", "-" * 70, "", result.get("analysis", ""), "", "=" * 70]
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return True
    except Exception:
        return False


# ── BATCH ANALYZE ─────────────────────────────────────────────────────────────
def batch_analyze(commands: list, vt_api_key: str = None) -> list:
    """Analyze a list of command strings. Returns list of result dicts."""
    results = []
    for cmd in commands:
        cmd = cmd.strip()
        if not cmd:
            continue
        dec = decode_command(cmd)
        r   = analyze(cmd, dec.get("decoded"), vt_api_key=vt_api_key)
        save_to_history(r)
        results.append(r)
    return results
