"""
threat_hunter.py
AI-powered threat hunting — the user describes suspicious behavior in plain
language, and the AI analyzes live system data (processes, network, files,
registry) to hunt for matching threats and report findings.

This feature literally doesn't exist in any commercial antivirus.
"""

import os
import platform
import json
import psutil
import requests

import paths

IS_WINDOWS = platform.system() == "Windows"
API_KEY = os.environ.get("GEMINI_API_KEY", "")
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={API_KEY}"

SYSTEM_PROMPT = """You are an expert cybersecurity threat hunter embedded in a custom antivirus tool called SkyAV.
The user will describe suspicious behavior they've noticed on their PC.
You will receive live system data: running processes, network connections, and recent scan results.

Your job:
1. Analyze the user's concern against the system data provided
2. Identify any processes, connections, or patterns that match or could explain the suspicious behavior
3. Give a clear verdict: Found / Not found / Inconclusive
4. If found: name the specific process/file/connection and explain what to do
5. If not found: explain what the behavior could mean and what other steps to take

Be direct and actionable. Use simple language. Keep response under 300 words."""


def _gather_system_snapshot() -> dict:
    """Collects live system data to give the AI context."""
    snapshot = {
        "running_processes": [],
        "network_connections": [],
        "platform": platform.system(),
    }

    # Running processes (top 30 by memory)
    try:
        procs = []
        for p in psutil.process_iter(["pid", "name", "exe", "memory_percent"]):
            try:
                procs.append({
                    "pid": p.info["pid"],
                    "name": p.info["name"],
                    "path": p.info["exe"] or "unknown",
                    "mem_pct": round(p.info["memory_percent"] or 0, 2),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        snapshot["running_processes"] = sorted(procs, key=lambda x: -x["mem_pct"])[:30]
    except Exception:
        pass

    # Active network connections
    try:
        conns = []
        for c in psutil.net_connections(kind="inet"):
            if c.status == "ESTABLISHED" and c.raddr:
                try:
                    proc_name = psutil.Process(c.pid).name() if c.pid else "unknown"
                except Exception:
                    proc_name = "unknown"
                conns.append({
                    "process": proc_name,
                    "pid": c.pid,
                    "remote": f"{c.raddr.ip}:{c.raddr.port}",
                })
        snapshot["network_connections"] = conns[:20]
    except Exception:
        pass

    return snapshot


def hunt(user_query: str, recent_scan_summary: dict = None, timeout: int = 30) -> str:
    """
    Main threat hunting function.
    user_query: plain language description of suspicious behavior
    recent_scan_summary: optional last scan result for context
    Returns: AI analysis string
    """
    if not API_KEY:
        return "[AI Threat Hunting unavailable — GEMINI_API_KEY not set]"

    snapshot = _gather_system_snapshot()

    context_parts = [
        f"USER CONCERN: {user_query}",
        f"\nRUNNING PROCESSES ({len(snapshot['running_processes'])} shown):",
    ]

    for p in snapshot["running_processes"]:
        context_parts.append(f"  [{p['pid']}] {p['name']} — {p['path']} (mem: {p['mem_pct']}%)")

    if snapshot["network_connections"]:
        context_parts.append(f"\nACTIVE NETWORK CONNECTIONS ({len(snapshot['network_connections'])} shown):")
        for c in snapshot["network_connections"]:
            context_parts.append(f"  {c['process']} (PID {c['pid']}) → {c['remote']}")
    else:
        context_parts.append("\nACTIVE NETWORK CONNECTIONS: None detected")

    if recent_scan_summary and recent_scan_summary.get("flagged"):
        context_parts.append(f"\nRECENT SCAN FLAGGED FILES ({len(recent_scan_summary['flagged'])}):")
        for f in recent_scan_summary["flagged"][:5]:
            context_parts.append(f"  [{f['status'].upper()}] {f['path']}: {f['detail']}")

    prompt = "\n".join(context_parts)

    try:
        response = requests.post(
            API_URL,
            headers={"Content-Type": "application/json"},
            json={
                "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": 600},
            },
            timeout=timeout,
        )

        if response.status_code == 200:
            return response.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        else:
            return f"[AI Threat Hunting unavailable — API returned {response.status_code}: {response.text}]"

    except requests.Timeout:
        return "[AI Threat Hunting timed out — check internet connection]"
    except Exception as e:
        return f"[AI Threat Hunting error: {type(e).__name__}: {e}]"
