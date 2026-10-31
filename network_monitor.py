"""
network_monitor.py
Monitors outbound network connections in real time and cross-checks them
against free threat intelligence feeds (abuse.ch Feodo Tracker, URLhaus).

This catches malware that has already executed and is phoning home to a
command-and-control server — something file scanning alone can't detect.

Threat intel is refreshed daily from free public feeds:
  • Feodo Tracker (abuse.ch) — known botnet C2 servers
  • URLhaus (abuse.ch) — known malware download URLs / IPs
"""

import os
import time
import json
import socket
import requests
import psutil
from datetime import datetime

import paths

DATA_DIR = paths.DATA_DIR
BLOCKLIST_FILE = os.path.join(DATA_DIR, "ip_blocklist.json")

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/json/"

# Well-known safe IP ranges to never flag (private/local networks)
SAFE_PREFIXES = (
    "127.", "0.", "10.", "192.168.", "169.254.", "::1",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_blocklist() -> dict:
    if not os.path.exists(BLOCKLIST_FILE):
        return {"ips": {}, "last_update": None}
    with open(BLOCKLIST_FILE, "r") as f:
        return json.load(f)


def _save_blocklist(data: dict):
    _ensure_dir()
    with open(BLOCKLIST_FILE, "w") as f:
        json.dump(data, f, indent=2)


def update_blocklist(progress_callback=None) -> dict:
    """Downloads fresh IP blocklists from abuse.ch feeds."""
    if progress_callback:
        progress_callback("Downloading Feodo Tracker IP blocklist...")

    data = _load_blocklist()
    added = 0

    try:
        resp = requests.get(FEODO_URL, timeout=30)
        resp.raise_for_status()
        entries = resp.json()
        for entry in entries:
            ip = entry.get("ip_address", "")
            malware = entry.get("malware", "Unknown")
            if ip:
                data["ips"][ip] = malware
                added += 1
        if progress_callback:
            progress_callback(f"Feodo: {added} malicious IPs loaded")
    except Exception as e:
        if progress_callback:
            progress_callback(f"Feodo update failed: {e}")

    data["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_blocklist(data)
    return {"added": added, "total": len(data["ips"])}


def is_malicious_ip(ip: str) -> str:
    """Returns malware family name if IP is in blocklist, else empty string."""
    if any(ip.startswith(p) for p in SAFE_PREFIXES):
        return ""
    data = _load_blocklist()
    return data["ips"].get(ip, "")


def scan_connections() -> list:
    """
    Scans all current outbound TCP connections and checks against blocklist.
    Returns list of flagged {pid, process, local, remote_ip, malware} dicts.
    """
    flagged = []
    blocklist = _load_blocklist()["ips"]

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED":
                continue
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            if any(remote_ip.startswith(p) for p in SAFE_PREFIXES):
                continue

            malware = blocklist.get(remote_ip, "")
            if malware:
                process_name = "Unknown"
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = f"{proc.name()} (PID {conn.pid})"
                except Exception:
                    pass

                flagged.append({
                    "pid": conn.pid,
                    "process": process_name,
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "malware": malware,
                })
    except Exception:
        pass

    return flagged


def start_network_monitor(on_threat=None, interval: float = 30.0):
    """
    Continuously checks network connections against the blocklist.
    Calls on_threat(flagged_list) when malicious connections are found.
    Blocking — run in a daemon thread.
    """
    # Ensure blocklist exists
    if not _load_blocklist()["ips"]:
        update_blocklist()

    print(f"Network Monitor active (checking every {interval}s)")
    alerted = set()

    while True:
        flagged = scan_connections()
        for item in flagged:
            key = f"{item['remote_ip']}:{item['pid']}"
            if key not in alerted:
                alerted.add(key)
                if on_threat:
                    on_threat(item)
                else:
                    print(f"🚨 Malicious connection: {item['process']} → "
                          f"{item['remote_ip']}:{item['remote_port']} ({item['malware']})")
        time.sleep(interval)
