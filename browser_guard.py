"""
browser_guard.py
Detects common browser-hijacking techniques:
  1. Hosts file tampering (redirecting known domains to a different IP)
  2. Sideloaded / unknown browser extensions (Chrome & Edge)
  3. Homepage / default search engine hijack
"""

import os
import json
import platform

IS_WINDOWS = platform.system() == "Windows"

# Domains that should never be redirected by a legitimate hosts file entry.
# If any of these point somewhere other than localhost/loopback, it's almost
# always a hijack (used to block updates/security sites or redirect traffic).
WATCHED_DOMAINS = [
    "google.com", "www.google.com",
    "facebook.com", "www.facebook.com",
    "microsoft.com", "www.microsoft.com",
    "windowsupdate.com",
    "virustotal.com",
]

# Known-good search engine domains. Anything else set as default search = flag.
TRUSTED_SEARCH_DOMAINS = [
    "google.com", "bing.com", "duckduckgo.com", "yahoo.com", "ecosia.org",
]


def check_hosts_file() -> list:
    """Scans the Windows hosts file for suspicious redirects."""
    findings = []
    if IS_WINDOWS:
        hosts_path = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32", "drivers", "etc", "hosts")
    else:
        hosts_path = "/etc/hosts"

    if not os.path.exists(hosts_path):
        return findings

    try:
        with open(hosts_path, "r", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip, domain = parts[0], parts[1].lower()
                if domain in WATCHED_DOMAINS and not ip.startswith("127.") and ip != "::1":
                    findings.append({
                        "type": "hosts_hijack",
                        "detail": f"'{domain}' is redirected to {ip} (line {line_num}) — should point to its real server, not be overridden.",
                    })
    except (PermissionError, OSError):
        pass

    return findings


def _chrome_based_paths():
    """Returns (browser_name, user_data_dir) for installed Chromium browsers."""
    if not IS_WINDOWS:
        return []
    user = os.environ.get("USERPROFILE", "")
    candidates = [
        ("Chrome", os.path.join(user, "AppData", "Local", "Google", "Chrome", "User Data")),
        ("Edge", os.path.join(user, "AppData", "Local", "Microsoft", "Edge", "User Data")),
    ]
    return [(name, path) for name, path in candidates if os.path.isdir(path)]


def check_extensions() -> list:
    """Lists installed extensions per profile and flags sideloaded (non-Web-Store) ones."""
    findings = []
    for browser_name, base in _chrome_based_paths():
        for profile in ("Default", "Profile 1", "Profile 2"):
            ext_dir = os.path.join(base, profile, "Extensions")
            if not os.path.isdir(ext_dir):
                continue
            for ext_id in os.listdir(ext_dir):
                ext_path = os.path.join(ext_dir, ext_id)
                if not os.path.isdir(ext_path):
                    continue
                # A real Web Store extension ID is exactly 32 lowercase letters.
                looks_legit = len(ext_id) == 32 and ext_id.isalpha() and ext_id.islower()
                if not looks_legit:
                    findings.append({
                        "type": "suspicious_extension",
                        "detail": f"{browser_name} ({profile}): extension folder '{ext_id}' doesn't look like a normal Web Store extension ID.",
                    })
    return findings


def check_homepage_and_search() -> list:
    """Reads Chromium 'Preferences' JSON and flags an untrusted default search engine."""
    findings = []
    for browser_name, base in _chrome_based_paths():
        for profile in ("Default", "Profile 1", "Profile 2"):
            pref_path = os.path.join(base, profile, "Preferences")
            if not os.path.exists(pref_path):
                continue
            try:
                with open(pref_path, "r", encoding="utf-8", errors="ignore") as f:
                    prefs = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            # Homepage
            homepage = prefs.get("homepage", "")
            if homepage and not any(d in homepage for d in TRUSTED_SEARCH_DOMAINS):
                if homepage.startswith("http"):
                    findings.append({
                        "type": "homepage_hijack",
                        "detail": f"{browser_name} ({profile}): homepage is set to an unrecognized site: {homepage}",
                    })

            # Default search engine (search_provider_overrides is the hijack vector)
            overrides = prefs.get("search_provider_overrides")
            if overrides:
                for entry in overrides:
                    url = entry.get("search_url", "")
                    if url and not any(d in url for d in TRUSTED_SEARCH_DOMAINS):
                        findings.append({
                            "type": "search_hijack",
                            "detail": f"{browser_name} ({profile}): default search engine overridden to an unrecognized provider: {url}",
                        })
    return findings


def run_full_check() -> dict:
    """Runs all browser hijack checks. Returns a summary dict."""
    findings = []
    findings.extend(check_hosts_file())
    findings.extend(check_extensions())
    findings.extend(check_homepage_and_search())
    return {
        "clean": len(findings) == 0,
        "findings": findings,
    }
