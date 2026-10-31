"""
signatures.py
Manages the known-malware hash database (SHA-256 based).
You can keep adding new hashes to data/signatures.json as you find them
(VirusShare, MalwareBazaar, abuse.ch feeds, etc.)
"""

import json
import os

import paths

DATA_DIR = paths.DATA_DIR
SIG_FILE = os.path.join(DATA_DIR, "signatures.json")

# EICAR test file hash included by default so you can test detection safely.
# (EICAR is an industry-standard harmless test string every AV flags.)
DEFAULT_SIGNATURES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}


def _ensure_file():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(SIG_FILE):
        with open(SIG_FILE, "w") as f:
            json.dump(DEFAULT_SIGNATURES, f, indent=2)


def load_signatures() -> dict:
    """Returns {sha256_hash: malware_name}"""
    _ensure_file()
    with open(SIG_FILE, "r") as f:
        return json.load(f)


def add_signature(sha256_hash: str, name: str):
    sigs = load_signatures()
    sigs[sha256_hash.lower()] = name
    with open(SIG_FILE, "w") as f:
        json.dump(sigs, f, indent=2)


def add_signatures_bulk(hash_name_pairs: dict):
    sigs = load_signatures()
    for h, n in hash_name_pairs.items():
        sigs[h.lower()] = n
    with open(SIG_FILE, "w") as f:
        json.dump(sigs, f, indent=2)


def import_from_txt(path: str):
    """
    Import a plain-text hash list where each line is either:
        <sha256_hash>
    or
        <sha256_hash>,<malware_name>
    Useful for bulk-loading public malware hash feeds.
    """
    sigs = load_signatures()
    count = 0
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",", 1)
            h = parts[0].strip().lower()
            name = parts[1].strip() if len(parts) > 1 else "Unknown-Malware"
            if len(h) == 64:  # valid sha256 length
                sigs[h] = name
                count += 1
    with open(SIG_FILE, "w") as f:
        json.dump(sigs, f, indent=2)
    return count
