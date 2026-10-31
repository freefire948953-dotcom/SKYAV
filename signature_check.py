"""
signature_check.py (v2)
Verifies whether an executable is digitally signed by a trusted publisher.

Originally implemented via raw ctypes calls to WinVerifyTrust -- that's the
"correct" low-level way, but it's fragile (struct layout bugs are easy to
introduce and hard to catch without a live Windows machine to test against).

Rewritten to shell out to PowerShell's Get-AuthenticodeSignature cmdlet
instead -- this is the exact same underlying Windows trust-verification
logic, but Microsoft has already implemented and tested it, so we just
parse its output instead of reimplementing WinTrust ourselves.
"""

import os
import platform
import subprocess
import json
import base64

IS_WINDOWS = platform.system() == "Windows"


def verify_signature(filepath: str, timeout: int = 10) -> dict:
    """
    Returns {status, publisher} where status is one of:
      "trusted"    -> validly signed by a trusted publisher chain
      "untrusted"  -> signed but invalid/expired/revoked/self-signed
      "unsigned"   -> no signature present at all
      "unknown"    -> couldn't determine (non-Windows, PowerShell unavailable, etc.)
    """
    if not IS_WINDOWS:
        return {"status": "unknown", "publisher": None}

    if not os.path.isfile(filepath):
        return {"status": "unknown", "publisher": None}

    ps_script = (
        "$sig = Get-AuthenticodeSignature -LiteralPath $env:SKYAV_TARGET_PATH; "
        "$signer = $null; "
        "if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }; "
        "$out = @{ Status = $sig.Status.ToString(); Signer = $signer }; "
        "$out | ConvertTo-Json -Compress"
    )
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")

    try:
        env = os.environ.copy()
        env["SKYAV_TARGET_PATH"] = filepath

        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        output = proc.stdout.strip()
        if not output:
            return {"status": "unknown", "publisher": None}

        data = json.loads(output)
        ps_status = data.get("Status", "")
        publisher = _extract_cn(data.get("Signer"))

        if ps_status == "Valid":
            return {"status": "trusted", "publisher": publisher}
        elif ps_status == "NotSigned":
            return {"status": "unsigned", "publisher": None}
        else:
            return {"status": "untrusted", "publisher": publisher}

    except (subprocess.SubprocessError, OSError, json.JSONDecodeError, FileNotFoundError):
        return {"status": "unknown", "publisher": None}


def _extract_cn(subject: str) -> str:
    """Pulls the 'CN=...' common name out of a certificate subject string."""
    if not subject:
        return None
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part[3:].strip('"')
    return subject
