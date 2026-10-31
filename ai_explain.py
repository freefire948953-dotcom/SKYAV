"""
ai_explain.py
Uses the Claude API to give a detailed, plain-language security analysis
of flagged files — exactly what you'd get if you pasted the scan result
into an AI chat yourself.

No setup needed beyond an internet connection — uses the same API that
powers SkyAV's built-in intelligence. If the API is unavailable, falls
back to built-in static explanations gracefully.
"""

import requests
import json


API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a cybersecurity expert assistant embedded inside a custom antivirus tool called SkyAV. 
Your job is to explain scan results to the user in simple, clear language — no jargon unless you explain it.

When given a flagged file's details, you must provide:
1. WHAT IT IS: What does this detection mean in simple terms?
2. WHY FLAGGED: Why specifically did the antivirus flag this?
3. IS IT DANGEROUS: Give a realistic risk assessment (low/medium/high). Be honest — many flags are false positives.
4. WHAT TO DO: Clear, specific action steps the user should take right now.

Keep your response concise but complete — around 150-200 words. Use simple language. 
Format with those 4 sections clearly labeled. Do NOT use markdown, just plain text."""


def explain_threat(file_path: str, status: str, detail: str, timeout: int = 20) -> str:
    """
    Calls the Claude API to get a detailed plain-language explanation of a flagged file.
    Returns the explanation string, or a fallback message if the API is unavailable.
    """
    prompt = f"""Antivirus scan result:
File: {file_path}
Status: {status.upper()}
Detection reason: {detail}

Please analyze this scan result and explain it to me."""

    try:
        response = requests.post(
            API_URL,
            headers={
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": MODEL,
                "max_tokens": 400,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=timeout,
        )

        if response.status_code == 200:
            data = response.json()
            return data["content"][0]["text"].strip()
        else:
            return f"[AI explanation unavailable — API returned {response.status_code}]"

    except requests.Timeout:
        return "[AI explanation timed out — check your internet connection]"
    except Exception as e:
        return f"[AI explanation error: {type(e).__name__}]"


def explain_threats_batch(flagged_list: list, on_result=None) -> list:
    """
    Explains multiple flagged items. Calls on_result(index, path, explanation)
    after each one so the GUI can update progressively (no long wait).
    Returns list of explanation strings.
    """
    results = []
    for i, item in enumerate(flagged_list):
        explanation = explain_threat(
            file_path=item.get("path", "unknown"),
            status=item.get("status", "suspicious"),
            detail=item.get("detail", ""),
        )
        results.append(explanation)
        if on_result:
            on_result(i, item.get("path", ""), explanation)
    return results
