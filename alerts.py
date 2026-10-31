"""
alerts.py
Sends real-time threat notifications so you know the instant something is
caught, even when you're away from the PC. Three channels, use any/all:

TELEGRAM (~2 min setup):
    1. Open Telegram, search for "@BotFather", start a chat
    2. Send: /newbot   and follow the prompts (name your bot anything)
    3. BotFather gives you a token like: 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ
    4. Send any message to your new bot (search its username, hit Start)
    5. Visit: https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
       (replace <YOUR_TOKEN>) — find "chat":{"id": 123456789} in the response
    6. Run: python main.py --set-telegram TOKEN CHAT_ID

DISCORD WEBHOOK (~1 min setup):
    1. In any Discord server you manage: Channel Settings -> Integrations
       -> Webhooks -> New Webhook
    2. Click "Copy Webhook URL"
    3. Run: python main.py --set-discord-webhook URL

EMAIL (~2 min setup, Gmail example):
    1. Go to https://myaccount.google.com/apppasswords
    2. Create an "App Password" for Mail (needs 2FA enabled on the account)
    3. Run: python main.py --set-email your@gmail.com APP_PASSWORD recipient@email.com
       (recipient can be the same address as sender, to email yourself)

DESKTOP NOTIFICATIONS:
    Uses the system tray icon's native balloon/toast notification — works
    automatically whenever the GUI is running with the tray icon active.
    No setup needed.
"""

import os
import json
import smtplib
from email.mime.text import MIMEText
import requests

import paths

DATA_DIR = paths.DATA_DIR
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

# Set by gui.py at startup once the tray icon is running, so alerts.py can
# trigger a native desktop notification without gui.py needing to import
# this module's internals directly.
_desktop_notify_callback = None


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_config() -> dict:
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def _save_config(config: dict):
    _ensure_dir()
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


# ---------- Telegram ----------

def save_telegram_config(bot_token: str, chat_id: str):
    config = _load_config()
    config["telegram_bot_token"] = bot_token.strip()
    config["telegram_chat_id"] = chat_id.strip()
    _save_config(config)


def get_telegram_config():
    config = _load_config()
    return config.get("telegram_bot_token"), config.get("telegram_chat_id")


def send_telegram_message(message: str, timeout: int = 10) -> bool:
    token, chat_id = get_telegram_config()
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        resp = requests.post(url, data={"chat_id": chat_id, "text": message}, timeout=timeout)
        return resp.status_code == 200
    except requests.RequestException:
        return False


# ---------- Discord Webhook ----------

def save_discord_webhook(webhook_url: str):
    config = _load_config()
    config["discord_webhook_url"] = webhook_url.strip()
    _save_config(config)


def get_discord_webhook():
    return _load_config().get("discord_webhook_url")


def send_discord_message(message: str, timeout: int = 10) -> bool:
    webhook_url = get_discord_webhook()
    if not webhook_url:
        return False
    try:
        resp = requests.post(webhook_url, json={"content": message}, timeout=timeout)
        return resp.status_code in (200, 204)
    except requests.RequestException:
        return False


# ---------- Email ----------

def save_email_config(sender_email: str, app_password: str, recipient_email: str,
                       smtp_server: str = "smtp.gmail.com", smtp_port: int = 465):
    config = _load_config()
    config["email_sender"] = sender_email.strip()
    config["email_app_password"] = app_password.strip()
    config["email_recipient"] = recipient_email.strip()
    config["email_smtp_server"] = smtp_server.strip()
    config["email_smtp_port"] = smtp_port
    _save_config(config)


def get_email_config():
    config = _load_config()
    return (
        config.get("email_sender"),
        config.get("email_app_password"),
        config.get("email_recipient"),
        config.get("email_smtp_server", "smtp.gmail.com"),
        config.get("email_smtp_port", 465),
    )


def send_email_message(subject: str, body: str, timeout: int = 15) -> bool:
    error = send_email_message_debug(subject, body, timeout)
    return error is None


def send_email_message_debug(subject: str, body: str, timeout: int = 15) -> str:
    """Same as send_email_message but returns the actual error string (or None on success) — for troubleshooting."""
    sender, app_password, recipient, smtp_server, smtp_port = get_email_config()
    if not sender or not app_password or not recipient:
        return "Email not configured (missing sender/password/recipient)"
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = recipient

        with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=timeout) as server:
            server.login(sender, app_password)
            server.sendmail(sender, [recipient], msg.as_string())
        return None
    except Exception as e:
        return f"{type(e).__name__}: {e}"


# ---------- Desktop Notification ----------

def register_desktop_notifier(callback):
    """gui.py calls this once, passing a function(title, message) that
    triggers the tray icon's native notification."""
    global _desktop_notify_callback
    _desktop_notify_callback = callback


def send_desktop_notification(title: str, message: str) -> bool:
    if _desktop_notify_callback is None:
        return False
    try:
        _desktop_notify_callback(title, message)
        return True
    except Exception:
        return False


# ---------- Unified alert dispatch ----------

def send_threat_alert(result: dict):
    """Sends a threat alert through every configured channel."""
    title = "SkyAV Threat Detected"
    message = (
        f"Status: {result.get('status', 'unknown').upper()}\n"
        f"File: {result.get('path', 'unknown')}\n"
        f"Detail: {result.get('detail', '')}"
    )
    send_telegram_message(f"🚨 {title}\n\n{message}")
    send_discord_message(f"🚨 **{title}**\n{message}")
    send_email_message(f"🚨 {title}", message)
    send_desktop_notification(title, f"{result.get('status', 'unknown').upper()}: {os.path.basename(result.get('path', ''))}")


def send_scan_summary(scan_type: str, summary: dict):
    """Sends a scan summary through every configured channel (skips clean scans)."""
    if summary.get("infected", 0) == 0 and summary.get("suspicious", 0) == 0:
        return
    title = f"SkyAV {scan_type} Complete"
    message = (
        f"Scanned: {summary.get('scanned', 0)}\n"
        f"Infected: {summary.get('infected', 0)}\n"
        f"Suspicious: {summary.get('suspicious', 0)}"
    )
    send_telegram_message(f"📊 {title}\n\n{message}")
    send_discord_message(f"📊 **{title}**\n{message}")
    send_email_message(f"📊 {title}", message)
    send_desktop_notification(title, f"{summary.get('infected', 0)} infected, {summary.get('suspicious', 0)} suspicious")
