"""
telegram_bot.py
Telegram alert delivery for live detections, on-demand scans, and simulations.
Supports dynamic token resolution, test alerts, automated Chat ID discovery, and retry backoff.
"""

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()


def get_bot_info(bot_token=None):
    """Validates the bot token and returns the bot details."""
    token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        return False, "Bot token not provided."

    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        if data.get("ok"):
            bot_user = data.get("result", {})
            name = bot_user.get("first_name", "Telegram Bot")
            username = bot_user.get("username", "")
            return True, {"name": name, "username": username, "id": bot_user.get("id")}
        return False, data.get("description", "Invalid Bot Token")
    except Exception as exc:
        return False, f"Connection error: {str(exc)}"


def get_chat_id_from_updates(bot_token=None):
    """
    Polls getUpdates from the Telegram Bot API to automatically detect the Chat ID
    of the user/group that messaged or started the bot.
    Returns (chat_id, user_display_name, error_message).
    """
    token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        return None, None, "Bot Token is required."

    url = f"https://api.telegram.org/bot{token}/getUpdates"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        if not data.get("ok"):
            return None, None, f"Telegram API Error: {data.get('description', 'Invalid token')}"

        results = data.get("result", [])
        if not results:
            return None, None, "No messages found yet. Please open Telegram, search your bot, tap 'Start' or send a message like 'hi', then click Auto-Detect again!"

        # Extract latest message or update
        for item in reversed(results):
            msg = item.get("message") or item.get("channel_post") or item.get("my_chat_member")
            if msg:
                chat = msg.get("chat", {})
                chat_id = str(chat.get("id"))
                first_name = chat.get("first_name", "")
                title = chat.get("title", "")
                username = chat.get("username", "")
                display = title or (f"{first_name} (@{username})" if username else (first_name or f"Chat {chat_id}"))
                return chat_id, display, None

        return None, None, "Could not extract chat information from recent updates."
    except Exception as exc:
        return None, None, f"Connection error: {str(exc)}"


def send_alert(
    domain,
    risk_score,
    risk_level,
    matched_brand,
    retries=2,
    source="LIVE",
    match_id=None,
    risk_reason=None,
    bot_token=None,
    chat_id=None,
):
    """Send a HIGH or MEDIUM risk Telegram alert."""
    token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
    chat = chat_id or os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat:
        print("[!] Telegram credentials not configured, skipping alert.")
        return False

    level = str(risk_level or "").upper()
    source = str(source or "LIVE").upper()

    title = f"🚨 {level}-RISK PHISHING ALERT [{source}]"

    message = (
        f"*{title}*\n\n"
        f"🌐 *Domain:* `{domain}`\n"
        f"🎯 *Target Brand:* `{matched_brand}`\n"
        f"📊 *Risk Score:* *{risk_score}/100* ({level})\n"
    )

    if risk_reason:
        message += f"⚠️ *Reason:* {risk_reason}\n"

    if match_id:
        message += f"🆔 *Match ID:* `{match_id}`\n"

    message += f"🕒 *Discovered:* `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`\n"
    message += "\n*Recommended Action:* Initiate immediate registrar takedown and block on DNS firewalls."

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat,
        "text": message,
        "parse_mode": "Markdown",
    }

    for attempt in range(1, retries + 2):
        try:
            response = requests.post(url, data=payload, timeout=12)
            if response.status_code == 200:
                print(f"[+] Telegram alert successfully delivered for {domain}.")
                return True
            print(f"[!] Telegram API error {response.status_code}: {response.text}")
        except Exception as exc:
            print(f"[!] Telegram alert attempt {attempt} failed: {exc}")

        if attempt < retries + 1:
            time.sleep(2)

    return False


def test_telegram_connection(bot_token=None, chat_id=None):
    """Sends a verification ping to validate credentials."""
    token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
    chat = chat_id or os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat:
        return False, "Bot Token and Chat ID must both be provided."

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat,
        "text": "🛡️ *CyberSentinel Alert Integration*\n\n✅ Your Telegram Bot has been linked successfully! Real-time phishing and brand impersonation alerts will be dispatched here.",
        "parse_mode": "Markdown",
    }

    try:
        resp = requests.post(url, data=payload, timeout=10)
        if resp.status_code == 200:
            return True, "Telegram test message sent successfully!"
        return False, f"Telegram API error {resp.status_code}: {resp.text}"
    except Exception as exc:
        return False, f"Connection failed: {str(exc)}"


def send_simulation_alert(candidate):
    """Wrapper for simulation scenario alerts."""
    return send_alert(
        domain=candidate.get("domain"),
        risk_score=candidate.get("risk_score"),
        risk_level=candidate.get("risk_level"),
        matched_brand=candidate.get("matched_brand"),
        source="SIMULATION",
        risk_reason="Simulation scenario demonstration triggered by analyst.",
    )


def send_live_alert(candidate):
    """Wrapper for live detection alerts."""
    return send_alert(
        domain=candidate.get("domain"),
        risk_score=candidate.get("risk_score"),
        risk_level=candidate.get("risk_level"),
        matched_brand=candidate.get("matched_brand"),
        source="LIVE",
        risk_reason=candidate.get("analyst_notes") or "High-risk domain detected in live scan.",
    )
