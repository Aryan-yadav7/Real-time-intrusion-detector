"""Alert notifications for security events (Telegram, Discord, Slack, and generic webhooks).

Features:
  * Zero external dependencies (uses urllib.request).
  * Built-in per-site cooldowns to prevent notification spam during floods.
  * Formatted alerts with actionable incident details.
  * Test alert helper for immediate setup verification.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request

log = logging.getLogger("ids.alerts")

# In-memory cooldowns: (site_id, category) -> last_notified_timestamp
_COOLDOWNS: dict[tuple[str, str], float] = {}
COOLDOWN_SECONDS = 60.0


def _post_json(url: str, payload: dict, timeout: float = 5.0) -> tuple[int, str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Guard-IDS-Alerts/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        log.warning("Alert webhook failed: HTTP %s - %s", e.code, err[:200])
        return e.code, err
    except Exception as exc:
        log.warning("Alert webhook network error: %s", exc)
        return 0, str(exc)


_last_telegram_error: str = ""


def get_last_telegram_error() -> str:
    return _last_telegram_error or "check bot token and chat id"


def send_telegram(bot_token: str, chat_id: str, message: str) -> bool:
    """Send a message via Telegram Bot API."""
    global _last_telegram_error
    if not bot_token or not chat_id:
        _last_telegram_error = "Bot token or chat ID is missing."
        return False
    url = f"https://api.telegram.org/bot{bot_token.strip()}/sendMessage"
    payload = {
        "chat_id": chat_id.strip(),
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    status, resp_body = _post_json(url, payload)
    if 200 <= status < 300:
        _last_telegram_error = ""
        return True

    err_desc = f"HTTP {status}"
    try:
        data = json.loads(resp_body)
        raw_desc = data.get("description", "")
        if "bot can't initiate conversation" in raw_desc.lower():
            err_desc = f"{raw_desc} (Open your bot in Telegram and press /start first)"
        elif "chat not found" in raw_desc.lower():
            err_desc = f"{raw_desc} (Verify Chat ID is numeric, e.g. 123456789, not your @username)"
        elif "unauthorized" in raw_desc.lower():
            err_desc = f"{raw_desc} (Check bot token from @BotFather)"
        elif raw_desc:
            err_desc = raw_desc
    except Exception:
        if resp_body:
            err_desc = resp_body[:120]
    _last_telegram_error = err_desc
    return False


def send_discord(webhook_url: str, title: str, description: str, fields: list[dict], color: int = 0xE02424) -> bool:
    """Send an embed alert via Discord webhook."""
    if not webhook_url or "discord.com/api/webhooks" not in webhook_url:
        return False
    payload = {
        "content": "🛡️ **Guard Security Alert**",
        "embeds": [{
            "title": title[:256],
            "description": description[:2048],
            "color": color,
            "fields": [{"name": f["name"][:256], "value": f["value"][:1024], "inline": f.get("inline", True)} for f in fields[:10]],
            "footer": {"text": "Guard IDS • Real-time Threat Monitor"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }
    status, _ = _post_json(webhook_url, payload)
    return 200 <= status < 300


def send_slack_or_webhook(webhook_url: str, text: str, payload_data: dict | None = None) -> bool:
    """Send an alert to a Slack or generic JSON webhook."""
    if not webhook_url:
        return False
    if "hooks.slack.com" in webhook_url:
        payload = {"text": text}
    else:
        payload = payload_data or {"text": text, "source": "guard_ids", "timestamp": time.time()}
    status, _ = _post_json(webhook_url, payload)
    return 200 <= status < 300


def is_on_cooldown(site_id: str, category: str, now: float | None = None,
                   cooldown_seconds: float = COOLDOWN_SECONDS) -> bool:
    """Check if an alert of this category was recently sent for this site."""
    now = now or time.time()
    key = (site_id, category)
    last = _COOLDOWNS.get(key, 0.0)
    if now - last < cooldown_seconds:
        return True
    _COOLDOWNS[key] = now
    # Clean up very old cooldowns
    if len(_COOLDOWNS) > 2000:
        cutoff = now - 3600
        for k in [k for k, t in _COOLDOWNS.items() if t < cutoff]:
            del _COOLDOWNS[k]
    return False


def build_alert_message(site_name: str, event: dict) -> str:
    """Construct plain-text and HTML-friendly summary for an intercepted threat."""
    score = event.get("score") or 0
    ip = event.get("ip") or "unknown"
    path = event.get("path") or "/"
    method = (event.get("method") or "GET").upper()
    action = (event.get("action") or "detected").upper()
    severity = (event.get("severity") or "high").upper()
    category = event.get("category") or "unknown"
    rule_id = event.get("rule_id") or ""
    evidence = event.get("evidence") or ""

    text = (
        f"🚨 [{severity}] GUARD SECURITY ALERT: {site_name}\n"
        f"Status: {action} (Score: {score}/100)\n"
        f"Attack: {category}" + (f" ({rule_id})" if rule_id else "") + "\n"
        f"Attacker IP: {ip}\n"
        f"Request: {method} {path}\n"
        f"Action: {action}\n"
    )
    if evidence:
        text += f"Evidence: {evidence[:100]}\n"
    return text


def dispatch_alert(message: str, config: dict, event: dict | None = None,
                   site_name: str = "Website") -> list[dict]:
    """Send an alert message across configured channels (Discord, Slack, Webhook, Telegram)."""
    results: list[dict] = []
    event = event or {}

    # 1. Telegram
    tg_token = config.get("telegram_token") or config.get("telegram_bot_token")
    tg_chat = config.get("telegram_chat_id")
    if tg_token and tg_chat:
        clean_msg = message.replace("<", "&lt;").replace(">", "&gt;")
        formatted_tg = f"<b>🚨 GUARD SECURITY ALERT</b>\n<pre>{clean_msg}</pre>"
        ok = send_telegram(tg_token, tg_chat, formatted_tg)
        results.append({"channel": "telegram", "ok": ok})

    # 2. Discord / Slack / Webhook
    webhook = config.get("webhook_url")
    if webhook:
        if "discord.com" in webhook:
            score = event.get("score") or 0
            category = event.get("category") or "Threat"
            action = (event.get("action") or "detected").upper()
            fields = [
                {"name": "Site", "value": site_name, "inline": True},
                {"name": "Action", "value": action, "inline": True},
                {"name": "Score", "value": str(score), "inline": True},
                {"name": "Attacker IP", "value": f"`{event.get('ip', 'unknown')}`", "inline": True},
                {"name": "Target Path", "value": f"`{event.get('path', '/')}`", "inline": True},
            ]
            if event.get("evidence"):
                fields.append({"name": "Evidence", "value": f"`{str(event['evidence'])[:120]}`", "inline": False})
            color = 0xDC2626 if action == "BLOCKED" else 0xF59E0B
            ok = send_discord(webhook, f"Security Alert: {category.title()}", message, fields, color)
            results.append({"channel": "discord", "ok": ok})
        else:
            channel_name = "slack" if "hooks.slack.com" in webhook else "webhook"
            ok = send_slack_or_webhook(webhook, message, {"site": site_name, "message": message, "event": event})
            results.append({"channel": channel_name, "ok": ok})

    return results


def notify_event(site_name: str, site_id: str, event: dict, config: dict, now: float | None = None) -> bool:
    """Send an alert across configured channels if not on cooldown.

    config can contain:
      * 'telegram_token', 'telegram_chat_id'
      * 'webhook_url' (Discord, Slack, or generic webhook)
      * 'alert_min_score': int (default 70)
    """
    if not config.get("alerts_enabled", True):
        return False

    score = event.get("score") or 0
    min_score = config.get("alert_min_score", 70)
    # Only alert on attacks crossing the score threshold or explicit blocks
    if score < min_score and event.get("action") != "blocked":
        return False

    category = event.get("category") or "unknown"
    if is_on_cooldown(site_id, category, now):
        return False

    if not (config.get("webhook_url") or (config.get("telegram_token") or config.get("telegram_bot_token"))):
        return False

    msg = build_alert_message(site_name, event)
    res = dispatch_alert(msg, config, event=event, site_name=site_name)
    return any(r.get("ok") for r in res)


def send_test_notification(config: dict, site_name: str = "Demo Site") -> dict:
    """Send an immediate test alert to verify webhook / Telegram configuration."""
    results = {}
    tg_token = config.get("telegram_token") or config.get("telegram_bot_token")
    tg_chat = config.get("telegram_chat_id")
    if tg_token and tg_chat:
        msg = (
            f"✅ <b>Guard IDS Integration Test</b>\n"
            f"<b>Site:</b> {site_name}\n"
            f"Your Telegram security alerts are successfully connected! You will receive instant notifications here when threats are blocked."
        )
        ok = send_telegram(tg_token, tg_chat, msg)
        results["telegram"] = "ok" if ok else f"failed ({get_last_telegram_error()})"

    webhook = config.get("webhook_url")
    if webhook:
        if "discord.com" in webhook:
            fields = [
                {"name": "Site", "value": site_name, "inline": True},
                {"name": "Status", "value": "Connected ✅", "inline": True},
                {"name": "Mode", "value": "Real-time Alerts", "inline": True},
            ]
            ok = send_discord(webhook, "Guard IDS Test Notification", f"Integration test for **{site_name}**. Security alerts are active.", fields, 0x10B981)
            results["discord"] = "ok" if ok else "failed (check webhook URL)"
        else:
            text = f"✅ Guard IDS Integration Test: Alerts connected for {site_name}."
            ok = send_slack_or_webhook(webhook, text)
            results["webhook"] = "ok" if ok else "failed (check webhook URL)"

    if not results:
        return {"ok": False, "error": "No notification channels configured (provide Telegram token/chat or webhook URL)."}

    all_ok = any(v == "ok" for v in results.values())
    res_list = [{"channel": k, "ok": v == "ok", "error": None if v == "ok" else v} for k, v in results.items()]
    return {"ok": all_ok, "channels": results, "results": res_list}
