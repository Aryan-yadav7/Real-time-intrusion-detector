"""Live dashboard: JSON snapshot, Server-Sent Events stream and the HTML page.

How "live" works (Server-Sent Events, SSE):
  The browser opens ONE long-lived request to /stream. The server keeps it
  open and writes a new "data: {...}" line whenever something changes. The
  browser's built-in EventSource reconnects automatically if the connection
  drops. It is simpler than WebSockets because data only flows one way.

SECURITY NOTE: attackers control much of what we record (path, evidence,
User-Agent). The dashboard page therefore never uses innerHTML, only
textContent, and is served with a strict Content-Security-Policy.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from . import alerts, copilot, db
from .behavior import BEHAVIOR_CATEGORIES
from .messages import category_info, describe_event
from .status import HIGH_SCORE, WINDOW_SECONDS, compute_status

_PAGE = (Path(__file__).parent / "static" / "dashboard.html").read_text(encoding="utf-8")
DAY = 24 * 3600


def snapshot(db_path: str, site_id: str, mode: str = "detect", now: float | None = None) -> dict:
    """Everything the dashboard needs, in one JSON-friendly dict."""
    now = time.time() if now is None else now
    counts = db.threat_counts(db_path, site_id, now - WINDOW_SECONDS, HIGH_SCORE, BEHAVIOR_CATEGORIES)
    sources = db.top_sources(db_path, site_id, now - DAY)
    for s in sources:
        s["top_label"] = category_info(s["top_category"])["label"]
    by_label: dict[str, int] = {}
    for category, n in db.category_counts(db_path, site_id, now - DAY):
        label = category_info(category)["label"]
        by_label[label] = by_label.get(label, 0) + n
    return {
        "generated_at": now,
        "mode": mode,
        "status": compute_status(counts),
        "totals": db.summary(db_path, site_id, now - DAY),
        "by_category": [{"label": k, "count": v}
                        for k, v in sorted(by_label.items(), key=lambda kv: (-kv[1], kv[0]))],
        "top_sources": sources,
        "timeline": db.timeline(db_path, site_id, 60, now),
        "events": [describe_event(e) for e in db.recent_events(db_path, site_id, limit=40)],
    }


async def sse_messages(db_path: str, site_id: str, mode: str = "detect",
                       interval: float = 1.0, heartbeat: float = 5.0,
                       max_messages: int | None = None):
    """Yield SSE messages: whenever data changed, and at least every `heartbeat` seconds.

    The heartbeat matters because the banner can change with time alone
    (red turns back to green after 5 quiet minutes).
    """
    yield "retry: 2000\n\n"
    last_key, last_sent, sent = None, 0.0, 0
    while max_messages is None or sent < max_messages:
        key = await asyncio.to_thread(
            lambda: (db.max_event_id(db_path, site_id), db.summary(db_path, site_id)["requests"]))
        now = time.monotonic()
        if key != last_key or now - last_sent >= heartbeat:
            snap = await asyncio.to_thread(snapshot, db_path, site_id, mode)
            yield f"data: {json.dumps(snap)}\n\n"
            last_key, last_sent, sent = key, now, sent + 1
        else:
            await asyncio.sleep(interval)


_LOCAL_ALERTS: dict[str, dict[str, str | int]] = {}


def get_local_alerts(site_id: str = "demo") -> dict[str, str | int]:
    return _LOCAL_ALERTS.setdefault(site_id, {
        "webhook_url": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "alert_min_score": 70,
    })


def create_dashboard_router(db_path: str, site_id: str = "demo", mode: str = "detect") -> APIRouter:
    """Mount with app.include_router(router, prefix="/ids") and exempt "/ids" in the middleware."""
    router = APIRouter()
    _local_alerts = get_local_alerts(site_id)

    @router.get("/", response_class=HTMLResponse)
    def page():
        nonce = secrets.token_urlsafe(16)
        csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        return HTMLResponse(_PAGE.replace("__NONCE__", nonce), headers={
            "Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})

    @router.get("/api/snapshot")
    def api_snapshot():
        return JSONResponse(snapshot(db_path, site_id, mode), headers={"Cache-Control": "no-store"})

    @router.get("/api/events")
    def api_events(limit: int = 50, offset: int = 0, category: str | None = None,
                   action: str | None = None, severity: str | None = None,
                   ip: str | None = None, search: str | None = None):
        limit = min(max(1, limit), 200)
        offset = max(0, offset)
        rows = db.query_events(db_path, site_id, limit=limit, offset=offset,
                               category=category, action=action, severity=severity,
                               ip=ip, search=search)
        total = db.count_events(db_path, site_id, category=category, action=action,
                                severity=severity, ip=ip, search=search)
        return JSONResponse({
            "events": [describe_event(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }, headers={"Cache-Control": "no-store"})

    @router.get("/api/export")
    def api_export(format: str = "csv"):
        import csv
        import io
        from fastapi.responses import Response
        rows = db.query_events(db_path, site_id, limit=5000, offset=0)
        if format.lower() == "json":
            return Response(
                content=json.dumps([describe_event(r) for r in rows], indent=2),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="guard_events_{site_id}.json"',
                         "Cache-Control": "no-store"}
            )
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Timestamp", "IP", "Method", "Path", "Category", "Rule", "Severity", "Score", "Action", "Evidence"])
        for r in rows:
            writer.writerow([r.get("id"), r.get("ts"), r.get("ip"), r.get("method"), r.get("path"),
                             r.get("category"), r.get("rule_id"), r.get("severity"), r.get("score"),
                             r.get("action"), r.get("evidence")])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="guard_events_{site_id}.csv"',
                     "Cache-Control": "no-store"}
        )

    @router.post("/api/chat")
    async def api_chat(request: Request):
        try:
            body = await request.json()
            message = str(body.get("message", "")).strip()
        except Exception:
            message = ""
        ans = copilot.ask_copilot(message or "summary", site_id, db_path)
        return JSONResponse(ans, headers={"Cache-Control": "no-store"})

    @router.get("/api/firewall-rules")
    def api_firewall_rules(format: str = "iptables"):
        rows = db.query_events(db_path, site_id, limit=200, action="blocked")
        ips = sorted({r["ip"] for r in rows if r.get("ip") and r["ip"] != "unknown"})
        fmt_clean = format.lower().strip()
        if fmt_clean == "ufw":
            lines = [f"ufw deny from {ip} to any comment 'Guard IDS blocked'" for ip in ips]
        elif fmt_clean == "nginx":
            lines = [f"deny {ip};" for ip in ips]
        elif fmt_clean == "cloudflare":
            lines = [json.dumps({"mode": "block", "configuration": {"target": "ip", "value": ip}, "notes": "Guard IDS"}) for ip in ips]
        else:
            lines = [f"iptables -A INPUT -s {ip} -j DROP" for ip in ips]
        return JSONResponse({"format": fmt_clean, "count": len(ips), "ips": ips, "rules": "\n".join(lines)},
                            headers={"Cache-Control": "no-store"})

    @router.get("/api/alerts")
    def api_get_alerts():
        return JSONResponse(_local_alerts, headers={"Cache-Control": "no-store"})

    @router.post("/api/alerts")
    async def api_save_alerts(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        _local_alerts["webhook_url"] = str(body.get("webhook_url", "")).strip()
        _local_alerts["telegram_bot_token"] = str(body.get("telegram_bot_token", "")).strip()
        _local_alerts["telegram_chat_id"] = str(body.get("telegram_chat_id", "")).strip()
        if "alert_min_score" in body:
            try:
                _local_alerts["alert_min_score"] = int(body["alert_min_score"])
            except Exception:
                pass
        return JSONResponse({"ok": True, "alerts": _local_alerts}, headers={"Cache-Control": "no-store"})

    @router.post("/api/alerts/test")
    async def api_test_alerts(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        cfg = {
            "webhook_url": body.get("webhook_url") or _local_alerts.get("webhook_url"),
            "telegram_bot_token": body.get("telegram_bot_token") or _local_alerts.get("telegram_bot_token"),
            "telegram_chat_id": body.get("telegram_chat_id") or _local_alerts.get("telegram_chat_id"),
        }
        res = alerts.send_test_notification(cfg, site_name=site_id)
        return JSONResponse(res, headers={"Cache-Control": "no-store"})

    @router.get("/stream")
    async def stream():
        return StreamingResponse(
            sse_messages(db_path, site_id, mode), media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    return router
