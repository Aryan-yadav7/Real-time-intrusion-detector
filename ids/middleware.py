"""ASGI middleware that inspects every HTTP request before the app sees it.

Works with any ASGI app (FastAPI, Starlette, Django-ASGI...). Two kinds of detection:

  payload rules   look inside ONE request (SQL injection, XSS, ...)       ids/rules.py
  behavior        look at the PATTERN of requests from one IP             ids/behavior.py

Modes:
  detect - log threats, let every request through (safe default)
  block  - reject a request with 403 when its payload score >= block_threshold,
           and reject every request from an IP with an active behavior alert
           (flood / brute force / stuffing) with 429 until the alert expires

The IDS fails open: if inspection or logging crashes, the request still goes
through, so a bug in the IDS can never take the protected site down.
"""
from __future__ import annotations

import json
import logging
import posixpath
import time

from .behavior import BehaviorConfig, BehaviorTracker, extract_username
from .rules import inspect_request, risk_score
from .sinks import LocalSink

log = logging.getLogger("ids")

MAX_BUFFER = 1_000_000  # never hold more than ~1 MB of a request body in memory


class IDSMiddleware:
    def __init__(self, app, db_path: str = "ids.db", mode: str = "detect",
                 block_threshold: int = 70, site_id: str = "demo",
                 max_inspect_bytes: int = 65536, trust_proxy: bool = False,
                 exempt_prefixes: tuple = (), allowlist_ips: tuple = (),
                 behavior: bool = True, behavior_config: BehaviorConfig | None = None,
                 tracker: BehaviorTracker | None = None, sink=None):
        if mode not in ("detect", "block"):
            raise ValueError("mode must be 'detect' or 'block'")
        self.app = app
        self.db_path = db_path
        self.mode = mode
        self.block_threshold = block_threshold
        self.site_id = site_id
        self.max_inspect_bytes = max_inspect_bytes
        self.trust_proxy = trust_proxy
        self.exempt_prefixes = tuple(p.rstrip("/") for p in exempt_prefixes)
        self.allowlist_ips = set(allowlist_ips)
        self.tracker = tracker or (BehaviorTracker(behavior_config) if behavior else None)
        # Where results go: a local SQLite file (default) or, with the SDK, the Sentinel platform.
        self.sink = sink or LocalSink(db_path, site_id)

    # ------------------------------------------------------------------
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self._exempt(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        ip = self._client_ip(scope, headers)
        if ip in self.allowlist_ips:
            await self.app(scope, receive, send)
            return
        body_text, receive = await self._buffer_body(headers, receive)

        # 1. payload rules (one request on its own)
        started = time.perf_counter()
        try:
            raw_path = (scope.get("raw_path") or scope.get("path", "/").encode()).decode("latin-1")
            query = scope.get("query_string", b"").decode("latin-1")
            findings = inspect_request(scope["method"], raw_path, query, headers, body_text)
        except Exception:  # fail open
            log.exception("IDS inspection failed; letting request through")
            findings = []
        score = risk_score(findings)
        log.debug("inspected in %.2f ms, score=%s", (time.perf_counter() - started) * 1000, score)

        # 2. behavior (the pattern of requests from this IP)
        behavior_events: list = []   # (Finding, action) pairs to log as their own events
        active: dict = {}
        retry_after = 0
        if self.tracker:
            try:
                for f in self.tracker.on_request(ip):
                    behavior_events.append((f, self._action_for(f.score)))
                active = self.tracker.active_offenses(ip)
                retry_after = self.tracker.retry_after(ip)
            except Exception:
                log.exception("IDS behavior tracking failed; ignoring it for this request")

        payload_block = bool(findings) and self.mode == "block" and score >= self.block_threshold
        behavior_block = self.mode == "block" and any(s >= self.block_threshold for s in active.values())
        blocked = payload_block or behavior_block
        status = {"code": None}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        try:
            if blocked:
                if payload_block:
                    status["code"] = 403
                    await self._send_blocked(send, 403, "This request was blocked because it "
                                                        "looks like an attack.")
                else:
                    status["code"] = 429
                    await self._send_blocked(send, 429, "Too many suspicious requests from your "
                                                        "address. Please wait and try again.",
                                             retry_after)
            else:
                await self.app(scope, receive, send_wrapper)
                behavior_events += self._after_response(ip, scope, body_text, findings,
                                                        status["code"] or 500)
        finally:
            self._record(scope, headers, ip, findings, score, blocked,
                         status["code"] or 500, behavior_events, bool(active))

    # ------------------------------------------------------------------
    def _exempt(self, path: str) -> bool:
        """Paths the IDS skips (e.g. its own dashboard). `..` tricks are normalized first."""
        if not self.exempt_prefixes:
            return False
        norm = posixpath.normpath(path) if path else "/"
        return any(norm == p or norm.startswith(p + "/") for p in self.exempt_prefixes)

    def _client_ip(self, scope, headers) -> str:
        client = scope.get("client")
        ip = client[0] if client else "unknown"
        if self.trust_proxy:
            if "cf-connecting-ip" in headers:
                return headers["cf-connecting-ip"].strip()
            if "x-real-ip" in headers:
                return headers["x-real-ip"].strip()
            if "x-forwarded-for" in headers:
                parts = [p.strip() for p in headers["x-forwarded-for"].split(",") if p.strip()]
                if parts:
                    return parts[0]
        return ip

    def _action_for(self, score: int) -> str:
        return "blocked" if self.mode == "block" and score >= self.block_threshold else "detected"

    def _after_response(self, ip, scope, body_text, findings, status_code) -> list:
        """Behavior checks that need the response status (failed logins, 404s)."""
        if not self.tracker:
            return []
        try:
            method, path = scope["method"], scope.get("path", "/")
            username = None
            if method.upper() == "POST" and self.tracker.is_login_path(path):
                username = extract_username(body_text)
            probe = any(f.rule_id == "PROBE-001" for f in findings)
            found = self.tracker.on_response(ip, method, path, status_code,
                                             username=username, probe=probe)
            return [(f, self._action_for(f.score)) for f in found]
        except Exception:
            log.exception("IDS behavior tracking failed after response")
            return []

    async def _buffer_body(self, headers, receive):
        """Read the body so we can inspect it, then replay it to the app."""
        try:
            declared = int(headers.get("content-length", "0"))
        except ValueError:
            declared = 0
        if declared > MAX_BUFFER:
            return "", receive  # too large to buffer; body is not inspected

        messages, chunks, kept, total = [], [], 0, 0
        fully_read = False
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                fully_read = True
                break
            chunk = message.get("body", b"")
            total += len(chunk)
            if kept < self.max_inspect_bytes:
                piece = chunk[: self.max_inspect_bytes - kept]
                chunks.append(piece)
                kept += len(piece)
            if not message.get("more_body", False) or total > MAX_BUFFER:
                fully_read = not message.get("more_body", False)
                break

        async def replay():
            if messages:
                return messages.pop(0)
            if fully_read:
                return {"type": "http.request", "body": b"", "more_body": False}
            return await receive()  # rest of a very large body / disconnect

        return b"".join(chunks).decode("utf-8", errors="replace"), replay

    async def _send_blocked(self, send, status: int, message: str, retry_after: int = 0):
        payload = json.dumps({"error": "blocked_by_ids", "message": message}).encode()
        headers = [(b"content-type", b"application/json"),
                   (b"content-length", str(len(payload)).encode())]
        if retry_after:
            headers.append((b"retry-after", str(retry_after).encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})

    def _record(self, scope, headers, ip, findings, score, blocked, status_code,
                behavior_events, ip_under_alert):
        try:
            path = scope.get("path", "/")
            ua = headers.get("user-agent", "")
            flagged = bool(findings or behavior_events or (blocked and ip_under_alert))
            self.sink.request(ip, scope["method"], path, status_code, flagged, blocked)
            if findings:
                self.sink.event(ip, scope["method"], path, findings, score,
                                "blocked" if blocked else "detected", ua)
            for finding, action in behavior_events:
                self.sink.event(ip, scope["method"], path, [finding], finding.score, action, ua)
        except Exception:  # never break the site because logging failed
            log.exception("IDS could not write to the database")
