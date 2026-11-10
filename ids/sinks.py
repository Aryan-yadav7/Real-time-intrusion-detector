"""Where the middleware sends what it sees.

LocalSink   writes to a SQLite file next to the app (Day 1/2 behavior).
RemoteSink  ships batches to the Guard platform over HTTPS using an API key (Day 3).

RemoteSink design goals:
  * Never slow down or break the protected website: the request path only does
    a non-blocking queue.put; a background thread does all the network work.
  * Survive outages: failed batches are retried with backoff, memory is bounded,
    and when the buffer is full the OLDEST data is dropped (never the website).
  * Zero dependencies: only the standard library.
"""
from __future__ import annotations

import atexit
import collections
import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import db

log = logging.getLogger("ids.sdk")

SDK_VERSION = "python-0.1"
MAX_BATCH = 200  # must stay <= the platform's per-batch limits


class LocalSink:
    def __init__(self, db_path: str, site_id: str):
        self.db_path = db_path
        self.site_id = site_id
        db.init_db(db_path)

    def request(self, ip, method, path, status, flagged, blocked) -> None:
        db.log_request(self.db_path, self.site_id, ip, method, path, status, flagged, blocked)

    def event(self, ip, method, path, findings, score, action, user_agent) -> None:
        db.log_event(self.db_path, self.site_id, ip, method, path, findings, score, action,
                     user_agent)


def _urllib_post(url: str, headers: dict, body: bytes, timeout: float):
    """Default transport. Returns (status, response_headers). Network errors raise."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}


class RemoteSink:
    def __init__(self, api_key: str, server: str, mode: str = "detect",
                 flush_interval: float = 2.0, batch_size: int = MAX_BATCH,
                 max_queue: int = 10_000, timeout: float = 5.0,
                 post=None, start_thread: bool = True):
        if not api_key or not api_key.startswith("gk_"):
            raise ValueError("api_key looks wrong: it should start with 'gk_'")
        parsed = urlparse(server)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("server must be a full URL such as https://guard.example.com")
        self.url = server.rstrip("/") + "/api/v1/events"
        self.api_key = api_key
        self.mode = mode
        self.flush_interval = flush_interval
        self.batch_size = min(batch_size, MAX_BATCH)
        self.timeout = timeout
        self._post = post or _urllib_post
        self._q: queue.Queue = queue.Queue(maxsize=max_queue)
        self._retry: collections.deque = collections.deque(maxlen=20)  # failed payloads
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._retry_after = 0.0
        self._failures = 0
        self.auth_failed = False
        self.dropped = 0
        self.sent_requests = 0
        self.sent_events = 0
        self._thread = None
        if start_thread:
            self._thread = threading.Thread(target=self._run, name="guard-sender", daemon=True)
            self._thread.start()
            atexit.register(self.close)

    # ---- called from the website's request path: must be instant and never raise ----
    def request(self, ip, method, path, status, flagged, blocked) -> None:
        self._put({"k": "r", "ts": time.time(), "ip": str(ip)[:64], "method": str(method)[:10],
                   "path": str(path)[:300], "status": min(599, max(100, int(status))),
                   "flagged": bool(flagged), "blocked": bool(blocked)})

    def event(self, ip, method, path, findings, score, action, user_agent) -> None:
        top = findings[0]
        self._put({"k": "e", "ts": time.time(), "ip": str(ip)[:64], "method": str(method)[:10],
                   "path": str(path)[:300], "category": top.category, "rule_id": top.rule_id[:20],
                   "rules": ",".join(sorted({f.rule_id for f in findings}))[:200],
                   "severity": top.severity, "score": int(score), "location": top.location[:60],
                   "evidence": (top.evidence or "")[:200], "user_agent": (user_agent or "")[:200],
                   "action": action})

    def _put(self, item: dict) -> None:
        if self.auth_failed:
            return
        try:
            self._q.put_nowait(item)
        except queue.Full:
            self.dropped += 1

    # ---- background sending ----
    def _drain(self):
        requests, events = [], []
        while len(requests) + len(events) < self.batch_size:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            kind = item.pop("k")
            (requests if kind == "r" else events).append(item)
        if not requests and not events:
            return None
        return {"mode": self.mode, "sdk": SDK_VERSION, "requests": requests, "events": events}

    def _send(self, payload: dict) -> str:
        """Returns 'ok', 'drop' (do not retry) or 'retry'."""
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json",
                   "User-Agent": f"guard-sdk/{SDK_VERSION}"}
        try:
            status, response_headers = self._post(self.url, headers, body, self.timeout)
        except Exception as exc:  # network down, DNS, timeout...
            log.warning("Guard server unreachable (%s); will retry", exc)
            return "retry"
        if 200 <= status < 300:
            self.sent_requests += len(payload["requests"])
            self.sent_events += len(payload["events"])
            self._retry_after = 0.0
            return "ok"
        if status in (401, 403):
            self.auth_failed = True
            log.error("Guard rejected the API key (HTTP %s). Sending is disabled; detection "
                      "still runs locally. Check the key or rotate it.", status)
            return "drop"
        if status == 429:
            try:
                self._retry_after = min(60.0, max(1.0, float(response_headers.get("retry-after", 5))))
            except ValueError:
                self._retry_after = 5.0
            return "retry"
        if 400 <= status < 500:
            log.error("Guard refused a batch (HTTP %s); dropping it", status)
            return "drop"
        return "retry"

    def flush(self) -> bool:
        """Send everything that is queued. True when nothing is waiting for a retry."""
        with self._lock:
            while self._retry:
                if self._send(self._retry[0]) == "retry":
                    return False
                self._retry.popleft()
            while True:
                payload = self._drain()
                if payload is None:
                    return True
                if self._send(payload) == "retry":
                    if len(self._retry) == self._retry.maxlen:
                        self.dropped += 1  # the oldest failed payload is about to be pushed out
                    self._retry.append(payload)
                    return False

    def _run(self) -> None:
        delay = self.flush_interval
        while not self._stop.wait(delay):
            try:
                ok = self.flush()
            except Exception:
                log.exception("Guard sender crashed on a batch; continuing")
                ok = False
            if ok:
                self._failures, delay = 0, self.flush_interval
            else:
                self._failures += 1
                delay = max(self._retry_after, min(30.0, 2.0 ** self._failures))

    def close(self, timeout: float = 5.0) -> None:
        """Stop the background thread and make one last attempt to send what is left."""
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout)
        try:
            self.flush()
        except Exception:
            log.exception("Guard final flush failed")
