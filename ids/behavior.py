"""Behavior tracking: attacks that only show up as a pattern over time.

One request can look perfectly normal. Fifty of them in two seconds, or five
failed logins in a row, are not. The tracker keeps a short memory per IP
address (in RAM only, nothing is written to disk) and raises an alert when a
pattern crosses a threshold:

  flood                requests per few seconds from one IP is far too high
  brute_force          many failed logins in a minute
  credential_stuffing  failed logins with MANY DIFFERENT usernames
  scanning             one IP asks for many pages that do not exist / sensitive files

Alerts fire once, then stay "active" for a cooldown period. This does two jobs:
the dashboard gets one alert instead of thousands, and in block mode the IP
stays blocked while the alert is active.

Limits (be honest in interviews): the memory lives inside one Python process,
so running several worker processes means each keeps its own counts; a real
deployment would share the counters through Redis.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import parse_qs

from .rules import SEVERITY_SCORE, Finding

# kind -> (rule id, category, severity, description)
KINDS = {
    "flood": ("BEH-001", "flood", "high",
              "Far too many requests from one address in a few seconds"),
    "brute_force": ("BEH-002", "brute_force", "high",
                    "Repeated failed logins from one address"),
    "credential_stuffing": ("BEH-003", "credential_stuffing", "high",
                            "Failed logins using many different usernames from one address"),
    "scanning": ("BEH-004", "scanning", "medium",
                 "One address asking for many pages that do not exist or are sensitive"),
}
BEHAVIOR_CATEGORIES = tuple(KINDS)

USERNAME_KEYS = ("username", "user", "email", "login", "userid", "user_id")


@dataclass
class BehaviorConfig:
    flood_requests: int = 100       # this many requests ...
    flood_window: float = 10        # ... within this many seconds
    brute_failures: int = 5         # this many failed logins ...
    brute_window: float = 60        # ... within this many seconds
    stuffing_usernames: int = 5     # this many DIFFERENT usernames failing ...
    stuffing_window: float = 300    # ... within this many seconds
    scan_paths: int = 15            # this many different missing/sensitive paths ...
    scan_window: float = 60         # ... within this many seconds
    cooldown: float = 120           # alert stays active (and IP stays blocked) this long
    login_paths: tuple = ("/login", "/signin", "/sign-in", "/api/login", "/api/auth/login",
                          "/auth/login", "/admin/login", "/user/login", "/wp-login.php")
    login_fail_statuses: tuple = (400, 401, 403)
    max_tracked_ips: int = 10_000


def _finding(kind: str, evidence: str) -> Finding:
    rule_id, category, severity, description = KINDS[kind]
    return Finding(rule_id=rule_id, category=category, severity=severity,
                   score=SEVERITY_SCORE[severity], description=description,
                   location="behavior", evidence=evidence)


def extract_username(body_text: str) -> str | None:
    """Find a username-like field in a JSON or form body.

    The result is only ever hashed in memory; usernames are never stored.
    """
    if not body_text:
        return None
    try:
        data = json.loads(body_text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).lower() in USERNAME_KEYS and isinstance(value, (str, int)):
                return str(value)
        return None
    if isinstance(data, (list, str, int, float)):
        return None
    form = parse_qs(body_text, keep_blank_values=True)
    lowered = {k.lower(): v for k, v in form.items()}
    for key in USERNAME_KEYS:
        if lowered.get(key):
            return lowered[key][0]
    return None


def _hash(username: str) -> str:
    return hashlib.sha256(username.strip().lower().encode()).hexdigest()[:16]


class _State:
    """What we remember about one IP address."""
    __slots__ = ("requests", "failures", "misses", "alerts", "last_seen")

    def __init__(self, flood_requests: int):
        # maxlen keeps memory bounded even during a huge flood
        self.requests: deque = deque(maxlen=max(2, flood_requests))
        self.failures: deque = deque(maxlen=200)   # (time, username hash or None)
        self.misses: deque = deque(maxlen=200)     # (time, path)
        self.alerts: dict = {}                     # kind -> time the alert stops being active
        self.last_seen = 0.0


class BehaviorTracker:
    def __init__(self, config: BehaviorConfig | None = None, clock=time.time):
        self.config = config or BehaviorConfig()
        self.clock = clock
        self._states: dict[str, _State] = {}
        self._calls = 0

    # ------------------------------------------------------------------
    def is_login_path(self, path: str) -> bool:
        clean = path.lower().rstrip("/")
        if clean in self.config.login_paths:
            return True
        parts = clean.split("/")
        return bool(parts and parts[-1] in ("login", "signin", "sign-in", "token", "authenticate"))

    def on_request(self, ip: str, now: float | None = None) -> list[Finding]:
        """Call BEFORE the app runs. Detects floods."""
        now = self.clock() if now is None else now
        c = self.config
        st = self._state(ip, now)
        st.requests.append(now)
        self._housekeeping(now)
        full = len(st.requests) >= c.flood_requests
        if full and now - st.requests[0] <= c.flood_window and self._arm(st, "flood", now):
            return [_finding("flood", f"{c.flood_requests}+ requests in {c.flood_window:g} seconds")]
        return []

    def on_response(self, ip: str, method: str, path: str, status: int,
                    username: str | None = None, probe: bool = False,
                    now: float | None = None) -> list[Finding]:
        """Call AFTER the app answered. Detects failed logins and scanning."""
        now = self.clock() if now is None else now
        c = self.config
        st = self._state(ip, now)
        findings: list[Finding] = []

        if status == 404 or probe:
            st.misses.append((now, path))
            distinct = {p for t, p in st.misses if t >= now - c.scan_window}
            if len(distinct) >= c.scan_paths and self._arm(st, "scanning", now):
                findings.append(_finding(
                    "scanning", f"{len(distinct)} different missing/sensitive pages in "
                                f"{c.scan_window:g} seconds"))

        if method.upper() == "POST" and self.is_login_path(path) and status in c.login_fail_statuses:
            st.failures.append((now, _hash(username) if username else None))
            names = {h for t, h in st.failures if t >= now - c.stuffing_window and h}
            fails = sum(1 for t, _ in st.failures if t >= now - c.brute_window)
            if len(names) >= c.stuffing_usernames:
                if self._arm(st, "credential_stuffing", now):
                    findings.append(_finding(
                        "credential_stuffing",
                        f"failed logins with {len(names)} different usernames"))
            elif fails >= c.brute_failures and self._arm(st, "brute_force", now):
                findings.append(_finding(
                    "brute_force", f"{fails} failed logins in {c.brute_window:g} seconds"))
        return findings

    def active_offenses(self, ip: str, now: float | None = None) -> dict[str, int]:
        """Alerts still active for this IP, as {kind: score}."""
        now = self.clock() if now is None else now
        st = self._states.get(ip)
        if not st:
            return {}
        return {kind: SEVERITY_SCORE[KINDS[kind][2]]
                for kind, until in st.alerts.items() if until > now}

    def retry_after(self, ip: str, now: float | None = None) -> int:
        now = self.clock() if now is None else now
        st = self._states.get(ip)
        if not st:
            return 0
        remaining = [until - now for until in st.alerts.values() if until > now]
        return int(max(remaining, default=0)) + 1 if remaining else 0

    # ------------------------------------------------------------------
    def _state(self, ip: str, now: float) -> _State:
        st = self._states.get(ip)
        if st is None:
            st = self._states[ip] = _State(self.config.flood_requests)
        st.last_seen = now
        return st

    def _arm(self, st: _State, kind: str, now: float) -> bool:
        """Start an alert unless one is already active. True = this is a NEW alert."""
        if st.alerts.get(kind, 0) > now:
            return False
        st.alerts[kind] = now + self.config.cooldown
        return True

    def _housekeeping(self, now: float) -> None:
        """Forget quiet IPs so memory cannot grow without limit."""
        self._calls += 1
        c = self.config
        if self._calls % 500 and len(self._states) <= c.max_tracked_ips:
            return
        horizon = now - max(c.flood_window, c.brute_window, c.stuffing_window, c.scan_window) - 1
        for ip in [ip for ip, st in self._states.items()
                   if st.last_seen < horizon and not any(u > now for u in st.alerts.values())]:
            del self._states[ip]
        if len(self._states) > c.max_tracked_ips:  # still too many: drop the least recent
            keep = int(c.max_tracked_ips * 0.9)
            oldest = sorted(self._states, key=lambda ip: self._states[ip].last_seen)
            for ip in oldest[: len(self._states) - keep]:
                del self._states[ip]
