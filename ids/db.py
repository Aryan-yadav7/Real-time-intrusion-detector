"""SQLite storage for requests and detected threats.

Privacy rule: we store the path (never the query string), a short redacted
evidence snippet, and the IP/User-Agent. We never store bodies, cookies or
passwords.
"""
from __future__ import annotations

import sqlite3
import time
from contextlib import closing

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id   TEXT    NOT NULL DEFAULT 'demo',
    ts        REAL    NOT NULL,
    ip        TEXT,
    method    TEXT,
    path      TEXT,
    status    INTEGER,
    flagged   INTEGER NOT NULL DEFAULT 0,
    blocked   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_requests_site_ts ON requests(site_id, ts);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id    TEXT    NOT NULL DEFAULT 'demo',
    ts         REAL    NOT NULL,
    ip         TEXT,
    method     TEXT,
    path       TEXT,
    category   TEXT,
    rule_id    TEXT,
    rules      TEXT,
    severity   TEXT,
    score      INTEGER,
    location   TEXT,
    evidence   TEXT,
    user_agent TEXT,
    action     TEXT NOT NULL            -- 'detected' or 'blocked'
);
CREATE INDEX IF NOT EXISTS idx_events_site_ts ON events(site_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Upgrade a database created by an older version (Day 1 had no 'blocked' column)."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(requests)")}
    if "blocked" not in cols:
        conn.execute("ALTER TABLE requests ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0")
        conn.execute("UPDATE requests SET blocked = 1 WHERE flagged = 1 AND status IN (403, 429)")


def init_db(db_path: str) -> None:
    with closing(connect(db_path)) as conn, conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        _migrate(conn)


# ----------------------------------------------------------------------------
# Writing
# ----------------------------------------------------------------------------
def log_request(db_path, site_id, ip, method, path, status, flagged,
                blocked=False, ts=None) -> None:
    with closing(connect(db_path)) as conn, conn:
        conn.execute(
            "INSERT INTO requests (site_id, ts, ip, method, path, status, flagged, blocked) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (site_id, ts or time.time(), ip, method, path, status, int(flagged), int(blocked)),
        )


def log_event(db_path, site_id, ip, method, path, findings, score, action,
              user_agent="", ts=None) -> None:
    """One row per flagged request (or behavior alert), describing its most severe finding."""
    top = findings[0]
    rules = ",".join(sorted({f.rule_id for f in findings}))
    with closing(connect(db_path)) as conn, conn:
        conn.execute(
            "INSERT INTO events (site_id, ts, ip, method, path, category, rule_id, rules, "
            "severity, score, location, evidence, user_agent, action) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (site_id, ts or time.time(), ip, method, path, top.category, top.rule_id,
             rules, top.severity, score, top.location, top.evidence,
             (user_agent or "")[:200], action),
        )


# ----------------------------------------------------------------------------
# Reading (used by the dashboard). Every query is filtered by site_id: this is
# what keeps one site's data separate from another's once there are many users.
# ----------------------------------------------------------------------------
def _scope(site_id, since):
    """WHERE-clause pieces shared by all queries."""
    return "(? IS NULL OR site_id = ?) AND ts >= ?", (site_id, site_id, since or 0)


def recent_events(db_path, site_id=None, limit=50, since=None) -> list[dict]:
    where, params = _scope(site_id, since)
    with closing(connect(db_path)) as conn:
        rows = conn.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY ts DESC, id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def query_events(db_path, site_id=None, limit=50, offset=0, since=None,
                 category=None, action=None, severity=None, ip=None, search=None) -> list[dict]:
    clauses = ["(? IS NULL OR site_id = ?)", "ts >= ?"]
    params: list = [site_id, site_id, since or 0]
    if category:
        clauses.append("category = ?")
        params.append(category)
    if action:
        clauses.append("action = ?")
        params.append(action)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if ip:
        clauses.append("ip LIKE ?")
        params.append(f"%{ip}%")
    if search:
        clauses.append("(ip LIKE ? OR path LIKE ? OR evidence LIKE ? OR rule_id LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term, term, term])

    where = " AND ".join(clauses)
    params.extend([limit, offset])
    with closing(connect(db_path)) as conn:
        rows = conn.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def count_events(db_path, site_id=None, since=None, category=None, action=None,
                 severity=None, ip=None, search=None) -> int:
    clauses = ["(? IS NULL OR site_id = ?)", "ts >= ?"]
    params: list = [site_id, site_id, since or 0]
    if category:
        clauses.append("category = ?")
        params.append(category)
    if action:
        clauses.append("action = ?")
        params.append(action)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if ip:
        clauses.append("ip LIKE ?")
        params.append(f"%{ip}%")
    if search:
        clauses.append("(ip LIKE ? OR path LIKE ? OR evidence LIKE ? OR rule_id LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term, term, term])

    where = " AND ".join(clauses)
    with closing(connect(db_path)) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]


def summary(db_path, site_id=None, since=None) -> dict:
    where, params = _scope(site_id, since)
    with closing(connect(db_path)) as conn:
        total, blocked = conn.execute(
            f"SELECT COUNT(*), COALESCE(SUM(blocked), 0) FROM requests WHERE {where}", params
        ).fetchone()
        threats = conn.execute(
            f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]
    return {"requests": total, "threats": threats, "blocked": int(blocked)}


def threat_counts(db_path, site_id, since, high_score=70, behavior_categories=()) -> dict:
    """Counts used to decide the green/yellow/red banner."""
    where, params = _scope(site_id, since)
    marks = ",".join("?" for _ in behavior_categories) or "NULL"
    with closing(connect(db_path)) as conn:
        total, high, behavior, blocked = conn.execute(
            f"SELECT COUNT(*), "
            f"COALESCE(SUM(score >= ?), 0), "
            f"COALESCE(SUM(category IN ({marks})), 0), "
            f"COALESCE(SUM(action = 'blocked'), 0) "
            f"FROM events WHERE {where}",
            (high_score, *behavior_categories, *params),
        ).fetchone()
    return {"total": total, "high": int(high), "behavior": int(behavior), "blocked": int(blocked)}


def category_counts(db_path, site_id, since) -> list[tuple[str, int]]:
    where, params = _scope(site_id, since)
    with closing(connect(db_path)) as conn:
        rows = conn.execute(
            f"SELECT category, COUNT(*) AS n FROM events WHERE {where} "
            f"GROUP BY category ORDER BY n DESC, category", params).fetchall()
    return [(r["category"], r["n"]) for r in rows]


def top_sources(db_path, site_id, since, limit=5) -> list[dict]:
    """Addresses with the most threats, and the kind of threat each one mostly caused."""
    where, params = _scope(site_id, since)
    with closing(connect(db_path)) as conn:
        rows = conn.execute(
            f"SELECT ip, category, COUNT(*) AS n FROM events WHERE {where} "
            f"GROUP BY ip, category", params).fetchall()
    per_ip: dict[str, dict] = {}
    for r in rows:
        entry = per_ip.setdefault(r["ip"], {"ip": r["ip"], "count": 0, "top": ("", 0)})
        entry["count"] += r["n"]
        if r["n"] > entry["top"][1]:
            entry["top"] = (r["category"], r["n"])
    ranked = sorted(per_ip.values(), key=lambda e: (-e["count"], e["ip"] or ""))[:limit]
    return [{"ip": e["ip"], "count": e["count"], "top_category": e["top"][0]} for e in ranked]


def timeline(db_path, site_id, minutes=60, now=None) -> list[dict]:
    """Per-minute counts of requests and threats for the last `minutes` minutes."""
    now = now if now is not None else time.time()
    end = int(now // 60)
    start = end - minutes + 1
    where, params = _scope(site_id, start * 60)
    with closing(connect(db_path)) as conn:
        req = dict(conn.execute(
            f"SELECT CAST(ts / 60 AS INTEGER) AS m, COUNT(*) FROM requests WHERE {where} "
            f"GROUP BY m", params).fetchall())
        thr = dict(conn.execute(
            f"SELECT CAST(ts / 60 AS INTEGER) AS m, COUNT(*) FROM events WHERE {where} "
            f"GROUP BY m", params).fetchall())
    return [{"t": m * 60, "requests": req.get(m, 0), "threats": thr.get(m, 0)}
            for m in range(start, end + 1)]


def max_event_id(db_path, site_id=None) -> int:
    with closing(connect(db_path)) as conn:
        return conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM events WHERE (? IS NULL OR site_id = ?)",
            (site_id, site_id)).fetchone()[0]
