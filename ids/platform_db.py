"""Platform storage: users, sessions and sites (the tables Day 3 adds).

It lives in the same SQLite file as the requests/events tables from Day 1-2.

TENANT ISOLATION RULE: every function that reads or changes a site takes the
owner's user_id and puts it in the WHERE clause. There is no function that fetches
a site by id alone on behalf of a logged-in user, so a forgotten check cannot leak data.
"""
from __future__ import annotations

import secrets
import sqlite3
import time
from contextlib import closing

from . import auth, db

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS sites (
    id             TEXT PRIMARY KEY,
    user_id        INTEGER NOT NULL,
    name           TEXT NOT NULL,
    domain         TEXT NOT NULL DEFAULT '',
    api_key_hash   TEXT NOT NULL UNIQUE,
    api_key_prefix TEXT NOT NULL,
    created_at     REAL NOT NULL,
    last_seen      REAL,
    reported_mode  TEXT NOT NULL DEFAULT 'detect'
);
CREATE INDEX IF NOT EXISTS idx_sites_user ON sites(user_id);
"""

SITE_COLUMNS = "id, user_id, name, domain, api_key_prefix, created_at, last_seen, reported_mode"


class EmailTaken(Exception):
    pass


def init(db_path: str) -> None:
    db.init_db(db_path)  # requests + events tables (and migration)
    with closing(db.connect(db_path)) as conn, conn:
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------- users
def create_user(db_path, email: str, password_hash: str, now=None) -> int:
    try:
        with closing(db.connect(db_path)) as conn, conn:
            cur = conn.execute(
                "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, password_hash, now or time.time()))
            return cur.lastrowid
    except sqlite3.IntegrityError as exc:
        raise EmailTaken(email) from exc


def get_user_by_email(db_path, email: str) -> dict | None:
    with closing(db.connect(db_path)) as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return dict(row) if row else None


# ------------------------------------------------------------- sessions
def create_session(db_path, user_id: int, ttl: float, now=None) -> tuple[str, str]:
    """Returns (token, csrf). Only the token's hash is stored."""
    now = now or time.time()
    token, csrf = auth.new_token(), auth.new_token()
    with closing(db.connect(db_path)) as conn, conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)", (auth.sha256_hex(token), user_id, csrf, now, now + ttl))
    return token, csrf


def get_session(db_path, token: str, now=None) -> dict | None:
    if not token or len(token) > 200:
        return None
    with closing(db.connect(db_path)) as conn:
        row = conn.execute(
            "SELECT s.user_id, s.csrf_token, u.email FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?",
            (auth.sha256_hex(token), now or time.time())).fetchone()
    return {"user_id": row["user_id"], "csrf": row["csrf_token"], "email": row["email"]} if row else None


def delete_session(db_path, token: str) -> None:
    with closing(db.connect(db_path)) as conn, conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (auth.sha256_hex(token),))


# ---------------------------------------------------------------- sites
def count_sites(db_path, user_id: int) -> int:
    with closing(db.connect(db_path)) as conn:
        return conn.execute("SELECT COUNT(*) FROM sites WHERE user_id = ?", (user_id,)).fetchone()[0]


def create_site(db_path, user_id: int, name: str, domain: str, now=None) -> tuple[dict, str]:
    """Returns (site, api_key). The key is returned here and never retrievable again."""
    key, prefix, key_hash = auth.new_api_key()
    site_id = secrets.token_hex(8)
    now = now or time.time()
    with closing(db.connect(db_path)) as conn, conn:
        conn.execute(
            "INSERT INTO sites (id, user_id, name, domain, api_key_hash, api_key_prefix, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", (site_id, user_id, name, domain, key_hash, prefix, now))
    return get_site(db_path, user_id, site_id), key


def list_sites(db_path, user_id: int) -> list[dict]:
    with closing(db.connect(db_path)) as conn:
        rows = conn.execute(f"SELECT {SITE_COLUMNS} FROM sites WHERE user_id = ? "
                            "ORDER BY created_at, id", (user_id,)).fetchall()
    return [dict(r) for r in rows]


def get_site(db_path, user_id: int, site_id: str) -> dict | None:
    """The ONLY way a logged-in user reaches a site: id AND owner must both match."""
    with closing(db.connect(db_path)) as conn:
        row = conn.execute(f"SELECT {SITE_COLUMNS} FROM sites WHERE id = ? AND user_id = ?",
                           (site_id, user_id)).fetchone()
    return dict(row) if row else None


def rotate_key(db_path, user_id: int, site_id: str) -> str | None:
    key, prefix, key_hash = auth.new_api_key()
    with closing(db.connect(db_path)) as conn, conn:
        cur = conn.execute(
            "UPDATE sites SET api_key_hash = ?, api_key_prefix = ? WHERE id = ? AND user_id = ?",
            (key_hash, prefix, site_id, user_id))
    return key if cur.rowcount else None


def delete_site(db_path, user_id: int, site_id: str) -> bool:
    """Deletes the site AND all its recorded data, but only if this user owns it."""
    with closing(db.connect(db_path)) as conn, conn:
        cur = conn.execute("DELETE FROM sites WHERE id = ? AND user_id = ?", (site_id, user_id))
        if not cur.rowcount:
            return False
        conn.execute("DELETE FROM events WHERE site_id = ?", (site_id,))
        conn.execute("DELETE FROM requests WHERE site_id = ?", (site_id,))
    return True


# ------------------------------------------------------------ ingestion
def get_site_by_key(db_path, api_key: str) -> dict | None:
    """Used only by the ingestion API: the key identifies the site (and so the owner)."""
    with closing(db.connect(db_path)) as conn:
        row = conn.execute(f"SELECT {SITE_COLUMNS} FROM sites WHERE api_key_hash = ?",
                           (auth.sha256_hex(api_key),)).fetchone()
    return dict(row) if row else None


def touch_site(db_path, site_id: str, mode: str, now=None) -> None:
    with closing(db.connect(db_path)) as conn, conn:
        conn.execute("UPDATE sites SET last_seen = ?, reported_mode = ? WHERE id = ?",
                     (now or time.time(), mode, site_id))


def insert_batch(db_path, site_id: str, requests: list[dict], events: list[dict]) -> None:
    """site_id comes from the API key, never from the payload."""
    with closing(db.connect(db_path)) as conn, conn:
        conn.executemany(
            "INSERT INTO requests (site_id, ts, ip, method, path, status, flagged, blocked) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(site_id, r["ts"], r["ip"], r["method"], r["path"], r["status"],
              int(r["flagged"]), int(r["blocked"])) for r in requests])
        conn.executemany(
            "INSERT INTO events (site_id, ts, ip, method, path, category, rule_id, rules, severity, "
            "score, location, evidence, user_agent, action) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(site_id, e["ts"], e["ip"], e["method"], e["path"], e["category"], e["rule_id"],
              e["rules"], e["severity"], e["score"], e["location"], e["evidence"],
              e["user_agent"], e["action"]) for e in events])


def purge_old(db_path, days: float = 30, now=None) -> None:
    """Data retention: forget requests and events older than `days`."""
    cutoff = (now or time.time()) - days * 86400
    with closing(db.connect(db_path)) as conn, conn:
        conn.execute("DELETE FROM requests WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
