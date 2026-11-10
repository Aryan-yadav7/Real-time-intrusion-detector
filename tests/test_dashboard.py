import asyncio
import json
import re

from fastapi import FastAPI
from fastapi.testclient import TestClient

from ids import db
from ids.behavior import BEHAVIOR_CATEGORIES, KINDS
from ids.dashboard import create_dashboard_router, snapshot, sse_messages
from ids.messages import CATEGORY_INFO, describe_event
from ids.rules import RULES, Finding
from ids.status import compute_status

NOW = 1_800_000_030.0  # 30 s into a minute, so "a few seconds ago" lands in the same minute bucket


def finding(category="sql_injection", severity="high", score=75, evidence="' or 1=1"):
    return Finding("SQLI-001", category, severity, score, "d", "query", evidence)


def seed(tmp_path, events=(), requests=0, site="demo"):
    path = str(tmp_path / "d.db")
    db.init_db(path)
    for i in range(requests):
        db.log_request(path, site, "9.9.9.9", "GET", "/", 200, False, ts=NOW - i)
    for ts, f, action, ip in events:
        db.log_event(path, site, ip, "GET", "/search", [f], f.score, action, "ua", ts=ts)
    return path


# ------------------------------------------------------------- messages
def test_every_category_has_a_plain_language_message():
    categories = {r.category for r in RULES} | set(BEHAVIOR_CATEGORIES) | {v[1] for v in KINDS.values()}
    assert categories <= set(CATEGORY_INFO), categories - set(CATEGORY_INFO)


def test_event_is_described_in_plain_language():
    row = {"id": 1, "ts": NOW, "category": "sql_injection", "severity": "high", "action": "blocked",
           "ip": "1.2.3.4", "path": "/login", "rule_id": "SQLI-001", "rules": "SQLI-001", "score": 80,
           "method": "POST", "location": "body", "evidence": "'--", "user_agent": "x"}
    d = describe_event(row)
    assert "trick your database" in d["headline"]
    assert d["severity_label"] == "High risk" and d["level"] == "danger"
    assert d["action_text"] == "We blocked it."
    assert d["technical"]["type"] == "SQL injection"


def test_unknown_category_falls_back_gracefully():
    d = describe_event({"id": 1, "ts": NOW, "category": "brand_new", "severity": None, "action": None})
    assert d["headline"] and d["level"] == "warning"


# --------------------------------------------------------------- status
def counts(total=0, high=0, behavior=0, blocked=0):
    return dict(total=total, high=high, behavior=behavior, blocked=blocked)


def test_status_levels():
    assert compute_status(counts())["level"] == "ok"
    assert compute_status(counts(total=1))["level"] == "warning"
    assert compute_status(counts(total=4, high=4))["level"] == "warning"
    assert compute_status(counts(total=5, high=5))["level"] == "danger"
    assert compute_status(counts(total=1, behavior=1))["level"] == "danger"


def test_snapshot_status_follows_recent_events_only(tmp_path):
    old = [(NOW - 3600, finding(), "detected", "1.1.1.1")]
    assert snapshot(seed(tmp_path, old), "demo", now=NOW)["status"]["level"] == "ok"


def test_snapshot_red_for_flood_and_counts_blocked(tmp_path):
    flood = Finding("BEH-001", "flood", "high", 75, "d", "behavior", "100+ requests")
    events = [(NOW - 10, flood, "blocked", "1.1.1.1")]
    snap = snapshot(seed(tmp_path, events, requests=5), "demo", mode="block", now=NOW)
    assert snap["status"]["level"] == "danger"
    assert snap["mode"] == "block"


# ------------------------------------------------------------- snapshot
def test_snapshot_contents(tmp_path):
    events = [(NOW - 5, finding(), "detected", "1.1.1.1"),
              (NOW - 4, finding("xss", "high", 75), "detected", "1.1.1.1"),
              (NOW - 3, finding(), "detected", "2.2.2.2")]
    snap = snapshot(seed(tmp_path, events, requests=20), "demo", now=NOW)
    assert snap["totals"]["requests"] == 20 and snap["totals"]["threats"] == 3
    assert [k["label"] for k in snap["by_category"]][0] == "Database tricks"
    assert snap["top_sources"][0] == {"ip": "1.1.1.1", "count": 2, "top_category": "sql_injection",
                                      "top_label": "Database tricks"} or snap["top_sources"][0]["ip"] == "1.1.1.1"
    assert len(snap["timeline"]) == 60
    assert snap["timeline"][-1]["threats"] == 3
    assert snap["events"][0]["ts"] >= snap["events"][-1]["ts"]  # newest first
    json.dumps(snap)  # must be JSON-serializable


def test_snapshot_is_scoped_to_one_site(tmp_path):
    path = seed(tmp_path, [(NOW - 5, finding(), "detected", "1.1.1.1")], requests=3, site="mine")
    db.log_event(path, "other", "6.6.6.6", "GET", "/", [finding()], 75, "detected", ts=NOW - 1)
    db.log_request(path, "other", "6.6.6.6", "GET", "/", 200, True, ts=NOW - 1)
    mine = snapshot(path, "mine", now=NOW)
    assert mine["totals"] == {"requests": 3, "threats": 1, "blocked": 0}
    assert all(e["ip"] != "6.6.6.6" for e in mine["events"])
    assert all(s["ip"] != "6.6.6.6" for s in mine["top_sources"])
    other = snapshot(path, "other", now=NOW)
    assert other["totals"]["requests"] == 1


def test_timeline_puts_events_in_the_right_minute(tmp_path):
    path = seed(tmp_path, [(NOW - 125, finding(), "detected", "1.1.1.1")])
    line = db.timeline(path, "demo", 60, NOW)
    bucket = [p for p in line if p["threats"]][0]
    assert bucket["t"] == int((NOW - 125) // 60) * 60
    assert line[-1]["t"] == int(NOW // 60) * 60


# ------------------------------------------------------------ the page
def make_client(tmp_path, events=()):
    path = seed(tmp_path, events)
    app = FastAPI()
    app.include_router(create_dashboard_router(path, "demo", "detect"), prefix="/ids")
    return TestClient(app), path


def test_dashboard_page_has_strict_csp_and_matching_nonce(tmp_path):
    client, _ = make_client(tmp_path)
    r = client.get("/ids/")
    assert r.status_code == 200 and "Live Security Monitor" in r.text
    csp = r.headers["content-security-policy"]
    nonce = re.search(r"script-src 'nonce-([^']+)'", csp).group(1)
    assert f'nonce="{nonce}"' in r.text and "__NONCE__" not in r.text
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert client.get("/ids/").headers["content-security-policy"] != csp  # fresh nonce per request


def test_dashboard_never_writes_untrusted_text_as_html(tmp_path):
    """Attack payloads are shown on this page, so it must only use textContent."""
    client, _ = make_client(tmp_path)
    page = client.get("/ids/").text
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert banned not in page, banned
    assert " style=" not in page  # inline style attributes would be blocked by the CSP


def test_snapshot_endpoint_returns_attack_text_only_as_data(tmp_path):
    evil = finding(evidence="<script>alert(1)</script>")
    client, _ = make_client(tmp_path, [(NOW, evil, "detected", "1.1.1.1")])
    r = client.get("/ids/api/snapshot")
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["events"][0]["technical"]["evidence"] == "<script>alert(1)</script>"


# ------------------------------------------------------------------ SSE
def collect(gen):
    async def run():
        return [m async for m in gen]
    return asyncio.run(run())


def test_sse_stream_sends_valid_messages(tmp_path):
    path = seed(tmp_path, [(NOW, finding(), "detected", "1.1.1.1")])
    messages = collect(sse_messages(path, "demo", max_messages=1))
    assert messages[0].startswith("retry:")
    data = messages[1]
    assert data.startswith("data: ") and data.endswith("\n\n") and data.count("\n") == 2
    assert json.loads(data[len("data: "):])["events"]


def test_sse_sends_again_only_when_something_changed(tmp_path):
    path = seed(tmp_path)

    async def run():
        out, gen = [], sse_messages(path, "demo", interval=0.01, heartbeat=60, max_messages=2)
        async for message in gen:
            out.append(message)
            if len(out) == 2:  # first data message received: now cause a change
                db.log_event(path, "demo", "3.3.3.3", "GET", "/", [finding()], 75, "detected")
        return out

    out = asyncio.run(run())
    assert len(out) == 3
    assert json.loads(out[2][6:])["events"][0]["ip"] == "3.3.3.3"
