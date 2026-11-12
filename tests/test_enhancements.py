import csv
import io
import time
from fastapi.testclient import TestClient

from ids import db
from ids.platform_app import create_app
from ids.rules import Finding, inspect_request

PASSWORD = "correct horse battery"


def test_sql_comment_splitting_evasion_is_detected():
    # Attackers split keywords with comments: SEL/**/ECT or UN/**/ION
    findings = inspect_request("GET", "/search", "q=1+UN/**/ION+SEL/**/ECT+1,2", {}, "")
    rule_ids = {f.rule_id for f in findings}
    assert "SQLI-003" in rule_ids


def test_command_injection_with_newline_is_detected():
    findings = inspect_request("GET", "/ping", "host=127.0.0.1%0acat+/etc/passwd", {}, "")
    rule_ids = {f.rule_id for f in findings}
    assert "CMD-001" in rule_ids


def test_path_traversal_forward_slash_windows():
    findings = inspect_request("GET", "/files", "name=c:/windows/system32", {}, "")
    rule_ids = {f.rule_id for f in findings}
    assert "PT-002" in rule_ids


def test_probe_in_query_parameter_is_detected():
    findings = inspect_request("GET", "/download", "file=.env", {}, "")
    rule_ids = {f.rule_id for f in findings}
    assert "PROBE-002" in rule_ids


def test_query_events_and_filtering(tmp_path):
    db_path = str(tmp_path / "test.db")
    db.init_db(db_path)
    now = time.time()
    f1 = Finding("SQLI-001", "sql_injection", "high", 75, "desc", "query", "' or 1=1")
    f2 = Finding("XSS-001", "xss", "high", 75, "desc", "query", "<script>")

    db.log_event(db_path, "s1", "10.0.0.1", "GET", "/search", [f1], 75, "detected", ts=now - 10)
    db.log_event(db_path, "s1", "10.0.0.2", "POST", "/submit", [f2], 75, "blocked", ts=now - 5)

    # Filter by category
    sqli = db.query_events(db_path, "s1", category="sql_injection")
    assert len(sqli) == 1 and sqli[0]["category"] == "sql_injection"

    # Filter by action
    blocked = db.query_events(db_path, "s1", action="blocked")
    assert len(blocked) == 1 and blocked[0]["action"] == "blocked"

    # Search filter
    matched = db.query_events(db_path, "s1", search="10.0.0.2")
    assert len(matched) == 1 and matched[0]["ip"] == "10.0.0.2"

    assert db.count_events(db_path, "s1") == 2
    assert db.count_events(db_path, "s1", action="blocked") == 1


def test_platform_events_and_export_endpoints(tmp_path):
    db_path = str(tmp_path / "g.db")
    app = create_app(db_path)
    client = TestClient(app)

    # Sign up and add site
    r = client.post("/api/signup", json={"email": "alice@example.com", "password": PASSWORD})
    csrf = r.json()["csrf"]
    r = client.post("/api/sites", json={"name": "Blog"}, headers={"X-CSRF-Token": csrf})
    site_id = r.json()["site"]["id"]
    api_key = r.json()["api_key"]

    # Ingest one event
    client.post("/api/v1/events", headers={"Authorization": f"Bearer {api_key}"}, json={
        "mode": "block",
        "requests": [{"ts": time.time(), "ip": "1.2.3.4", "method": "GET", "path": "/foo", "status": 403, "flagged": True, "blocked": True}],
        "events": [{
            "ts": time.time(), "ip": "1.2.3.4", "method": "GET", "path": "/foo",
            "category": "sql_injection", "rule_id": "SQLI-001", "rules": "SQLI-001",
            "severity": "high", "score": 75, "location": "query", "evidence": "' or 1=1",
            "user_agent": "curl", "action": "blocked"
        }]
    })

    # Test GET /api/events
    r = client.get(f"/app/sites/{site_id}/api/events?action=blocked")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 1
    assert data["events"][0]["ip"] == "1.2.3.4"

    # Test CSV export
    r_csv = client.get(f"/app/sites/{site_id}/api/export?format=csv")
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]
    reader = csv.reader(io.StringIO(r_csv.text))
    rows = list(reader)
    assert len(rows) == 2  # header + 1 event
    assert rows[1][2] == "1.2.3.4"

    # Test JSON export
    r_json = client.get(f"/app/sites/{site_id}/api/export?format=json")
    assert r_json.status_code == 200
    assert "application/json" in r_json.headers["content-type"]
    assert len(r_json.json()) == 1

