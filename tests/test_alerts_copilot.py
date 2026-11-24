from contextlib import closing
import os
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ids import alerts, copilot, db
from ids import platform_db as pdb
from ids.dashboard import create_dashboard_router
from ids.middleware import IDSMiddleware
from ids.platform_app import create_app


# ================================================================ alerts unit tests
def test_cooldown_mechanism():
    site = "site_cooldown_test"
    cat = "sql_injection"
    alerts._COOLDOWNS.clear()

    # First check: not on cooldown
    assert not alerts.is_on_cooldown(site, cat, cooldown_seconds=60)

    # Immediately after: on cooldown
    assert alerts.is_on_cooldown(site, cat, cooldown_seconds=60)

    # Different category: not on cooldown
    assert not alerts.is_on_cooldown(site, "xss", cooldown_seconds=60)

    # Different site: not on cooldown
    assert not alerts.is_on_cooldown("site2", cat, cooldown_seconds=60)


def test_build_alert_message():
    ev = {
        "category": "sql_injection",
        "ip": "1.2.3.4",
        "method": "POST",
        "path": "/login",
        "severity": "high",
        "score": 85,
        "action": "blocked",
        "evidence": "' OR 1=1 --",
    }
    msg = alerts.build_alert_message("My Store", ev)
    assert "[HIGH]" in msg
    assert "My Store" in msg
    assert "1.2.3.4" in msg
    assert "POST /login" in msg
    assert "Action: BLOCKED" in msg


def test_notify_event_skips_when_disabled_or_low_score():
    ev = {"category": "probe", "score": 30, "severity": "low"}
    with patch("ids.alerts.dispatch_alert") as mock_dispatch:
        # Score below min_score
        alerts.notify_event("Shop", "s1", ev, {"webhook_url": "https://example.com/webhook", "alert_min_score": 70})
        mock_dispatch.assert_not_called()

        # No webhooks configured
        alerts.notify_event("Shop", "s1", {"category": "probe", "score": 90}, {"webhook_url": ""})
        mock_dispatch.assert_not_called()


def test_dispatch_alert_discord_webhook():
    alerts._COOLDOWNS.clear()
    with patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.read.return_value = b""
        mock_url.return_value.__enter__.return_value = mock_resp

        res = alerts.dispatch_alert(
            "Test Alert Message",
            {"webhook_url": "https://discord.com/api/webhooks/123/xyz"},
        )
        assert len(res) == 1
        assert res[0]["channel"] == "discord"
        assert res[0]["ok"] is True
        assert mock_url.called


def test_dispatch_alert_telegram():
    alerts._COOLDOWNS.clear()
    with patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok": true}'
        mock_url.return_value.__enter__.return_value = mock_resp

        res = alerts.dispatch_alert(
            "Test Alert Message",
            {"telegram_bot_token": "123:abc", "telegram_chat_id": "456"},
        )
        assert len(res) == 1
        assert res[0]["channel"] == "telegram"
        assert res[0]["ok"] is True


def test_send_test_notification():
    with patch("ids.alerts.send_slack_or_webhook", return_value=True):
        res = alerts.send_test_notification({"webhook_url": "https://example.com/webhook"}, site_name="Demo")
        assert res["ok"] is True
        assert len(res["results"]) == 1
        assert res["results"][0]["ok"] is True


# ================================================================ copilot unit tests
def test_copilot_remediation_knowledge_base():
    ans_sql = copilot.ask_copilot("How do I fix SQL injection in FastAPI?", "demo")
    assert "FastAPI" in ans_sql["reply"] or "SQLAlchemy" in ans_sql["reply"]
    assert "remediation" in ans_sql["sources_used"]

    ans_xss = copilot.ask_copilot("How to prevent XSS in Flask or Django?", "demo")
    assert "XSS" in ans_xss["reply"] or "Jinja2" in ans_xss["reply"] or "autoescaping" in ans_xss["reply"]

    ans_trav = copilot.ask_copilot("How do I stop path traversal attacks?", "demo")
    assert "Path Traversal" in ans_trav["reply"] or "resolve" in ans_trav["reply"] or "os.path" in ans_trav["reply"]

    ans_brute = copilot.ask_copilot("How to mitigate brute force logins?", "demo")
    assert "Brute Force" in ans_brute["reply"] or "Rate Limiting" in ans_brute["reply"]


def test_copilot_database_investigation():
    tmp = tempfile.mktemp(suffix=".db")
    db.init_db(tmp)
    with closing(db.connect(tmp)) as conn, conn:
        conn.execute(
            "INSERT INTO events (site_id, ts, ip, method, path, category, rule_id, rules, "
            "severity, score, location, evidence, user_agent, action) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("site_test", time.time(), "198.51.100.5", "POST", "/admin", "credential_stuffing",
             "BEH-003", "BEH-003", "critical", 95, "body", "admin/admin", "python-requests", "blocked"),
        )

    ans_ip = copilot.ask_copilot("Why was 198.51.100.5 blocked?", "site_test", db_path=tmp)
    assert "198.51.100.5" in ans_ip["reply"]
    assert "database_events" in ans_ip["sources_used"]

    ans_sum = copilot.ask_copilot("Summarize security posture", "site_test", db_path=tmp)
    assert "summary" in ans_sum["sources_used"]
    assert "Threats detected" in ans_sum["reply"] or "Security Posture" in ans_sum["reply"]

    if os.path.exists(tmp):
        os.remove(tmp)


# ================================================================ platform endpoints
@pytest.fixture
def platform_env():
    path = tempfile.mktemp(suffix=".db")
    pdb.init(path)
    app = create_app(path, cookie_secure=False)
    yield app, path
    if os.path.exists(path):
        os.remove(path)


def test_platform_alerts_and_copilot_endpoints(platform_env):
    app, db_path = platform_env
    client = TestClient(app)

    with patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok": true}'
        mock_url.return_value.__enter__.return_value = mock_resp

        # 1. Sign up
        r = client.post("/api/signup", json={"email": "analyst@example.com", "password": "securepassword123"})
        assert r.status_code == 200
        csrf = r.json()["csrf"]
        auth_headers = {"X-CSRF-Token": csrf}

        # 2. Create site
        r_site = client.post("/api/sites", json={"name": "Prod Web", "domain": "prod.example.com"}, headers=auth_headers)
        assert r_site.status_code == 201
        site = r_site.json()["site"]
        site_id = site["id"]
        api_key = r_site.json()["api_key"]

        # 3. Configure Alerts
        r_alert = client.post(
            f"/app/sites/{site_id}/api/alerts",
            json={
                "webhook_url": "https://discord.com/api/webhooks/test",
                "telegram_bot_token": "token123",
                "telegram_chat_id": "chat456",
                "alert_min_score": 80,
            },
            headers=auth_headers,
        )
        assert r_alert.status_code == 200
        assert r_alert.json()["ok"] is True

        # 4. Get Alerts
        r_get_alert = client.get(f"/app/sites/{site_id}/api/alerts")
        assert r_get_alert.status_code == 200
        cfg = r_get_alert.json()
        assert cfg["webhook_url"] == "https://discord.com/api/webhooks/test"
        assert cfg["telegram_chat_id"] == "chat456"
        assert cfg["alert_min_score"] == 80

        # 5. Test Alerts
        r_test_alert = client.post(f"/app/sites/{site_id}/api/alerts/test", headers=auth_headers)
        assert r_test_alert.status_code == 200
        assert r_test_alert.json()["ok"] is True

        # 6. Ask Copilot via Platform endpoint
        r_chat = client.post(
            f"/app/sites/{site_id}/api/chat",
            json={"message": "How do I fix SQL injection in FastAPI?"},
            headers=auth_headers,
        )
        assert r_chat.status_code == 200
        chat_resp = r_chat.json()
        assert "reply" in chat_resp
        assert "FastAPI" in chat_resp["reply"] or "SQLAlchemy" in chat_resp["reply"]

        # 7. Test Probe
        r_probe = client.post(f"/app/sites/{site_id}/api/test-probe", headers=auth_headers)
        assert r_probe.status_code == 200
        assert r_probe.json()["ok"] is True
        assert "connected" in r_probe.json()

        # Ingest a blocked event to test firewall rules
        now = time.time()
        r_ingest = client.post(
            "/api/v1/events",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "mode": "block",
                "requests": [{"ts": now, "ip": "203.0.113.42", "method": "GET", "path": "/etc/passwd", "status": 403, "flagged": True, "blocked": True}],
                "events": [{
                    "ts": now, "ip": "203.0.113.42", "method": "GET", "path": "/etc/passwd",
                    "category": "path_traversal", "rule_id": "TRAV-001", "rules": "TRAV-001",
                    "severity": "critical", "score": 90, "location": "path",
                    "evidence": "../etc/passwd", "user_agent": "curl/7.68.0", "action": "blocked"
                }],
            },
        )
        assert r_ingest.status_code == 200

        # 8. Firewall rules export (iptables, ufw, nginx, cloudflare)
        for fmt in ("iptables", "ufw", "nginx", "cloudflare"):
            r_fw = client.get(f"/app/sites/{site_id}/api/firewall-rules?format={fmt}")
            assert r_fw.status_code == 200
            data = r_fw.json()
            assert data["format"] == fmt
            assert "203.0.113.42" in data["rules"]


# ================================================================ dashboard endpoints
def test_standalone_dashboard_chat_and_firewall(tmp_path):
    db_file = str(tmp_path / "standalone.db")
    db.init_db(db_file)
    now = time.time()
    with closing(db.connect(db_file)) as conn, conn:
        conn.execute(
            "INSERT INTO events (site_id, ts, ip, method, path, category, rule_id, rules, "
            "severity, score, location, evidence, user_agent, action) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("demo", now, "198.51.100.99", "GET", "/.env", "probe",
             "PROBE-001", "PROBE-001", "high", 80, "path", "/.env", "scanner", "blocked"),
        )

    app = FastAPI()
    router = create_dashboard_router(db_file, site_id="demo")
    app.include_router(router, prefix="/ids")
    client = TestClient(app)

    # Copilot endpoint
    r_chat = client.post("/ids/api/chat", json={"message": "Why was 198.51.100.99 blocked?"})
    assert r_chat.status_code == 200
    assert "198.51.100.99" in r_chat.json()["reply"]

    # Firewall rules
    r_fw = client.get("/ids/api/firewall-rules?format=iptables")
    assert r_fw.status_code == 200
    assert "198.51.100.99" in r_fw.json()["rules"]

    # Alerts save & get in standalone
    r_save = client.post("/ids/api/alerts", json={"webhook_url": "https://hooks.slack.com/services/xyz"})
    assert r_save.status_code == 200
    assert r_save.json()["ok"] is True

    r_get = client.get("/ids/api/alerts")
    assert r_get.status_code == 200
    assert r_get.json()["webhook_url"] == "https://hooks.slack.com/services/xyz"


# ================================================================ middleware allowlist_ips
def test_middleware_allowlist_ips(tmp_path):
    db_file = str(tmp_path / "allowlist.db")
    db.init_db(db_file)

    app = FastAPI()
    app.add_middleware(
        IDSMiddleware,
        db_path=db_file,
        site_id="demo",
        mode="block",
        trust_proxy=True,
        allowlist_ips=["192.168.1.100", "testclient"],
    )

    @app.get("/search")
    def search(q: str):
        return {"q": q}

    client = TestClient(app)

    # Attack payload from allowlisted client IP ("testclient") -> allowed!
    r = client.get("/search?q=' OR 1=1 --")
    assert r.status_code == 200

    # Attack payload from trusted allowlisted header IP -> allowed!
    r2 = client.get("/search?q=' OR 1=1 --", headers={"X-Forwarded-For": "192.168.1.100"})
    assert r2.status_code == 200

    # Attack payload from non-allowlisted IP -> blocked with 403!
    r3 = client.get("/search?q=' OR 1=1 --", headers={"X-Forwarded-For": "203.0.113.88"})
    assert r3.status_code == 403
