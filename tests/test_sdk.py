import json
import threading
import time

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from ids.platform_app import create_app
from ids.rules import Finding
from ids.sdk import SentinelMiddleware
from ids.sinks import RemoteSink

KEY = "sk_" + "a" * 40
SERVER = "http://sentinel.test"


def finding(category="sql_injection", severity="high", score=75, evidence="' or '1'='1"):
    return Finding("SQLI-001", category, severity, score, "d", "query", evidence)


class FakeServer:
    """Stands in for the network: records what was sent and answers with queued statuses."""

    def __init__(self, *statuses):
        self.statuses = list(statuses)
        self.bodies, self.headers = [], []

    def __call__(self, url, headers, body, timeout):
        self.bodies.append(json.loads(body))
        self.headers.append(headers)
        status = self.statuses.pop(0) if self.statuses else 200
        if isinstance(status, Exception):
            raise status
        if isinstance(status, tuple):
            return status[0], {k.lower(): v for k, v in status[1].items()}
        return status, {}


def sink(post, **kw):
    return RemoteSink(KEY, SERVER, post=post, start_thread=False, **kw)


def fill(s, requests=0, events=0):
    for _ in range(requests):
        s.request("1.1.1.1", "GET", "/", 200, False, False)
    for _ in range(events):
        s.event("1.1.1.1", "GET", "/search", [finding()], 80, "detected", "ua")


# ------------------------------------------------------------- batching
def test_payloads_are_batched_and_authenticated():
    fake = FakeServer()
    s = sink(fake)
    fill(s, requests=450)
    assert s.flush() is True
    assert [len(b["requests"]) for b in fake.bodies] == [200, 200, 50]
    assert fake.headers[0]["Authorization"] == f"Bearer {KEY}"
    assert fake.bodies[0]["sdk"].startswith("python-") and fake.bodies[0]["mode"] == "detect"
    assert s.sent_requests == 450


def test_event_payload_shape():
    fake = FakeServer()
    s = sink(fake)
    s.event("1.2.3.4", "POST", "/login", [finding(), finding("xss", "high", 75)], 80, "blocked", "agent")
    s.flush()
    e = fake.bodies[0]["events"][0]
    assert e["category"] == "sql_injection" and e["action"] == "blocked" and e["score"] == 80
    assert e["rules"] == "SQLI-001" and e["user_agent"] == "agent" and "k" not in e


def test_empty_queue_sends_nothing():
    fake = FakeServer()
    assert sink(fake).flush() is True and fake.bodies == []


# ------------------------------------------------------ failures & retries
def test_failed_batches_are_retried_not_lost():
    fake = FakeServer(500, 200)
    s = sink(fake)
    fill(s, requests=3, events=1)
    assert s.flush() is False and s.sent_requests == 0
    assert s.flush() is True
    assert s.sent_requests == 3 and s.sent_events == 1
    assert len(fake.bodies) == 2 and fake.bodies[0] == fake.bodies[1]     # same data, sent again


def test_network_errors_are_retried():
    fake = FakeServer(OSError("connection refused"), TimeoutError("slow"), 200)
    s = sink(fake)
    fill(s, requests=2)
    assert s.flush() is False and s.flush() is False and s.flush() is True
    assert s.sent_requests == 2


def test_rate_limit_response_is_honored():
    fake = FakeServer((429, {"Retry-After": "7"}), 200)
    s = sink(fake)
    fill(s, requests=1)
    assert s.flush() is False and s._retry_after == 7
    assert s.flush() is True and s._retry_after == 0


def test_bad_key_disables_sending_but_never_raises():
    fake = FakeServer(401)
    s = sink(fake)
    fill(s, requests=2)
    assert s.flush() is True and s.auth_failed
    fill(s, requests=5)
    assert s._q.qsize() == 0                       # nothing is queued any more
    assert len(fake.bodies) == 1


def test_rejected_payloads_are_dropped_instead_of_retried_forever():
    fake = FakeServer(422, 200)
    s = sink(fake)
    fill(s, requests=1)
    assert s.flush() is True and len(fake.bodies) == 1 and not s._retry


def test_full_queue_drops_new_data_instead_of_blocking_or_growing():
    s = sink(FakeServer(), max_queue=10)
    start = time.perf_counter()
    fill(s, requests=500)
    assert time.perf_counter() - start < 1.0
    assert s._q.qsize() == 10 and s.dropped == 490


def test_memory_stays_bounded_during_a_long_outage():
    fake = FakeServer(*([500] * 1000))
    s = sink(fake, max_queue=50)
    for _ in range(30):
        fill(s, requests=20, events=5)
        s.flush()
    assert s._q.qsize() <= 50 and len(s._retry) <= 20
    assert s.dropped > 0


def test_recording_never_raises_even_with_odd_input():
    fake = FakeServer()
    s = sink(fake)
    s.request("x" * 500, "M" * 50, "/p" * 500, 99999, 1, 0)   # oversized / out-of-range values
    s.flush()
    sent = fake.bodies[0]["requests"][0]
    assert len(sent["ip"]) == 64 and len(sent["method"]) == 10 and len(sent["path"]) == 300
    assert sent["status"] == 599 and sent["flagged"] is True


def test_constructor_validation():
    with pytest.raises(ValueError):
        RemoteSink("not-a-key", SERVER, start_thread=False)
    with pytest.raises(ValueError):
        RemoteSink(KEY, "ftp://nope", start_thread=False)
    with pytest.raises(ValueError):
        RemoteSink(KEY, "sentinel.example.com", start_thread=False)


def test_background_thread_delivers_and_close_flushes():
    fake = FakeServer()
    s = RemoteSink(KEY, SERVER, post=fake, flush_interval=0.05)
    fill(s, requests=3)
    deadline = time.time() + 3
    while s.sent_requests < 3 and time.time() < deadline:
        time.sleep(0.02)
    assert s.sent_requests == 3
    fill(s, events=1)
    s.close()
    assert s.sent_events == 1
    assert not any(t.name == "sentinel-sender" and t.is_alive() for t in threading.enumerate())


# ============================================== end to end with the platform
def transport(client):
    def post(url, headers, body, timeout):
        r = client.post("/api/v1/events", content=body, headers=headers)
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}
    return post


def customer_site(sink_obj, mode="detect"):
    app = FastAPI()

    @app.get("/search")
    def search(q: str = ""):
        return {"q": q}

    @app.post("/login")
    def login():
        return JSONResponse({"ok": False}, status_code=401)

    app.add_middleware(SentinelMiddleware, api_key=KEY, mode=mode, sink=sink_obj)
    return TestClient(app)


@pytest.fixture
def platform(tmp_path):
    app = create_app(str(tmp_path / "g.db"))
    owner = TestClient(app)
    r = owner.post("/api/signup", json={"email": "owner@example.com", "password": "correct horse battery"})
    csrf = r.json()["csrf"]
    r = owner.post("/api/sites", json={"name": "Shop"}, headers={"X-CSRF-Token": csrf})
    return dict(app=app, owner=owner, site=r.json()["site"], key=r.json()["api_key"])


def test_attack_on_customer_site_reaches_the_owners_dashboard(platform):
    s = RemoteSink(platform["key"], SERVER, post=transport(TestClient(platform["app"])), start_thread=False)
    shop = customer_site(s)
    shop.get("/search", params={"q": "red shoes"})
    shop.get("/search", params={"q": "' OR '1'='1"})
    shop.get("/search", params={"q": "<script>alert(1)</script>"})
    assert s.flush() is True

    snap = platform["owner"].get(f"/app/sites/{platform['site']['id']}/api/snapshot").json()
    assert snap["totals"]["requests"] == 3 and snap["totals"]["threats"] == 2
    assert {e["technical"]["category"] for e in snap["events"]} == {"sql_injection", "xss"}
    assert snap["status"]["level"] in ("warning", "danger")
    listed = platform["owner"].get("/api/sites").json()["sites"][0]
    assert listed["last_seen"] and listed["threats_24h"] == 2


def test_block_mode_works_locally_and_reports_blocks(platform):
    s = RemoteSink(platform["key"], SERVER, mode="block", post=transport(TestClient(platform["app"])),
                   start_thread=False)
    shop = customer_site(s, mode="block")
    assert shop.get("/search", params={"q": "' OR '1'='1"}).status_code == 403
    assert shop.get("/search", params={"q": "ok"}).status_code == 200
    s.flush()
    snap = platform["owner"].get(f"/app/sites/{platform['site']['id']}/api/snapshot").json()
    assert snap["totals"]["blocked"] == 1 and snap["mode"] == "block"
    assert snap["events"][0]["action"] == "blocked"


def test_behavior_alerts_are_reported_too(platform):
    s = RemoteSink(platform["key"], SERVER, post=transport(TestClient(platform["app"])), start_thread=False)
    shop = customer_site(s)
    for i in range(6):
        shop.post("/login", json={"username": "bob", "password": f"guess{i}"})
    s.flush()
    snap = platform["owner"].get(f"/app/sites/{platform['site']['id']}/api/snapshot").json()
    assert [e["technical"]["category"] for e in snap["events"]] == ["brute_force"]
    assert snap["status"]["level"] == "danger"


def test_passwords_and_query_strings_never_leave_the_customers_server(platform):
    fake_sent = []
    real = transport(TestClient(platform["app"]))

    def spy(url, headers, body, timeout):
        fake_sent.append(body.decode())
        return real(url, headers, body, timeout)

    s = RemoteSink(platform["key"], SERVER, post=spy, start_thread=False)
    shop = customer_site(s)
    shop.post("/login", json={"username": "admin'--", "password": "hunter2-secret"})
    shop.get("/search", params={"q": "' OR '1'='1", "session": "SESSIONTOKEN123"})
    shop.get("/search", headers={"cookie": "sid=COOKIESECRET' OR '1'='1"})
    s.flush()
    sent = "".join(fake_sent)
    assert sent and "hunter2-secret" not in sent and "SESSIONTOKEN123" not in sent
    assert "COOKIESECRET" not in sent and "session=" not in sent


def test_customer_site_keeps_working_when_the_platform_is_down(tmp_path):
    def down(url, headers, body, timeout):
        raise ConnectionError("platform unreachable")

    s = RemoteSink(KEY, SERVER, post=down, start_thread=False)
    shop = customer_site(s, mode="block")
    assert shop.get("/search", params={"q": "fine"}).status_code == 200
    assert shop.get("/search", params={"q": "' OR '1'='1"}).status_code == 403   # still protected
    assert s.flush() is False                                                      # data waits for a retry


def test_a_broken_sink_cannot_break_the_site():
    class Broken:
        def request(self, *a, **k): raise RuntimeError("boom")
        def event(self, *a, **k): raise RuntimeError("boom")

    shop = customer_site(Broken())
    assert shop.get("/search", params={"q": "' OR '1'='1"}).status_code == 200
