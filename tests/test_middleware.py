import json

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from ids import db
from ids.middleware import IDSMiddleware

ATTACK = "' OR '1'='1"


def make_client(tmp_path, mode="detect", **kwargs):
    calls = []
    app = FastAPI()

    @app.get("/hello")
    def hello(q: str = ""):
        calls.append(q)
        return {"q": q}

    @app.post("/echo")
    async def echo(request: Request):
        calls.append("echo")
        return {"body": (await request.body()).decode()}

    db_path = str(tmp_path / "test.db")
    app.add_middleware(IDSMiddleware, db_path=db_path, mode=mode, **kwargs)
    return TestClient(app), db_path, calls


def test_normal_request_passes_and_is_not_flagged(tmp_path):
    client, db_path, calls = make_client(tmp_path)
    r = client.get("/hello", params={"q": "red shoes"})
    assert r.status_code == 200 and r.json() == {"q": "red shoes"}
    assert db.recent_events(db_path) == []
    assert db.summary(db_path) == {"requests": 1, "threats": 0, "blocked": 0}


def test_detect_mode_logs_but_does_not_block(tmp_path):
    client, db_path, calls = make_client(tmp_path, mode="detect")
    r = client.get("/hello", params={"q": ATTACK})
    assert r.status_code == 200 and calls == [ATTACK]
    events = db.recent_events(db_path)
    assert len(events) == 1
    assert events[0]["category"] == "sql_injection"
    assert events[0]["action"] == "detected"
    assert events[0]["path"] == "/hello"  # query string is never stored


def test_block_mode_returns_403_and_app_is_never_called(tmp_path):
    client, db_path, calls = make_client(tmp_path, mode="block")
    r = client.get("/hello", params={"q": ATTACK})
    assert r.status_code == 403
    assert r.json()["error"] == "blocked_by_ids"
    assert calls == []
    assert db.recent_events(db_path)[0]["action"] == "blocked"
    assert db.summary(db_path) == {"requests": 1, "threats": 1, "blocked": 1}


def test_low_score_is_logged_but_not_blocked_in_block_mode(tmp_path):
    client, db_path, calls = make_client(tmp_path, mode="block")
    r = client.get("/hello", params={"q": "javascript:void(0)"})  # medium severity (50 < 70)
    assert r.status_code == 200
    assert db.recent_events(db_path)[0]["action"] == "detected"


def test_body_is_replayed_intact_to_the_app(tmp_path):
    client, db_path, calls = make_client(tmp_path, mode="block")
    payload = json.dumps({"message": "hello world", "n": 42})
    r = client.post("/echo", content=payload, headers={"content-type": "application/json"})
    assert r.status_code == 200 and r.json()["body"] == payload


def test_attack_in_body_is_detected(tmp_path):
    client, db_path, calls = make_client(tmp_path, mode="block")
    r = client.post("/echo", json={"username": "admin'--", "password": "x"})
    assert r.status_code == 403 and calls == []
    event = db.recent_events(db_path)[0]
    assert event["location"] == "body"
    assert "x" not in (event["evidence"] or "").replace("admin'--", "")  # password not leaked


def test_ids_fails_open_when_logging_breaks(tmp_path, monkeypatch):
    client, db_path, calls = make_client(tmp_path, mode="detect")

    def boom(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(db, "log_event", boom)
    monkeypatch.setattr(db, "log_request", boom)
    r = client.get("/hello", params={"q": ATTACK})
    assert r.status_code == 200 and calls == [ATTACK]


def test_exempt_prefix_is_not_inspected(tmp_path):
    client, db_path, calls = make_client(tmp_path, exempt_prefixes=("/hello",))
    client.get("/hello", params={"q": ATTACK})
    assert db.recent_events(db_path) == []
    assert db.summary(db_path)["requests"] == 0


def test_invalid_mode_is_rejected(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        IDSMiddleware(lambda *a: None, db_path=str(tmp_path / "x.db"), mode="nonsense")
