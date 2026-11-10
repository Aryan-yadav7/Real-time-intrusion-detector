from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from ids import db
from ids.behavior import BehaviorConfig
from ids.middleware import IDSMiddleware


def make_client(tmp_path, mode="detect", **config):
    app = FastAPI()

    @app.get("/hello")
    def hello():
        return {"ok": True}

    @app.post("/login")
    def login():
        return JSONResponse({"ok": False}, status_code=401)

    db_path = str(tmp_path / "t.db")
    app.add_middleware(IDSMiddleware, db_path=db_path, mode=mode,
                       behavior_config=BehaviorConfig(**config))
    return TestClient(app), db_path


def categories(db_path):
    return [e["category"] for e in db.recent_events(db_path)]


def test_brute_force_is_detected_but_not_blocked_in_detect_mode(tmp_path):
    client, db_path = make_client(tmp_path)
    codes = [client.post("/login", json={"username": "bob", "password": f"p{i}"}).status_code
             for i in range(8)]
    assert codes == [401] * 8                      # the site still answers normally
    assert categories(db_path) == ["brute_force"]   # one alert, not eight
    assert db.recent_events(db_path)[0]["action"] == "detected"


def test_block_mode_locks_out_the_ip_after_brute_force(tmp_path):
    client, db_path = make_client(tmp_path, mode="block")
    for i in range(5):
        client.post("/login", json={"username": "bob", "password": f"p{i}"})
    r = client.get("/hello")                        # a totally normal page, same IP
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0
    assert db.recent_events(db_path)[0]["action"] == "blocked"
    assert db.summary(db_path)["blocked"] == 1


def test_credential_stuffing_is_detected(tmp_path):
    client, db_path = make_client(tmp_path)
    for i in range(6):
        client.post("/login", json={"username": f"user{i}", "password": "x"})
    assert categories(db_path) == ["credential_stuffing"]
    evidence = db.recent_events(db_path)[0]["evidence"]
    assert not any(f"user{i}" in evidence for i in range(6))  # submitted names are never stored


def test_scanning_and_probe_events(tmp_path):
    client, db_path = make_client(tmp_path, scan_paths=10)
    for i in range(12):
        client.get(f"/missing{i}")
    assert "scanning" in categories(db_path)
    client.get("/.env")
    assert "probe" in categories(db_path)


def test_flood_in_block_mode_gets_429(tmp_path):
    client, db_path = make_client(tmp_path, mode="block", flood_requests=20, flood_window=10)
    codes = [client.get("/hello").status_code for _ in range(25)]
    assert codes[:19] == [200] * 19
    assert set(codes[19:]) == {429}
    assert categories(db_path) == ["flood"]


def test_payload_attack_still_gets_403_not_429(tmp_path):
    client, db_path = make_client(tmp_path, mode="block")
    assert client.get("/hello", params={"q": "' OR '1'='1"}).status_code == 403


def test_normal_traffic_never_triggers_behavior_alerts(tmp_path):
    client, db_path = make_client(tmp_path, mode="block")
    for _ in range(40):
        assert client.get("/hello").status_code == 200
    assert db.recent_events(db_path) == []


def test_behavior_can_be_switched_off(tmp_path):
    app = FastAPI()

    @app.post("/login")
    def login():
        return JSONResponse({"ok": False}, status_code=401)

    db_path = str(tmp_path / "off.db")
    app.add_middleware(IDSMiddleware, db_path=db_path, behavior=False)
    client = TestClient(app)
    for i in range(10):
        client.post("/login", json={"username": "bob", "password": str(i)})
    assert db.recent_events(db_path) == []


def test_exempt_prefix_must_match_whole_path_segments(tmp_path):
    mw = IDSMiddleware(lambda *a: None, db_path=str(tmp_path / "e.db"),
                       exempt_prefixes=("/ids",))
    assert mw._exempt("/ids") and mw._exempt("/ids/api/snapshot")
    assert not mw._exempt("/idsfoo")            # similar name is NOT exempt
    assert not mw._exempt("/ids/../search")      # dot-dot escape is NOT exempt
    assert not mw._exempt("//ids/x")


def test_old_day1_database_is_upgraded(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL DEFAULT 'demo',
            ts REAL NOT NULL, ip TEXT, method TEXT, path TEXT, status INTEGER, flagged INTEGER NOT NULL DEFAULT 0);
        INSERT INTO requests (ts, ip, method, path, status, flagged) VALUES (1, 'a', 'GET', '/', 403, 1);
    """)
    conn.commit()
    conn.close()
    db.init_db(path)
    assert db.summary(path)["blocked"] == 1
