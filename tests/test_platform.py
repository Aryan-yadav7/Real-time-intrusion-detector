import asyncio
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from ids import db
from ids import platform_db as pdb
from ids.platform_app import create_app, guarded_stream

PASSWORD = "correct horse battery"


class Account:
    """A browser: its own cookie jar, signed up as `email`."""

    def __init__(self, app, email):
        self.client = TestClient(app)
        r = self.client.post("/api/signup", json={"email": email, "password": PASSWORD})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf"]

    def post(self, url, **kw):
        return self.client.post(url, headers={"X-CSRF-Token": self.csrf}, **kw)

    def delete(self, url):
        return self.client.delete(url, headers={"X-CSRF-Token": self.csrf})

    def add_site(self, name="Shop"):
        r = self.post("/api/sites", json={"name": name, "domain": "shop.example"})
        assert r.status_code == 201, r.text
        return r.json()["site"], r.json()["api_key"]


def ev(ip="6.6.6.6", category="sql_injection", evidence="' or 1=1", action="detected"):
    return dict(ts=time.time(), ip=ip, method="GET", path="/search", category=category,
                rule_id="SQLI-001", rules="SQLI-001", severity="high", score=75,
                location="query", evidence=evidence, user_agent="ua", action=action)


def rq(ip="6.6.6.6", status=200):
    return dict(ts=time.time(), ip=ip, method="GET", path="/", status=status, flagged=False, blocked=False)


def send(client, key, requests=(), events=(), mode="detect", **extra):
    return client.post("/api/v1/events", headers={"Authorization": f"Bearer {key}"},
                       json={"mode": mode, "requests": list(requests), "events": list(events), **extra})


@pytest.fixture
def env(tmp_path):
    path = str(tmp_path / "g.db")
    return create_app(path), path


# ============================================================== accounts
def test_signup_login_logout_flow(env):
    app, path = env
    a = Account(app, "Alice@Example.com")
    me = a.client.get("/api/me")
    assert me.status_code == 200 and me.json()["email"] == "alice@example.com"
    cookie = a.client.get("/api/me").request.headers["cookie"]
    assert a.post("/api/logout").status_code == 200
    assert a.client.get("/api/me").status_code == 401
    # the old cookie is dead on the server side too, not just deleted in the browser
    other = TestClient(app)
    assert other.get("/api/me", headers={"cookie": cookie}).status_code == 401
    r = other.post("/api/login", json={"email": "ALICE@example.com", "password": PASSWORD})
    assert r.status_code == 200 and other.get("/api/me").status_code == 200


def test_session_cookie_flags(env):
    app, _ = env
    r = TestClient(app).post("/api/signup", json={"email": "a@example.com", "password": PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie


def test_secure_flag_when_configured(tmp_path):
    app = create_app(str(tmp_path / "s.db"), cookie_secure=True)
    r = TestClient(app).post("/api/signup", json={"email": "a@example.com", "password": PASSWORD})
    assert "secure" in r.headers["set-cookie"].lower()


def test_passwords_are_never_stored(env):
    app, path = env
    Account(app, "a@example.com")
    row = pdb.get_user_by_email(path, "a@example.com")
    assert row["password_hash"].startswith("scrypt$") and PASSWORD not in row["password_hash"]


def test_signup_validation_and_duplicates(env):
    app, _ = env
    c = TestClient(app)
    assert c.post("/api/signup", json={"email": "nope", "password": PASSWORD}).status_code == 400
    assert c.post("/api/signup", json={"email": "a@example.com", "password": "short"}).status_code == 400
    assert c.post("/api/signup", json={"email": "a@example.com", "password": PASSWORD}).status_code == 200
    r = c.post("/api/signup", json={"email": "A@EXAMPLE.COM", "password": PASSWORD})
    assert r.status_code == 409
    assert c.post("/api/signup", json={"email": "b@example.com", "password": PASSWORD, "admin": True}).status_code == 422


def test_login_errors_do_not_reveal_whether_the_account_exists(env):
    app, _ = env
    Account(app, "real@example.com")
    c = TestClient(app)
    wrong = c.post("/api/login", json={"email": "real@example.com", "password": "wrong password!"})
    ghost = c.post("/api/login", json={"email": "ghost@example.com", "password": "wrong password!"})
    assert wrong.status_code == ghost.status_code == 401
    assert wrong.json() == ghost.json()


def test_sql_injection_in_login_is_just_a_wrong_password(env):
    app, _ = env
    Account(app, "real@example.com")
    r = TestClient(app).post("/api/login", json={"email": "' OR '1'='1", "password": "' OR '1'='1"})
    assert r.status_code == 401


def test_login_is_rate_limited(env):
    app, _ = env
    Account(app, "real@example.com")
    c = TestClient(app)
    codes = [c.post("/api/login", json={"email": "real@example.com", "password": f"guess number {i}"}).status_code
             for i in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    r = c.post("/api/login", json={"email": "real@example.com", "password": PASSWORD})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1  # even the right password waits


def test_signup_is_rate_limited_per_address(env):
    app, _ = env
    c = TestClient(app)
    codes = [c.post("/api/signup", json={"email": f"u{i}@example.com", "password": PASSWORD}).status_code
             for i in range(7)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429, 429]


# ================================================================== CSRF
def test_state_changing_requests_need_the_csrf_token(env):
    app, _ = env
    a = Account(app, "a@example.com")
    site, _ = a.add_site()
    for bad in ({}, {"X-CSRF-Token": "wrong"}):
        assert a.client.post("/api/sites", json={"name": "x"}, headers=bad).status_code == 403
        assert a.client.post(f"/api/sites/{site['id']}/rotate-key", headers=bad).status_code == 403
        assert a.client.delete(f"/api/sites/{site['id']}", headers=bad).status_code == 403
        assert a.client.post("/api/logout", headers=bad).status_code == 403
    assert a.client.get("/api/me").status_code == 200  # still logged in


def test_another_users_csrf_token_does_not_work(env):
    app, _ = env
    a, b = Account(app, "a@example.com"), Account(app, "b@example.com")
    r = a.client.post("/api/sites", json={"name": "x"}, headers={"X-CSRF-Token": b.csrf})
    assert r.status_code == 403


# ============================================================ unauthenticated
def test_everything_private_needs_login(env):
    app, _ = env
    c = TestClient(app)
    site_id = "0123456789abcdef"
    assert c.get("/api/me").status_code == 401
    assert c.get("/api/sites").status_code == 401
    assert c.get(f"/app/sites/{site_id}/api/snapshot").status_code == 401
    assert c.get(f"/app/sites/{site_id}/stream").status_code == 401
    page = c.get(f"/app/sites/{site_id}/", follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"] == "/"


# ==================================================================== sites
def test_site_creation_shows_the_key_once_and_stores_only_a_hash(env):
    app, path = env
    a = Account(app, "a@example.com")
    site, key = a.add_site()
    assert key.startswith("gk_") and site["key_prefix"] == key[:11]
    listing = a.client.get("/api/sites")
    assert key not in listing.text and "api_key" not in listing.text and "hash" not in listing.text
    conn = sqlite3.connect(path)
    dump = "\n".join(str(row) for table in ("users", "sessions", "sites")
                     for row in conn.execute(f"SELECT * FROM {table}"))
    conn.close()
    assert key not in dump                       # plaintext key is nowhere in the database
    assert PASSWORD not in dump


def test_site_limits_and_validation(env):
    app, _ = env
    a = Account(app, "a@example.com")
    assert a.post("/api/sites", json={"name": "   "}).status_code == 400
    assert a.post("/api/sites", json={"name": "x" * 61}).status_code == 422
    for i in range(10):
        a.add_site(f"s{i}")
    assert a.post("/api/sites", json={"name": "one too many"}).status_code == 400


def test_rotating_a_key_kills_the_old_one(env):
    app, _ = env
    a = Account(app, "a@example.com")
    site, old = a.add_site()
    assert send(a.client, old).status_code == 200
    r = a.post(f"/api/sites/{site['id']}/rotate-key")
    new = r.json()["api_key"]
    assert new != old
    assert send(a.client, old).status_code == 401
    assert send(a.client, new).status_code == 200


def test_deleting_a_site_deletes_its_data_and_key(env):
    app, path = env
    a = Account(app, "a@example.com")
    site, key = a.add_site()
    send(a.client, key, [rq()], [ev()])
    assert db.summary(path, site["id"])["requests"] == 1
    assert a.delete(f"/api/sites/{site['id']}").status_code == 200
    assert db.summary(path, site["id"]) == {"requests": 0, "threats": 0, "blocked": 0}
    assert send(a.client, key).status_code == 401
    assert a.client.get("/api/sites").json()["sites"] == []


# ========================================================= TENANT ISOLATION
@pytest.fixture
def two_users(env):
    app, path = env
    a, b = Account(app, "a@example.com"), Account(app, "b@example.com")
    (sa, ka), (sb, kb) = a.add_site("Alice shop"), b.add_site("Bob shop")
    send(a.client, ka, [rq("1.1.1.1")], [ev("1.1.1.1", evidence="ALICE-SECRET")])
    send(b.client, kb, [rq("2.2.2.2"), rq("2.2.2.2")], [ev("2.2.2.2", "xss", "BOB-SECRET")])
    return dict(app=app, path=path, a=a, b=b, sa=sa, sb=sb, ka=ka, kb=kb)


def test_sites_list_only_shows_your_own(two_users):
    t = two_users
    assert [s["id"] for s in t["a"].client.get("/api/sites").json()["sites"]] == [t["sa"]["id"]]
    assert [s["id"] for s in t["b"].client.get("/api/sites").json()["sites"]] == [t["sb"]["id"]]


def test_you_cannot_open_someone_elses_dashboard_data_or_stream(two_users):
    t = two_users
    for suffix in ("api/snapshot", "stream", ""):
        mine = (None if suffix == "stream" else
                t["a"].client.get(f"/app/sites/{t['sa']['id']}/{suffix}", follow_redirects=False))
        theirs = t["a"].client.get(f"/app/sites/{t['sb']['id']}/{suffix}", follow_redirects=False)
        ghost = t["a"].client.get(f"/app/sites/{'f' * 16}/{suffix}", follow_redirects=False)
        assert theirs.status_code == 404 and ghost.status_code == 404
        assert theirs.json() == ghost.json()                 # indistinguishable from "does not exist"
        assert "BOB-SECRET" not in theirs.text and "2.2.2.2" not in theirs.text
        if suffix != "stream":                               # a real stream never ends, so don't open it
            assert mine.status_code == 200


def test_snapshots_contain_only_your_own_events(two_users):
    t = two_users
    a_snap = t["a"].client.get(f"/app/sites/{t['sa']['id']}/api/snapshot").json()
    b_snap = t["b"].client.get(f"/app/sites/{t['sb']['id']}/api/snapshot").json()
    assert "ALICE-SECRET" in str(a_snap) and "BOB-SECRET" not in str(a_snap) and "2.2.2.2" not in str(a_snap)
    assert "BOB-SECRET" in str(b_snap) and "ALICE-SECRET" not in str(b_snap) and "1.1.1.1" not in str(b_snap)
    assert a_snap["totals"]["requests"] == 1 and b_snap["totals"]["requests"] == 2


def test_you_cannot_rotate_or_delete_someone_elses_site(two_users):
    t = two_users
    assert t["a"].post(f"/api/sites/{t['sb']['id']}/rotate-key").status_code == 404
    assert t["a"].delete(f"/api/sites/{t['sb']['id']}").status_code == 404
    assert send(t["b"].client, t["kb"]).status_code == 200        # Bob's key still works
    assert len(t["b"].client.get("/api/sites").json()["sites"]) == 1


def test_malformed_site_ids_are_just_404(two_users):
    t = two_users
    for bad in ["../x", "%27%20OR%201=1", "A" * 16, "g" * 16, "short", "0" * 17]:
        r = t["a"].client.get(f"/app/sites/{bad}/api/snapshot")
        assert r.status_code in (404, 307, 308), bad
        assert t["a"].post(f"/api/sites/{bad}/rotate-key").status_code == 404


def test_the_payload_can_never_choose_the_site(two_users):
    """A's key plus B's site id in the body: rejected, and nothing lands in B's data."""
    t = two_users
    before = db.summary(t["path"], t["sb"]["id"])
    r = send(t["a"].client, t["ka"], [rq("9.9.9.9")], [ev("9.9.9.9")], site_id=t["sb"]["id"])
    assert r.status_code == 422
    r = t["a"].client.post("/api/v1/events", headers={"Authorization": f"Bearer {t['ka']}"},
                           json={"requests": [dict(rq(), site_id=t["sb"]["id"])], "events": []})
    assert r.status_code == 422
    assert db.summary(t["path"], t["sb"]["id"]) == before


def test_data_sent_with_a_key_lands_in_exactly_that_site(two_users):
    t = two_users
    send(t["a"].client, t["ka"], [rq("7.7.7.7")], [ev("7.7.7.7")])
    assert db.summary(t["path"], t["sa"]["id"])["requests"] == 2
    assert db.summary(t["path"], t["sb"]["id"])["requests"] == 2   # unchanged


def test_user_scoped_queries_ignore_other_owners(two_users):
    t = two_users
    uid_a = pdb.get_user_by_email(t["path"], "a@example.com")["id"]
    assert pdb.get_site(t["path"], uid_a, t["sb"]["id"]) is None
    assert pdb.rotate_key(t["path"], uid_a, t["sb"]["id"]) is None
    assert pdb.delete_site(t["path"], uid_a, t["sb"]["id"]) is False


# ============================================================== ingestion
def test_ingestion_requires_a_valid_key(env):
    app, _ = env
    a = Account(app, "a@example.com")
    _, key = a.add_site()
    c = TestClient(app)
    body = {"requests": [], "events": []}
    assert c.post("/api/v1/events", json=body).status_code == 401
    assert c.post("/api/v1/events", json=body, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.post("/api/v1/events", json=body, headers={"Authorization": f"Basic {key}"}).status_code == 401
    assert c.post("/api/v1/events", json=body, headers={"Authorization": f"Bearer {key}x"}).status_code == 401
    assert c.post("/api/v1/events", json=body, headers={"Authorization": f"Bearer {key}"}).status_code == 200
    assert c.get("/api/v1/ping", headers={"Authorization": f"Bearer {key}"}).json()["ok"] is True


def test_guessing_keys_is_rate_limited(env):
    app, _ = env
    c = TestClient(app)
    codes = [c.get("/api/v1/ping", headers={"Authorization": f"Bearer gk_wrong{i}"}).status_code
             for i in range(35)]
    assert codes[:30] == [401] * 30 and set(codes[30:]) == {429}


def test_payload_validation(env):
    app, path = env
    a = Account(app, "a@example.com")
    site, key = a.add_site()
    H = {"Authorization": f"Bearer {key}"}
    c = a.client
    assert c.post("/api/v1/events", content=b"not json", headers=H).status_code == 422
    assert send(c, key, events=[dict(ev(), severity="apocalyptic")]).status_code == 422
    assert send(c, key, events=[dict(ev(), score=101)]).status_code == 422
    assert send(c, key, events=[dict(ev(), category="Bad Category!")]).status_code == 422
    assert send(c, key, events=[dict(ev(), action="exploded")]).status_code == 422
    assert send(c, key, events=[dict(ev(), evidence="x" * 201)]).status_code == 422
    assert send(c, key, requests=[dict(rq(), status=99)]).status_code == 422
    assert send(c, key, events=[dict(ev(), surprise=1)]).status_code == 422
    assert send(c, key, events=[ev()] * 201).status_code == 422
    assert send(c, key, requests=[rq()] * 201).status_code == 422
    assert send(c, key, mode="chaos").status_code == 422
    assert db.summary(path, site["id"]) == {"requests": 0, "threats": 0, "blocked": 0}  # nothing partial stored


def test_oversized_body_is_refused(env):
    app, _ = env
    a = Account(app, "a@example.com")
    _, key = a.add_site()
    r = a.client.post("/api/v1/events", headers={"Authorization": f"Bearer {key}"},
                      content=b"x" * 1_100_000)
    assert r.status_code == 413


def test_timestamps_are_clamped_and_control_characters_stripped(env):
    app, path = env
    a = Account(app, "a@example.com")
    site, key = a.add_site()
    now = time.time()
    send(a.client, key, [dict(rq(), ts=now + 10 ** 7), dict(rq(), ts=1.0)],
         [dict(ev(), evidence="a\x00b\x1bc\nd", ts=now + 10 ** 7)])
    for row in db.recent_events(path, site["id"]):
        assert abs(row["ts"] - now) < 60 and row["evidence"] == "abcd"
    assert db.summary(path, site["id"], now - 60)["requests"] == 2


def test_ingestion_is_rate_limited_per_site_and_reports_the_mode(tmp_path):
    app = create_app(str(tmp_path / "r.db"), ingest_limit=3)
    a = Account(app, "a@example.com")
    site, key = a.add_site()
    codes = [send(a.client, key, mode="block").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert send(a.client, key).headers["retry-after"]
    listed = a.client.get("/api/sites").json()["sites"][0]
    assert listed["mode"] == "block" and listed["last_seen"] is not None


def test_one_sites_rate_limit_does_not_affect_another(tmp_path):
    app = create_app(str(tmp_path / "r.db"), ingest_limit=2)
    a, b = Account(app, "a@example.com"), Account(app, "b@example.com")
    (_, ka), (_, kb) = a.add_site(), b.add_site()
    assert [send(a.client, ka).status_code for _ in range(3)] == [200, 200, 429]
    assert send(b.client, kb).status_code == 200


def test_old_data_is_purged(env):
    app, path = env
    a = Account(app, "a@example.com")
    site, key = a.add_site()
    db.log_request(path, site["id"], "1.1.1.1", "GET", "/", 200, False, ts=time.time() - 40 * 86400)
    db.log_request(path, site["id"], "1.1.1.1", "GET", "/", 200, False)
    pdb.purge_old(path, 30)
    assert db.summary(path, site["id"])["requests"] == 1


# ================================================================ the pages
def test_pages_have_strict_csp_and_no_html_injection_apis(env):
    app, _ = env
    r = TestClient(app).get("/")
    csp = r.headers["content-security-policy"]
    nonce = re.search(r"script-src 'nonce-([^']+)'", csp).group(1)
    assert f'nonce="{nonce}"' in r.text and "default-src 'none'" in csp
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", " style="):
        assert banned not in r.text, banned


def test_site_name_is_escaped_on_the_dashboard_page(env):
    app, _ = env
    a = Account(app, "a@example.com")
    site, _ = a.add_site('<img src=x onerror=alert(1)>')
    page = a.client.get(f"/app/sites/{site['id']}/")
    assert page.status_code == 200
    assert "<img src=x" not in page.text and "&lt;img src=x onerror=alert(1)&gt;" in page.text
    assert "content-security-policy" in page.headers


# ============================================================ live stream
def test_stream_stops_when_the_session_ends():
    import tempfile, os
    path = os.path.join(tempfile.mkdtemp(), "s.db")
    db.init_db(path)

    async def run_real():
        got = []
        async for message in guarded_stream(path, "s", "detect", alive=lambda: False, recheck_every=0):
            got.append(message)
        return got

    assert len(asyncio.run(run_real())) == 1   # sent the first message, saw the dead session, stopped
