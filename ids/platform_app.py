"""The Guard platform: accounts, websites, API keys, ingestion API, per-site dashboards.

Run (Windows PowerShell):
    python -m uvicorn ids.platform_app:create_app --factory --port 9000
then open http://127.0.0.1:9000

Security design (each line is something an interviewer may ask about):
  * Passwords: scrypt hashes. Sessions and API keys: random, only their SHA-256 is stored.
  * Session cookie: HttpOnly (JS cannot read it), SameSite=Lax, Secure when behind HTTPS.
  * CSRF: every state-changing request needs an X-CSRF-Token header tied to the session.
  * Tenant isolation: a site is only ever looked up with (site id AND owner id); someone
    else's site answers 404, exactly like a site that does not exist.
  * Ingestion: the API key decides the site. The payload can never name a site.
  * Limits: rate limits on login/signup/ingestion, body size cap, strict payload schema.
  * Pages: strict Content-Security-Policy; attacker-controlled text only via textContent.
"""
from __future__ import annotations

import asyncio
import hmac
import html
import os
import re
import time
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import auth, db
from . import platform_db as pdb
from .dashboard import snapshot, sse_messages
from .ratelimit import RateLimiter

STATIC = Path(__file__).parent / "static"
_APP_PAGE = (STATIC / "app.html").read_text(encoding="utf-8")
_DASH_PAGE = (STATIC / "dashboard.html").read_text(encoding="utf-8")

COOKIE = "guard_session"
SESSION_TTL = 7 * 24 * 3600
MAX_SITES_PER_USER = 10
MAX_STREAMS_PER_USER = 5
MAX_BODY = 1_000_000
RETENTION_DAYS = 30
SITE_ID = re.compile(r"^[a-f0-9]{16}$")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
NO_STORE = {"Cache-Control": "no-store"}


class ApiError(Exception):
    def __init__(self, status: int, message: str, headers: dict | None = None):
        self.status, self.message, self.headers = status, message, headers or {}


# ----------------------------------------------------------------- schemas
class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)


class SiteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=60)
    domain: str = Field(default="", max_length=100)


class RequestRec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ts: float
    ip: str = Field(max_length=64)
    method: str = Field(max_length=10)
    path: str = Field(max_length=300)
    status: int = Field(ge=100, le=599)
    flagged: bool
    blocked: bool


class EventRec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ts: float
    ip: str = Field(max_length=64)
    method: str = Field(max_length=10)
    path: str = Field(max_length=300)
    category: str = Field(pattern=r"^[a-z_]{1,40}$")
    rule_id: str = Field(max_length=20)
    rules: str = Field(max_length=200)
    severity: Literal["low", "medium", "high", "critical"]
    score: int = Field(ge=0, le=100)
    location: str = Field(max_length=60)
    evidence: str = Field(max_length=200)
    user_agent: str = Field(default="", max_length=200)
    action: Literal["detected", "blocked"]


class Batch(BaseModel):
    model_config = ConfigDict(extra="forbid")   # a "site_id" field is rejected outright
    mode: Literal["detect", "block"] = "detect"
    sdk: str = Field(default="", max_length=40)
    requests: list[RequestRec] = Field(default_factory=list, max_length=200)
    events: list[EventRec] = Field(default_factory=list, max_length=200)


# ------------------------------------------------------------------ helpers
def _clean(text: str) -> str:
    return CONTROL_CHARS.sub("", text)


def _clamp_ts(ts: float, now: float) -> float:
    return ts if now - 7 * 86400 <= ts <= now + 300 else now


def _html_page(template: str) -> HTMLResponse:
    import secrets
    nonce = secrets.token_urlsafe(16)
    csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
           "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return HTMLResponse(template.replace("__NONCE__", nonce), headers={
        "Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})


def _json(data, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, headers=NO_STORE)


async def read_limited(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise ApiError(413, "Request body too large.")
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise ApiError(413, "Request body too large.")
        chunks.append(chunk)
    return b"".join(chunks)


async def guarded_stream(db_path, site_id, mode, alive, recheck_every: float = 30.0):
    """The live SSE stream, but it ends if the user's session stops being valid
    (logout, expiry), because a stream can stay open for hours."""
    last = time.monotonic()
    async for message in sse_messages(db_path, site_id, mode):
        yield message
        if time.monotonic() - last >= recheck_every:
            last = time.monotonic()
            if not await asyncio.to_thread(alive):
                return


# -------------------------------------------------------------------- app
def create_app(db_path: str | None = None, cookie_secure: bool | None = None,
               ingest_limit: int = 120, login_limit: int = 5) -> FastAPI:
    db_path = db_path or os.getenv("GUARD_DB", "guard.db")
    if cookie_secure is None:
        cookie_secure = os.getenv("GUARD_COOKIE_SECURE") == "1"
    pdb.init(db_path)
    pdb.purge_old(db_path, RETENTION_DAYS)

    app = FastAPI(title="Guard platform", docs_url=None, redoc_url=None, openapi_url=None)
    login_ip = RateLimiter(10, 60)
    login_email = RateLimiter(login_limit, 60)
    signup_ip = RateLimiter(5, 3600)
    bad_key_ip = RateLimiter(30, 60)
    ingest = RateLimiter(ingest_limit, 60)
    streams: dict[int, int] = {}
    counters = {"ingests": 0}

    @app.exception_handler(ApiError)
    async def api_error(_: Request, exc: ApiError):
        return JSONResponse({"error": exc.message}, status_code=exc.status,
                            headers={**NO_STORE, **exc.headers})

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError):
        return JSONResponse({"error": "Invalid input."}, status_code=422, headers=NO_STORE)

    # ------------------------------------------------------- auth helpers
    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def current_user(request: Request) -> dict | None:
        return pdb.get_session(db_path, request.cookies.get(COOKIE, ""))

    def need_user(request: Request) -> dict:
        user = current_user(request)
        if not user:
            raise ApiError(401, "Please log in.")
        return user

    def need_csrf(request: Request, user: dict) -> None:
        sent = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(sent.encode(), user["csrf"].encode()):
            raise ApiError(403, "Missing or wrong CSRF token. Reload the page and try again.")

    def owned_site(user: dict, site_id: str) -> dict:
        """404 for 'not yours' and 'does not exist' alike, so ids cannot be probed."""
        site = pdb.get_site(db_path, user["user_id"], site_id) if SITE_ID.match(site_id) else None
        if not site:
            raise ApiError(404, "Not found.")
        return site

    def start_session(user_id: int, email: str) -> JSONResponse:
        token, csrf = pdb.create_session(db_path, user_id, SESSION_TTL)
        response = _json({"email": email, "csrf": csrf})
        response.set_cookie(COOKIE, token, max_age=SESSION_TTL, httponly=True,
                            samesite="lax", secure=cookie_secure, path="/")
        return response

    def site_json(site: dict) -> dict:
        totals = db.summary(db_path, site["id"], time.time() - 86400)
        return {"id": site["id"], "name": site["name"], "domain": site["domain"],
                "key_prefix": site["api_key_prefix"], "created_at": site["created_at"],
                "last_seen": site["last_seen"], "mode": site["reported_mode"],
                "requests_24h": totals["requests"], "threats_24h": totals["threats"]}

    # ------------------------------------------------------------- pages
    @app.get("/", response_class=HTMLResponse)
    def home():
        return _html_page(_APP_PAGE)

    # ---------------------------------------------------------- accounts
    @app.post("/api/signup")
    def signup(creds: Credentials, request: Request):
        if not signup_ip.hit(client_ip(request)):
            raise ApiError(429, "Too many sign-ups from this address. Try again later.",
                           {"Retry-After": str(signup_ip.retry_after(client_ip(request)))})
        email = creds.email.strip().lower()
        if not auth.validate_email(email):
            raise ApiError(400, "Please enter a valid email address.")
        problem = auth.validate_password(creds.password)
        if problem:
            raise ApiError(400, problem)
        try:
            user_id = pdb.create_user(db_path, email, auth.hash_password(creds.password))
        except pdb.EmailTaken:
            raise ApiError(409, "An account with this email already exists.")
        return start_session(user_id, email)

    @app.post("/api/login")
    def login(creds: Credentials, request: Request):
        email = creds.email.strip().lower()
        ip = client_ip(request)
        if not (login_ip.hit(ip) and login_email.hit(email)):
            raise ApiError(429, "Too many attempts. Please wait a minute and try again.",
                           {"Retry-After": str(max(login_ip.retry_after(ip),
                                                   login_email.retry_after(email)))})
        user = pdb.get_user_by_email(db_path, email)
        ok = auth.verify_password(creds.password, user["password_hash"] if user else auth.dummy_hash())
        if not user or not ok:
            raise ApiError(401, "Wrong email or password.")
        return start_session(user["id"], user["email"])

    @app.post("/api/logout")
    def logout(request: Request):
        user = need_user(request)
        need_csrf(request, user)
        pdb.delete_session(db_path, request.cookies.get(COOKIE, ""))
        response = _json({"ok": True})
        response.delete_cookie(COOKIE, path="/")
        return response

    @app.get("/api/me")
    def me(request: Request):
        user = need_user(request)
        return _json({"email": user["email"], "csrf": user["csrf"]})

    # -------------------------------------------------------------- sites
    @app.get("/api/sites")
    def list_sites(request: Request):
        user = need_user(request)
        return _json({"sites": [site_json(s) for s in pdb.list_sites(db_path, user["user_id"])]})

    @app.post("/api/sites")
    def create_site(body: SiteIn, request: Request):
        user = need_user(request)
        need_csrf(request, user)
        name, domain = _clean(body.name).strip(), _clean(body.domain).strip()
        if not name:
            raise ApiError(400, "Please give the website a name.")
        if pdb.count_sites(db_path, user["user_id"]) >= MAX_SITES_PER_USER:
            raise ApiError(400, f"You can have at most {MAX_SITES_PER_USER} websites.")
        site, key = pdb.create_site(db_path, user["user_id"], name, domain)
        return _json({"site": site_json(site), "api_key": key}, 201)

    @app.post("/api/sites/{site_id}/rotate-key")
    def rotate(site_id: str, request: Request):
        user = need_user(request)
        need_csrf(request, user)
        owned_site(user, site_id)
        key = pdb.rotate_key(db_path, user["user_id"], site_id)
        site = owned_site(user, site_id)
        return _json({"site": site_json(site), "api_key": key})

    @app.delete("/api/sites/{site_id}")
    def delete_site(site_id: str, request: Request):
        user = need_user(request)
        need_csrf(request, user)
        owned_site(user, site_id)
        pdb.delete_site(db_path, user["user_id"], site_id)
        return _json({"ok": True})

    # ------------------------------------------------- per-site dashboard
    @app.get("/app/sites/{site_id}/")
    def site_dashboard(site_id: str, request: Request):
        user = current_user(request)
        if not user:
            return RedirectResponse("/", status_code=303)
        site = owned_site(user, site_id)
        page = _DASH_PAGE.replace(
            "<h1>Live Security Monitor</h1>",
            '<style nonce="__NONCE__">h1 a{color:inherit;text-decoration:none;opacity:.7}'
            'h1 a:hover{text-decoration:underline;opacity:1}</style>'
            f'<h1><a href="/">&larr; Sites</a> &middot; {html.escape(site["name"])}</h1>')
        return _html_page(page)

    @app.get("/app/sites/{site_id}/api/snapshot")
    def site_snapshot(site_id: str, request: Request):
        user = need_user(request)
        site = owned_site(user, site_id)
        return _json(snapshot(db_path, site["id"], site["reported_mode"]))

    @app.get("/app/sites/{site_id}/stream")
    async def site_stream(site_id: str, request: Request):
        user = need_user(request)
        site = owned_site(user, site_id)
        uid = user["user_id"]
        if streams.get(uid, 0) >= MAX_STREAMS_PER_USER:
            raise ApiError(429, "Too many dashboards open. Close one and retry.")
        token = request.cookies.get(COOKIE, "")

        def alive() -> bool:
            return pdb.get_session(db_path, token) is not None

        async def generate():
            streams[uid] = streams.get(uid, 0) + 1
            try:
                async for message in guarded_stream(db_path, site["id"], site["reported_mode"], alive):
                    yield message
            finally:
                streams[uid] = max(0, streams.get(uid, 1) - 1)

        return StreamingResponse(generate(), media_type="text/event-stream",
                                 headers={**NO_STORE, "X-Accel-Buffering": "no"})

    # ----------------------------------------------------- ingestion API
    async def site_from_key(request: Request) -> dict:
        scheme, _, key = request.headers.get("authorization", "").partition(" ")
        key = key.strip()
        site = None
        if scheme.lower() == "bearer" and key.startswith(auth.API_KEY_PREFIX) and len(key) <= 100:
            site = await asyncio.to_thread(pdb.get_site_by_key, db_path, key)
        if not site:
            if not bad_key_ip.hit(client_ip(request)):
                raise ApiError(429, "Too many invalid keys.", {"Retry-After": "60"})
            raise ApiError(401, "Invalid or missing API key.")
        return site

    @app.get("/api/v1/ping")
    async def ping(request: Request):
        site = await site_from_key(request)
        return _json({"ok": True, "site": site["name"]})

    @app.post("/api/v1/events")
    async def ingest_events(request: Request):
        site = await site_from_key(request)
        if not ingest.hit(site["id"]):
            raise ApiError(429, "Rate limit exceeded.",
                           {"Retry-After": str(ingest.retry_after(site["id"]))})
        raw = await read_limited(request, MAX_BODY)
        try:
            batch = Batch.model_validate_json(raw)
        except ValidationError:
            raise ApiError(422, "Invalid payload.")
        now = time.time()
        requests = [{**r.model_dump(), "ts": _clamp_ts(r.ts, now), "ip": _clean(r.ip),
                     "method": _clean(r.method), "path": _clean(r.path)} for r in batch.requests]
        events = [{**e.model_dump(), "ts": _clamp_ts(e.ts, now), **{
            k: _clean(getattr(e, k)) for k in ("ip", "method", "path", "rule_id", "rules",
                                               "location", "evidence", "user_agent")}}
                  for e in batch.events]
        await asyncio.to_thread(pdb.insert_batch, db_path, site["id"], requests, events)
        await asyncio.to_thread(pdb.touch_site, db_path, site["id"], batch.mode)
        counters["ingests"] += 1
        if counters["ingests"] % 1000 == 0:
            await asyncio.to_thread(pdb.purge_old, db_path, RETENTION_DAYS)
        return _json({"ok": True, "accepted": {"requests": len(requests), "events": len(events)}})

    return app
