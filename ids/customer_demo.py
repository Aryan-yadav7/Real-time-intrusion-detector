"""A pretend CUSTOMER website protected with the Sentinel SDK (what a user of your platform does).

    $env:SENTINEL_API_KEY = "sk_..."     # the key shown once when you add a website
    $env:SENTINEL_SERVER  = "http://127.0.0.1:9000"   # optional, this is the default
    $env:SENTINEL_MODE    = "detect"     # or "block"
    python -m uvicorn ids.customer_demo:app --port 8000

Then run:  python scripts\\attack.py --everything   and watch the site's dashboard on the platform.
The endpoints are harmless on purpose (nothing touches a database, the disk or a shell).
"""
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel


def _load_env_files() -> None:
    """Load .env / ids/.env if present so SENTINEL_API_KEY works from .env files."""
    for candidate in (Path(__file__).resolve().parent / ".env", Path.cwd() / ".env"):
        if not candidate.is_file():
            continue
        for raw in candidate.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


_load_env_files()

API_KEY = os.getenv("SENTINEL_API_KEY", os.getenv("GUARD_API_KEY"))
if not API_KEY:
    raise SystemExit("Set SENTINEL_API_KEY first (copy it from the platform when you add a website).")

SERVER = os.getenv("SENTINEL_SERVER", os.getenv("GUARD_SERVER", "http://127.0.0.1:9000"))
MODE = os.getenv("SENTINEL_MODE", os.getenv("GUARD_MODE", "detect"))

app = FastAPI(title="Customer demo site")

from .sdk import SentinelMiddleware

app.add_middleware(
    SentinelMiddleware,
    api_key=API_KEY,
    server=SERVER,
    mode=MODE,
)


class Login(BaseModel):
    username: str = ""
    password: str = ""


@app.get("/", response_class=HTMLResponse)
def home():
    return "<h1>Customer demo shop</h1><p>Protected by the Sentinel SDK.</p>"


@app.get("/search")
def search(q: str = ""):
    return {"query": q, "results": []}


@app.get("/files")
def files(name: str = ""):
    return {"note": "demo only - never reads the disk", "requested": name}


@app.get("/ping")
def ping(host: str = ""):
    return {"note": "demo only - never runs a command", "host": host}


@app.post("/login")
def login(body: Login):
    if body.username == "demo" and body.password == "demo123":
        return {"ok": True}
    return JSONResponse({"ok": False, "error": "wrong username or password"}, status_code=401)
