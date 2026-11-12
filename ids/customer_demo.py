"""A pretend CUSTOMER website protected with the Guard SDK (what a user of your platform does).

    $env:GUARD_API_KEY = "gk_..."        # the key shown once when you add a website
    $env:GUARD_SERVER  = "http://127.0.0.1:9000"   # optional, this is the default
    $env:GUARD_MODE    = "detect"        # or "block"
    python -m uvicorn ids.customer_demo:app --port 8000

Then run:  python scripts\\attack.py --everything   and watch the site's dashboard on the platform.
The endpoints are harmless on purpose (nothing touches a database, the disk or a shell).
"""
import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel



API_KEY = os.getenv("GUARD_API_KEY")
if not API_KEY:
    raise SystemExit("Set GUARD_API_KEY first (copy it from the platform when you add a website).")

SERVER = os.getenv("GUARD_SERVER", "http://127.0.0.1:9000")
MODE = os.getenv("GUARD_MODE", "detect")

app = FastAPI(title="Customer demo site")

from .sdk import GuardMiddleware

app.add_middleware(
    GuardMiddleware,
    api_key=API_KEY,
    server=SERVER,
    mode=MODE,
)


class Login(BaseModel):
    username: str = ""
    password: str = ""


@app.get("/", response_class=HTMLResponse)
def home():
    return "<h1>Customer demo shop</h1><p>Protected by the Guard SDK.</p>"


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
