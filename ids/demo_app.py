"""A tiny demo website protected by the IDS, with the live dashboard at /ids/.

The endpoints LOOK like typical attack targets (search, login, file download,
ping) but are harmless: nothing here touches a real database, the disk or a
shell. Attacks sent at it are detected and logged, and that is all.

Run:   python -m uvicorn ids.demo_app:app --port 8000
Open:  http://127.0.0.1:8000/ids/      (the dashboard)
Mode:  set IDS_MODE=block (default is detect)

The dashboard has NO login yet (accounts arrive on Day 3), so only run this on
your own computer (uvicorn listens on 127.0.0.1 by default).
"""
import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .dashboard import create_dashboard_router
from .middleware import IDSMiddleware
from .sdk import GuardMiddleware

DB_PATH = os.getenv("IDS_DB", "ids.db")
MODE = os.getenv("IDS_MODE", "detect")
SITE_ID = "demo"
API_KEY = os.getenv("GUARD_API_KEY")

app = FastAPI(title="Demo target site")

if API_KEY:
    app.add_middleware(
        GuardMiddleware,
        api_key=API_KEY,
        server=os.getenv("GUARD_SERVER", "http://127.0.0.1:9000"),
        mode=MODE,
        exempt_prefixes=("/ids",),
    )
else:
    app.add_middleware(
        IDSMiddleware,
        db_path=DB_PATH,
        site_id=SITE_ID,
        mode=MODE,
        exempt_prefixes=("/ids",),
    )

app.include_router(create_dashboard_router(DB_PATH, SITE_ID, MODE), prefix="/ids")


class Login(BaseModel):
    username: str = ""
    password: str = ""


@app.get("/", response_class=HTMLResponse)
def home():
    return """<h1>Demo shop</h1>
    <p>Protected by the IDS. Try <a href="/search?q=shoes">/search?q=shoes</a>
    or watch the <a href="/ids/">live dashboard</a>.</p>"""


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
