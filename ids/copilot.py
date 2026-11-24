"""Guard AI Security Copilot: Incident investigation, threat explanations, and code remediation.

Features:
  * Analyzes recent security events for a specific website.
  * Explains attack mechanisms and motives in plain English.
  * Provides actionable framework-specific remediation code (FastAPI, Flask, Django).
  * Generates executive attack summaries and response checklists.
  * Works out of the box via built-in expert engine; optionally uses Gemini / OpenAI if API key is set.
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request

from . import db
from .messages import CATEGORY_INFO, describe_event

log = logging.getLogger("ids.copilot")

REMEDIATION_GUIDES = {
    "sql_injection": {
        "title": "Fixing SQL Injection",
        "description": "SQL injection happens when untrusted user input is concatenated directly into SQL query strings.",
        "fastapi": """# In FastAPI with SQLAlchemy:
# ❌ VULNERABLE:
# db.execute(f"SELECT * FROM users WHERE name = '{username}'")

# ✅ SAFE (Prepared / Parameterized queries):
from sqlalchemy import text
result = db.execute(text("SELECT * FROM users WHERE name = :u"), {"u": username})
""",
        "django": """# In Django:
# ❌ VULNERABLE:
# User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")

# ✅ SAFE (Django ORM handles parameterization automatically):
user = User.objects.filter(username=username).first()
""",
        "flask": """# In Flask with sqlite3 / psycopg2:
# ❌ VULNERABLE:
# cursor.execute(f"SELECT * FROM products WHERE id = {pid}")

# ✅ SAFE (Tuple / Dictionary parameters):
cursor.execute("SELECT * FROM products WHERE id = ?", (pid,))
""",
    },
    "xss": {
        "title": "Preventing Cross-Site Scripting (XSS)",
        "description": "XSS occurs when malicious scripts are echoed into web pages without HTML escaping.",
        "fastapi": """# In FastAPI:
# 1. Use Jinja2 templates (auto-escaping is enabled by default):
# {{ user_text }}  <-- Automatically escaped!

# 2. Add strict Content-Security-Policy headers in middleware:
# response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
""",
        "django": """# In Django:
# Django templates auto-escape by default:
# {{ user_input }}

# Do NOT use |safe on untrusted input!
""",
        "flask": """# In Flask:
# Jinja2 escapes HTML by default. If returning raw HTML, sanitize first:
import markupsafe
safe_html = markupsafe.escape(untrusted_text)
""",
    },
    "path_traversal": {
        "title": "Preventing Path Traversal",
        "description": "Path traversal happens when user-supplied filenames contain '../' to break out of intended folders.",
        "fastapi": """from pathlib import Path
from fastapi import HTTPException

BASE_DIR = Path("/var/app/uploads").resolve()

def safe_download(filename: str):
    # Resolve absolute path and verify it stays inside BASE_DIR:
    target = (BASE_DIR / filename).resolve()
    if not target.is_relative_to(BASE_DIR):
        raise HTTPException(status_code=403, detail="Access denied")
    return target
""",
        "django": """import os
from django.core.exceptions import PermissionDenied

BASE_DIR = os.path.abspath("/var/app/uploads")
target = os.path.abspath(os.path.join(BASE_DIR, filename))
if not target.startswith(BASE_DIR + os.sep):
    raise PermissionDenied("Invalid file path")
""",
        "flask": """# In Flask, use secure_filename and send_from_directory:
from werkzeug.utils import secure_filename
from flask import send_from_directory

filename = secure_filename(untrusted_filename)
return send_from_directory("/var/app/uploads", filename)
""",
    },
    "command_injection": {
        "title": "Preventing Command Injection",
        "description": "Never pass user input into a system shell string. Use list arguments and avoid shell=True.",
        "fastapi": """import subprocess

# ❌ VULNERABLE:
# subprocess.run(f"ping -c 1 {host}", shell=True)

# ✅ SAFE (Pass executable and arguments as a list with shell=False):
subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
""",
        "django": """import subprocess
# Always pass command arguments as a list, never a shell string:
subprocess.run(["/usr/bin/git", "log", "-n", "1"], shell=False)
""",
        "flask": """import subprocess
# Validate input with strict regex or allowlist before invoking system tools:
if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
    raise ValueError("Invalid hostname")
subprocess.run(["nslookup", hostname], shell=False)
""",
    },
    "brute_force": {
        "title": "Mitigating Brute Force & Credential Stuffing",
        "description": "Attackers cycle through common passwords or stolen credentials on login endpoints.",
        "fastapi": """# Recommendations:
# 1. Enable GuardMiddleware in 'block' mode: repeat failed logins get HTTP 429 automatically.
# 2. Add an account-level delay or progressive lock:
#    After 5 failed attempts, require a 5-minute wait.
# 3. Implement Multi-Factor Authentication (TOTP / WebAuthn).
# 4. Use constant-time password verification (e.g. hmac.compare_digest).
""",
        "django": """# In Django:
# 1. Use django-axes or django-ratelimit on login views:
# from axes.decorators import axes_dispatch
# @axes_dispatch
# def login_view(request): ...
""",
        "flask": """# In Flask:
# Use Flask-Limiter:
# @limiter.limit("5 per minute")
# def login(): ...
""",
    },
}


def _call_gemini(api_key: str, prompt: str) -> str | None:
    """Optional LLM query if GEMINI_API_KEY is configured."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 800},
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            data = json.loads(resp.read().decode())
            return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as exc:
        log.warning("Gemini copilot query failed: %s; using local expert engine", exc)
        return None


def ask_copilot(question: str, site_id: str, db_path: str | None = None) -> dict:
    """Analyze the user's question, inspect site security records, and return a helpful response."""
    q = question.strip()
    q_lower = q.lower()

    # 1. Gather recent site context
    events_raw: list[dict] = []
    events: list[dict] = []
    totals: dict[str, int] = {"requests": 0, "threats": 0, "blocked": 0}
    blocked_events: list[dict] = []
    top_sources: list[dict] = []
    if db_path and os.path.exists(db_path):
        try:
            events_raw = db.query_events(db_path, site_id, limit=20)
            events = [describe_event(e) for e in events_raw]
            totals = db.summary(db_path, site_id)
            blocked_events = [e for e in events if e.get("action") == "blocked"]
            top_sources = db.top_sources(db_path, site_id, since=0, limit=5)
        except Exception as exc:
            log.warning("Could not load DB context for copilot: %s", exc)

    # 2. Check for optional LLM API Key
    llm_key = os.getenv("GEMINI_API_KEY") or os.getenv("COPILOT_API_KEY")
    if llm_key:
        summary_context = (
            f"Site: {site_id}\n"
            f"Total requests: {totals['requests']}, Threats spotted: {totals['threats']}, Blocked: {totals['blocked']}\n"
            f"Recent events: " + ", ".join(f"{e['technical']['category']} from {e['ip']}" for e in events[:5])
        )
        system_prompt = (
            "You are Guard AI, an expert cybersecurity assistant and Web Application Firewall copilot. "
            "Explain attacks clearly, provide safe remediation code (FastAPI/Python), and be concise.\n\n"
            f"Current Site Context:\n{summary_context}\n\nUser Question: {q}"
        )
        llm_reply = _call_gemini(llm_key, system_prompt)
        if llm_reply:
            sugs = [
                "Why was the last IP blocked?",
                "How do I fix SQL injection in FastAPI?",
                "Export firewall rules for these attackers",
            ]
            return {
                "reply": llm_reply,
                "suggestions": sugs,
                "suggested_actions": sugs,
                "source": "gemini",
                "sources_used": ["gemini"],
            }

    # 3. Built-in Security Expert Engine (100% offline, immediate, tailored)

    # Case A: User asks why an IP was blocked
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q)
    if "why" in q_lower and (ip_match or "blocked" in q_lower or "ip" in q_lower):
        target_ip = ip_match.group(0) if ip_match else (blocked_events[0]["ip"] if blocked_events else (events[0]["ip"] if events else None))
        if target_ip:
            ip_events = [e for e in events if e.get("ip") == target_ip]
            if ip_events:
                top_ev = ip_events[0]
                tech = top_ev["technical"]
                reply = (
                    f"### Investigation Report for IP `{target_ip}`\n\n"
                    f"• **Action Taken:** `{top_ev['action'].upper()}`\n"
                    f"• **Threat Type:** {top_ev['headline']} ({tech['type']})\n"
                    f"• **Target Endpoint:** `{tech['method']} {top_ev['path']}`\n"
                    f"• **Matched Rule:** `{tech['rule_id']}` (Risk Score: {tech['score']}/100)\n"
                )
                if tech.get("evidence"):
                    reply += f"• **Intercepted Evidence:** `{tech['evidence']}`\n\n"
                reply += (
                    f"**Why this was flagged:**\n{top_ev['explanation']}\n\n"
                    f"**Recommended action:**\n{top_ev['advice']}"
                )
                sugs = [
                    f"How do I prevent {tech['category']} in my code?",
                    "Export firewall rules for this IP",
                    "Show all recent attacks",
                ]
                return {
                    "reply": reply,
                    "suggestions": sugs,
                    "suggested_actions": sugs,
                    "source": "expert_engine",
                    "sources_used": ["database_events"],
                }

    # Case B: Remediation code requests ("how to fix", "remediate", "prevent")
    for category, guide in REMEDIATION_GUIDES.items():
        cat_keywords = [category, category.replace("_", " ")]
        if any(kw in q_lower for kw in cat_keywords) or (("fix" in q_lower or "prevent" in q_lower or "remediate" in q_lower) and category in q_lower):
            code_block = guide["fastapi"]
            if "django" in q_lower:
                code_block = guide["django"]
            elif "flask" in q_lower:
                code_block = guide["flask"]

            reply = (
                f"### {guide['title']}\n\n"
                f"{guide['description']}\n\n"
                f"```python\n{code_block.strip()}\n```\n\n"
                f"💡 **Guard Middleware Tip:** Keep Guard in `mode='block'` to automatically reject these attacks at your site's entry point."
            )
            sugs = [
                "How do I prevent Cross-Site Scripting (XSS)?",
                "How do I mitigate Brute Force attacks?",
                "Show site attack summary",
            ]
            return {
                "reply": reply,
                "suggestions": sugs,
                "suggested_actions": sugs,
                "source": "expert_engine",
                "sources_used": ["remediation"],
            }

    # Case C: Summary / Status request
    if any(k in q_lower for k in ("summar", "overview", "what happened", "status", "report", "health", "posture")):
        reply = (
            f"### Security Posture Summary (Last 24 Hours)\n\n"
            f"• **Total HTTP Requests Inspected:** {totals['requests']:,}\n"
            f"• **Threats Intercepted:** {totals['threats']:,}\n"
            f"• **Attacks Blocked:** {totals['blocked']:,}\n\n"
        )
        if top_sources:
            reply += "**Top Malicious Sources:**\n"
            for s in top_sources[:3]:
                reply += f"• `{s['ip']}`: {s['count']} threats (mostly {s['top_category']})\n"
            reply += "\n"
        if events:
            reply += f"**Latest Incident:** {events[0]['headline']} from IP `{events[0]['ip']}` targeting `{events[0]['path']}`."
        else:
            reply += "✅ **All Clear:** No suspicious requests recorded in the inspection window."
        sugs = [
            "Why were requests blocked?",
            "How do I fix SQL injection in FastAPI?",
            "Export firewall rules",
        ]
        return {
            "reply": reply,
            "suggestions": sugs,
            "suggested_actions": sugs,
            "source": "expert_engine",
            "sources_used": ["summary"],
        }

    # Case D: General rule explanation
    for cat_key, info in CATEGORY_INFO.items():
        if cat_key in q_lower or info["tech"].lower() in q_lower or info["label"].lower() in q_lower:
            reply = (
                f"### What is {info['tech']}?\n\n"
                f"**Headline:** {info['headline']}\n\n"
                f"**How it works:**\n{info['explanation']}\n\n"
                f"**Developer Recommendation:**\n{info['advice']}"
            )
            sugs = [
                f"How to fix {cat_key} in FastAPI",
                "Show recent attacks",
                "Check site security status",
            ]
            return {
                "reply": reply,
                "suggestions": sugs,
                "suggested_actions": sugs,
                "source": "expert_engine",
                "sources_used": ["category_info"],
            }

    # Case E: Default fallback with helpful context
    reply = (
        f"I am your **Guard AI Security Copilot**. I analyze real-time threats intercepted on this website.\n\n"
        f"Currently, this site has recorded **{totals['threats']} threats** ({totals['blocked']} blocked) across **{totals['requests']} total requests**.\n\n"
        f"You can ask me questions such as:\n"
        f"• *\"Why was the latest IP blocked?\"*\n"
        f"• *\"How do I fix SQL injection in FastAPI?\"*\n"
        f"• *\"Summarize today's attacks\"*\n"
        f"• *\"How do I prevent Path Traversal?\"*"
    )
    sugs = [
        "Why was the last IP blocked?",
        "How do I fix SQL injection in FastAPI?",
        "Summarize attacks today",
    ]
    return {
        "reply": reply,
        "suggestions": sugs,
        "suggested_actions": sugs,
        "source": "expert_engine",
        "sources_used": ["fallback"],
    }
