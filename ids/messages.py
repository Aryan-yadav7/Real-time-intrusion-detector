"""Plain-language descriptions of every kind of threat.

The dashboard is meant for people who are not security experts, so every
event is translated into: a headline, a one-sentence explanation, and a
"what to do" tip. These templates are also the fallback when the AI layer
(Day 4) is unavailable, so the dashboard never depends on an LLM.
"""
from __future__ import annotations

# category -> plain label, technical name, headline, explanation, advice
CATEGORY_INFO = {
    "sql_injection": dict(
        label="Database tricks", tech="SQL injection",
        headline="Someone tried to trick your database",
        explanation="A visitor typed special database commands into a form or web address, "
                    "hoping your site would run them and hand over or change private data.",
        advice="Make sure the site uses parameterized (prepared) queries and never builds "
               "database commands by gluing user text together."),
    "nosql_injection": dict(
        label="Database tricks", tech="NoSQL injection",
        headline="Someone tried to trick your database",
        explanation="A visitor sent special operators (like $ne) hoping to log in or read data "
                    "without the right password.",
        advice="Validate that login fields are plain text, not objects, before querying."),
    "xss": dict(
        label="Script planting", tech="Cross-site scripting (XSS)",
        headline="Someone tried to plant a harmful script",
        explanation="A visitor tried to slip a small program into your page so it would run "
                    "in other people's browsers, for example to steal their login.",
        advice="Escape everything users type before showing it on a page, and add a "
               "Content-Security-Policy header."),
    "path_traversal": dict(
        label="File snooping", tech="Path traversal",
        headline="Someone tried to read private files on your server",
        explanation="A visitor used ../ tricks to climb out of the public folder and open "
                    "files such as passwords or settings.",
        advice="Never use user input directly in file paths; allow only a fixed list of files."),
    "command_injection": dict(
        label="Server commands", tech="Command injection",
        headline="Someone tried to run commands on your server",
        explanation="A visitor hid operating-system commands inside a form or address, "
                    "hoping the server would execute them.",
        advice="Avoid running shell commands with user input; use safe library functions instead."),
    "php_injection": dict(
        label="Code injection", tech="PHP / code injection",
        headline="Someone tried to send code for your server to run",
        explanation="A visitor sent program code instead of normal text, hoping your server "
                    "would run it and give them control.",
        advice="Never evaluate user input as code, and keep your software up to date."),
    "template_injection": dict(
        label="Code injection", tech="Template injection",
        headline="Someone tried to make your server run their formula",
        explanation="A visitor sent a template expression (like {{7*7}}) to test whether "
                    "your server would evaluate it, a first step toward taking control.",
        advice="Do not build templates from user text; pass user data only as variables."),
    "jndi_injection": dict(
        label="Known exploits", tech="Log4Shell (JNDI)",
        headline="Someone tried a famous remote-takeover trick (Log4Shell)",
        explanation="A visitor sent a special ${jndi:...} string that, on unpatched Java "
                    "software, makes the server contact the attacker and run their code.",
        advice="If you use Java, make sure Log4j is version 2.17.1 or newer."),
    "crlf_injection": dict(
        label="Header tricks", tech="CRLF / header injection",
        headline="Someone tried to sneak fake instructions into your site's messages",
        explanation="A visitor added hidden line breaks to a web address, hoping to forge "
                    "extra headers such as cookies or redirects.",
        advice="Reject line breaks in any value that ends up in a response header."),
    "scanner": dict(
        label="Hacking tools", tech="Automated scanner",
        headline="An automated hacking tool visited your site",
        explanation="A program known for hunting vulnerabilities announced itself while "
                    "visiting. This usually means someone is probing your site.",
        advice="Keep software updated; this alone is not a break-in."),
    "probe": dict(
        label="Hidden-file hunting", tech="Sensitive file probing",
        headline="Someone looked for secret or admin files",
        explanation="A visitor asked for files that should never be public, such as .env, "
                    ".git or admin panels, hoping you left one exposed.",
        advice="Check that those files are not reachable from the internet."),
    "brute_force": dict(
        label="Password guessing", tech="Brute force",
        headline="Someone is guessing passwords",
        explanation="The same visitor failed to log in many times in a row, trying one "
                    "password after another.",
        advice="Use strong passwords, rate-limit logins and consider two-factor login."),
    "credential_stuffing": dict(
        label="Stolen-login attempts", tech="Credential stuffing",
        headline="Someone is trying lots of different stolen logins",
        explanation="One visitor tried many different usernames, most likely reusing "
                    "passwords leaked from other websites.",
        advice="Offer two-factor login and encourage unique passwords."),
    "flood": dict(
        label="Request flooding", tech="Flood / DoS-style traffic",
        headline="Your site is being flooded with requests",
        explanation="One visitor is sending far more requests than any real person could, "
                    "which can slow your site down for everyone.",
        advice="Add rate limiting, and use a CDN or firewall service if this keeps happening."),
    "scanning": dict(
        label="Site scanning", tech="Page scanning",
        headline="Someone is searching your site for weak spots",
        explanation="One visitor asked for lots of pages that do not exist, a common way "
                    "to discover hidden or vulnerable parts of a site.",
        advice="No action needed unless it continues; consider blocking the address."),
}

GENERIC = dict(
    label="Other", tech="Unknown",
    headline="Something suspicious was detected",
    explanation="A request looked unusual and was flagged for review.",
    advice="Review the technical details.")

SEVERITY_LABEL = {"low": "Low risk", "medium": "Medium risk", "high": "High risk",
                  "critical": "Critical risk"}
LEVEL = {"low": "info", "medium": "warning", "high": "danger", "critical": "danger"}


def category_info(category: str) -> dict:
    return CATEGORY_INFO.get(category, GENERIC)


def action_text(action: str, category: str) -> str:
    if action == "blocked":
        if category in ("flood", "brute_force", "credential_stuffing"):
            return "We temporarily blocked this visitor."
        return "We blocked it."
    return "We spotted it but let it through (monitoring mode)."


def describe_event(event: dict) -> dict:
    """Turn a database row into something safe and friendly to show on the dashboard."""
    info = category_info(event.get("category") or "")
    severity = event.get("severity") or "medium"
    return {
        "id": event["id"],
        "ts": event["ts"],
        "headline": info["headline"],
        "explanation": info["explanation"],
        "advice": info["advice"],
        "label": info["label"],
        "severity": severity,
        "severity_label": SEVERITY_LABEL.get(severity, "Medium risk"),
        "level": LEVEL.get(severity, "warning"),
        "action": event.get("action"),
        "action_text": action_text(event.get("action") or "", event.get("category") or ""),
        "ip": event.get("ip"),
        "path": event.get("path"),
        "technical": {
            "type": info["tech"],
            "category": event.get("category"),
            "rule_id": event.get("rule_id"),
            "rules": event.get("rules"),
            "score": event.get("score"),
            "method": event.get("method"),
            "location": event.get("location"),
            "evidence": event.get("evidence"),
            "user_agent": event.get("user_agent"),
        },
    }
