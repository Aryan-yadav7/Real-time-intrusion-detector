"""Rule engine for the web IDS.

inspect_request() looks at every part of an HTTP request that an attacker
controls (path, query string, body and a few headers) and returns a list of
Finding objects. It is pure Python with no I/O, so it is fast and easy to
unit test.

Detection steps for each field:
  1. normalize(): URL-decode repeatedly (attackers double-encode), remove SQL
     comments used to split keywords, collapse whitespace, lowercase.
  2. Run every rule's regex against the normalized text.
  3. Return one Finding per (rule, location) that matched.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

SEVERITY_SCORE = {"low": 25, "medium": 50, "high": 75, "critical": 95}

MAX_TEXT = 8192  # inspect at most this many characters of each field


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    description: str
    pattern: "re.Pattern[str]"
    only_in: "tuple[str, ...] | None" = None  # restrict rule to certain locations


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    score: int
    description: str
    location: str  # where it was found: path, query, body, header:user-agent ...
    evidence: str  # the matched payload only (redacted), never the whole request


def _r(rule_id, category, severity, description, regex, only_in=None) -> Rule:
    return Rule(rule_id, category, severity, description,
                re.compile(regex, re.I | re.S), only_in)


RULES: list[Rule] = [
    # ---- SQL injection -------------------------------------------------
    _r("SQLI-001", "sql_injection", "high",
       "Quote-based boolean trick (' OR '1'='1)",
       r"""['"]\s*(?:or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+"""),
    _r("SQLI-002", "sql_injection", "high",
       "Numeric boolean trick (OR 1=1)",
       r"""\b(?:or|and)\s+['"]?(\w+)['"]?\s*=\s*['"]?\1\b"""),
    _r("SQLI-003", "sql_injection", "critical",
       "UNION SELECT used to read other tables",
       r"""\bunion\b(?:\s+all)?\s+select\b"""),
    _r("SQLI-004", "sql_injection", "critical",
       "Stacked query (a second SQL command after ;)",
       r""";\s*(?:drop\s+(?:table|database)|delete\s+from|insert\s+into|"""
       r"""update\s+\w+\s+set|alter\s+table|truncate\s+table|exec(?:ute)?\s)"""),
    _r("SQLI-005", "sql_injection", "high",
       "Time-based blind injection (sleep/benchmark/waitfor)",
       r"""\b(?:sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay"""),
    _r("SQLI-006", "sql_injection", "high",
       "Quote followed by a SQL comment (admin'--)",
       r"""['"]\s*--(?![a-z0-9])"""),
    _r("SQLI-007", "sql_injection", "high",
       "Probing database internals",
       r"""\binformation_schema\b|\bsqlite_master\b|\bpg_catalog\b|@@version"""),

    # ---- Cross-site scripting ------------------------------------------
    _r("XSS-001", "xss", "high",
       "<script> tag",
       r"""<\s*script\b"""),
    _r("XSS-002", "xss", "high",
       "HTML tag with an event handler (onerror=, onload=...)",
       r"""<[^>]{0,200}\bon\w+\s*="""),
    _r("XSS-003", "xss", "medium",
       "javascript: URL",
       r"""javascript\s*:"""),
    _r("XSS-004", "xss", "medium",
       "Embedded frame/object tag",
       r"""<\s*(?:iframe|object|embed)\b"""),
    _r("XSS-005", "xss", "medium",
       "Script reading cookies or redirecting the page",
       r"""document\.(?:cookie|location)|window\.location"""),

    # ---- Path traversal -------------------------------------------------
    _r("PT-001", "path_traversal", "high",
       "Directory traversal (../)",
       r"""\.\.[/\\]"""),
    _r("PT-002", "path_traversal", "high",
       "Access to well-known system files",
       r"""/etc/(?:passwd|shadow|hosts)\b|\b(?:boot|win)\.ini\b|c:[/\\]windows"""),

    # ---- Command injection ---------------------------------------------
    _r("CMD-001", "command_injection", "high",
       "Shell separator followed by a command",
       r"""(?:;|&&|\|\||\||`|[\r\n])\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|"""
       r"""bash|sh|powershell|cmd|ping|rm|dir|type|certutil)\b"""),
    _r("CMD-002", "command_injection", "medium",
       "Command substitution $(...)",
       r"""\$\(\s*[a-z]"""),

    # ---- PHP / server-side code injection -------------------------------
    _r("PHP-001", "php_injection", "high",
       "PHP code (<?php)",
       r"""<\?php\b"""),
    _r("PHP-002", "php_injection", "critical",
       "Dangerous PHP function fed with request data",
       r"""\b(?:eval|assert|system|passthru|shell_exec|exec)\s*\(\s*\$_(?:get|post|request|cookie)"""
       r"""|\beval\s*\(\s*base64_decode"""),
    _r("PHP-003", "php_injection", "high",
       "PHP stream wrapper (php://input, php://filter ...)",
       r"""php://(?:input|filter|stdin|memory|temp)|\b(?:expect|phar)://"""),

    # ---- Log4Shell / JNDI -----------------------------------------------
    _r("JNDI-001", "jndi_injection", "critical",
       "Log4Shell-style JNDI lookup (${jndi:...})",
       r"""\$\{\s*jndi\s*:"""),

    # ---- Template injection (SSTI) --------------------------------------
    _r("SSTI-001", "template_injection", "high",
       "Template math probe ({{7*7}} or ${7*7})",
       r"""\{\{\s*\d+\s*[*+\-/]\s*\d+\s*\}\}|\$\{\s*\d+\s*[*+\-/]\s*\d+\s*\}"""),
    _r("SSTI-002", "template_injection", "critical",
       "Template expression reaching into Python/system internals",
       r"""\{[{%][^}]{0,120}(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|"""
       r"""__import__|\bos\.popen|\bsubprocess)"""),

    # ---- NoSQL injection ------------------------------------------------
    _r("NOSQL-001", "nosql_injection", "high",
       "MongoDB-style operator injected into a field",
       r"""\[\s*\$(?:ne|gt|gte|lt|lte|regex|where|nin|exists|eq)\s*\]"""
       r"""|["']\$(?:ne|gt|gte|lt|lte|regex|where|nin|exists|eq)["']\s*:"""),

    # ---- CRLF / header injection ----------------------------------------
    _r("CRLF-001", "crlf_injection", "high",
       "Line break followed by an HTTP header (header injection)",
       r"""[\r\n]\s*(?:set-cookie|location|content-type|content-length|refresh|host|cookie|x-[a-z-]+)\s*:""",
       only_in=("path", "query")),

    # ---- Probing for sensitive files (never legitimate on a normal site) --
    _r("PROBE-001", "probe", "medium",
       "Request for a sensitive or admin file",
       r"""/\.(?:env|git|svn|hg|htaccess|htpasswd|ds_store|aws|ssh|bash_history)\b"""
       r"""|/wp-(?:admin|login\.php|config\.php)|/xmlrpc\.php|/phpmyadmin|/pma/|/adminer\b"""
       r"""|/(?:backup|dump|database|db|site)\.(?:sql|zip|tar|tgz|gz|bak|7z)\b"""
       r"""|/server-status|/actuator/(?:env|heapdump|beans)|/web-inf/|/cgi-bin/""",
       only_in=("path",)),
    _r("PROBE-002", "probe", "medium",
       "Query parameter targeting a sensitive or secret file",
       r"""(?:\b|/|=)\.(?:env|git|aws|ssh|htaccess|htpasswd)\b""",
       only_in=("query",)),

    # ---- Scanning tools -------------------------------------------------
    _r("SCAN-001", "scanner", "medium",
       "Known attack/scanning tool in User-Agent",
       r"""sqlmap|nikto|nmap|nessus|acunetix|dirbuster|gobuster|wfuzz|masscan|"""
       r"""burpsuite|havij""",
       only_in=("header:user-agent",)),
]

_SQL_COMMENT = re.compile(r"/\*.*?\*/", re.S)
# Collapse spaces/tabs but KEEP newlines: CRLF header injection needs to see them.
_WS = re.compile(r"[ \t\f\v]+")
# Log4Shell obfuscation: ${lower:j} and ${::-j} both mean just "j".
_LOOKUP = re.compile(r"\$\{(?:lower|upper)?:+-?([^}:]*)\}", re.I)
_SECRET = re.compile(
    r"""(password|passwd|pwd|token|secret|api[_-]?key)(["']?\s*[=:]\s*["']?)[^&"'\s,}]*""",
    re.I,
)


def _normalize_variant(text: str, remove_comments: bool = False) -> str:
    """Undo common evasion tricks so the rules see the real payload."""
    text = text.replace("\x00", "")
    for _ in range(3):  # handles double/triple URL-encoding
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    if remove_comments:
        text = _SQL_COMMENT.sub("", text)  # un/**/ion -> union, sel/**/ect -> select
    else:
        text = _SQL_COMMENT.sub(" ", text)  # un/**/ion -> un ion, union/**/select -> union select
    for _ in range(3):  # un-nest ${${lower:j}ndi:...} style tricks
        simplified = _LOOKUP.sub(r"\1", text)
        if simplified == text:
            break
        text = simplified
    return _WS.sub(" ", text).strip().lower()


def normalize(text: str) -> str:
    return _normalize_variant(text, remove_comments=False)


def _evidence(match: "re.Match[str]", location: str) -> str:
    if location == "header:cookie":
        return "[redacted: cookie]"
    snippet = _SECRET.sub(lambda s: s.group(1) + s.group(2) + "***", match.group(0))
    return snippet.replace("\r", " ").replace("\n", " ")[:120]


def inspect_request(method: str, path: str, query: str, headers: dict, body: str) -> list[Finding]:
    """Return findings sorted by score (highest first). headers: lowercase keys."""
    targets = [("path", path), ("query", query), ("body", body)]
    for name in ("user-agent", "referer", "cookie", "x-forwarded-for"):
        if name in headers:
            targets.append((f"header:{name}", headers[name]))

    findings: list[Finding] = []
    for location, raw in targets:
        if not raw:
            continue
        norm = normalize(raw[:MAX_TEXT])
        variants = [norm]
        if "/*" in raw:
            collapsed = _normalize_variant(raw[:MAX_TEXT], remove_comments=True)
            if collapsed != norm:
                variants.append(collapsed)

        matched_rules = set()
        for variant in variants:
            for rule in RULES:
                if rule.id in matched_rules:
                    continue
                if rule.only_in and location not in rule.only_in:
                    continue
                m = rule.pattern.search(variant)
                if m:
                    matched_rules.add(rule.id)
                    findings.append(Finding(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        score=SEVERITY_SCORE[rule.severity],
                        description=rule.description,
                        location=location,
                        evidence=_evidence(m, location),
                    ))
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


def risk_score(findings: list[Finding]) -> int:
    """0-100. Highest finding, plus 5 for every extra distinct rule that fired."""
    if not findings:
        return 0
    distinct = len({f.rule_id for f in findings})
    return min(100, findings[0].score + 5 * (distinct - 1))
