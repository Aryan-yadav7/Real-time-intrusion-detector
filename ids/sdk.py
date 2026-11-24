"""The SDK a customer adds to THEIR website (three lines):

    from ids.sdk import SentinelMiddleware

    app.add_middleware(SentinelMiddleware, api_key="sk_...", server="https://sentinel.example.com",
                       mode="detect",          # use mode="block" to also stop attacks
                       exempt_prefixes=("/api/webhooks",), # skip trusted webhooks
                       allowlist_ips=("192.168.1.100",))   # skip trusted office IPs

Detection and blocking happen inside the customer's own process (fast, works even if
the Sentinel platform is down). Only metadata is sent to the platform, in the background:
the path (never the query string), a short redacted snippet, IP and User-Agent.
Passwords, cookies and request bodies never leave the customer's server.
"""
from __future__ import annotations

from .middleware import IDSMiddleware
from .sinks import RemoteSink


# Keep old name as an alias for backwards compatibility
class SentinelMiddleware(IDSMiddleware):
    def __init__(self, app, api_key: str, server: str = "http://127.0.0.1:9000",
                 mode: str = "detect", sink=None, **kwargs):
        sink = sink or RemoteSink(api_key, server, mode=mode)
        super().__init__(app, mode=mode, sink=sink, site_id="remote", **kwargs)


# Backwards-compatible alias
GuardMiddleware = SentinelMiddleware
