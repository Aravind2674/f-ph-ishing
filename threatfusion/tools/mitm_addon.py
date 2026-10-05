"""
ThreatFusion – mitmproxy Live-Capture Addon  (Phase 3)
=======================================================

Streams live HTTP(S) traffic through the neural HTTP attack classifier as you
browse. This is the real-time bridge: every request that passes through the
proxy is forwarded to the ThreatFusion backend's ``/traffic/analyze`` endpoint
and scored, and any injection attempt is printed to the mitmproxy event log.

mitmproxy is the programmable, scriptable equivalent of Burp Suite's proxy — it
decrypts HTTPS (with its CA installed) and hands each flow to this Python addon.

Usage
-----
1. Install mitmproxy in *your* environment (not a backend dependency):

       pip install mitmproxy

2. Start the ThreatFusion backend (so ``/traffic/analyze`` is reachable):

       cd threatfusion/backend && python -m uvicorn app.main:app --port 8000

3. Run mitmproxy with this addon and browse the **authorised** target through it:

       mitmdump -s threatfusion/tools/mitm_addon.py

   Point your browser/tool at the proxy (default http://127.0.0.1:8080) and
   install mitmproxy's CA to intercept HTTPS. Set TF_BACKEND to override the
   backend URL and TF_API_TOKEN to the token printed by `python -m app.core.auth`.

Scope & safety
--------------
Only run this against traffic you are authorised to test. The addon is passive —
it observes and scores; it neither blocks nor modifies requests. Cookie, Authorization and
API-key style headers are redacted before anything is sent to the backend.
"""

from __future__ import annotations

import os
import urllib.request
import json

BACKEND = os.environ.get("TF_BACKEND", "http://127.0.0.1:8000").rstrip("/")
ANALYZE_URL = f"{BACKEND}/traffic/analyze"
# The backend requires a Bearer token (A0-8): `python -m app.core.auth` prints it.
API_TOKEN = os.environ.get("TF_API_TOKEN", "")
# Skip static asset noise — these rarely carry injection and flood the log.
_SKIP_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
             ".woff2", ".ico", ".map", ".mp4", ".webp")


# Credential-bearing headers are never forwarded to the backend (A0-10). Kept dependency-free on purpose:
# this file runs inside mitmproxy's own Python environment, not the backend's.
_REDACTED = "[redacted]"
_SENSITIVE_HEADERS = {
    "cookie", "cookie2", "set-cookie", "set-cookie2", "authorization", "proxy-authorization",
    "x-api-key", "apikey", "api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
    "x-amz-security-token", "x-goog-api-key",
}
_SENSITIVE_FRAGMENTS = ("token", "secret", "apikey", "api-key", "api_key", "session", "password",
                        "passwd", "credential", "signature")


def redact_headers(headers: dict) -> dict:
    """Replace the values of credential-bearing headers (case-insensitive)."""
    out = {}
    for k, v in (headers or {}).items():
        name = str(k).strip().lower()
        sensitive = name in _SENSITIVE_HEADERS or any(f in name for f in _SENSITIVE_FRAGMENTS)
        out[k] = _REDACTED if sensitive else v
    return out


def _score(method: str, url: str, headers: dict, body: str | None) -> dict | None:
    headers = redact_headers(headers)
    payload = json.dumps({
        "requests": [{"method": method, "url": url, "headers": headers, "body": body}]
    }).encode("utf-8")
    req = urllib.request.Request(
        ANALYZE_URL, data=payload,
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as exc:  # backend down / slow — never break the proxy
        print(f"[threatfusion] backend unreachable: {exc}")
        return None


def request(flow) -> None:  # mitmproxy hook, called for every request
    r = flow.request
    if r.path.lower().rsplit("?", 1)[0].endswith(_SKIP_EXT):
        return

    headers = {k: v for k, v in r.headers.items()}
    body = None
    try:
        if r.raw_content:
            body = r.get_text(strict=False)
    except Exception:
        body = None

    result = _score(r.method, r.url, headers, body)
    if not result or not result.get("findings"):
        return

    finding = result["findings"][0]
    if finding.get("is_attack"):
        span = finding.get("suspicious_span")
        print(
            f"[threatfusion] ⚠ {finding['worst_label'].upper()} "
            f"({finding['worst_confidence']:.0%}) in {r.method} {r.url} "
            f"@ {finding['worst_location']}"
            + (f"  token={span!r}" if span else "")
        )


if __name__ == "__main__":
    print("Run me with mitmproxy, not directly:\n"
          "    mitmdump -s threatfusion/tools/mitm_addon.py")
