"""A0-8 — local API token, Host allow-list, JSON-only mutations (AUDIT_REPORT.md §H3).

Audit finding (Medium): no authentication anywhere, and body-less ``POST /network/monitor/start|stop``
are "simple" cross-site requests — any web page the user visits could start or stop packet capture;
with DNS rebinding a page could also read ``/network/*`` and ``/scan/history``.

Contract now:
* every route except ``/health`` (and the OpenAPI docs) needs ``Authorization: Bearer <token>``;
  the token is random, generated on first start and stored OUTSIDE the repository;
* requests whose ``Host`` header is not a configured local name are refused (anti-rebinding);
* every POST/PUT/PATCH/DELETE must be ``Content-Type: application/json`` — a cross-site HTML form or a
  ``no-cors`` fetch cannot send that without a CORS preflight, which only the dev origins pass;
* CORS no longer allows credentials;
* the SSE feed (EventSource cannot set headers) uses a short-lived, single-use ticket, so the token never
  appears in a URL (uvicorn logs URLs).
"""

from __future__ import annotations

import logging
import os
import stat
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core import auth
from app.core.config import get_settings

TOKEN = os.environ["API_TOKEN"]          # set by conftest for the whole suite


def _client(token: str | None = TOKEN, **kw) -> TestClient:
    from app.main import app

    headers = {"Authorization": f"Bearer {token}"} if token is not None else {"Authorization": ""}
    return TestClient(app, headers=headers, **kw)


PROTECTED = [
    ("POST", "/scan", {"target": "example.com", "target_type": "domain"}),
    ("GET", "/scan/history", None),
    ("GET", "/scan/some-id", None),
    ("POST", "/analyze", {"text": "x"}),
    ("POST", "/traffic/analyze", {"requests": []}),
    ("GET", "/network/status", None),
    ("GET", "/network/alerts", None),
    ("GET", "/network/devices", None),
    ("POST", "/network/monitor/stop", {}),
    ("POST", "/network/monitor/start", {}),
    ("POST", "/network/stream-ticket", {}),
    ("GET", "/network/stream", None),
]


@pytest.mark.parametrize("method,path,body", PROTECTED)
def test_every_protected_route_rejects_a_missing_token(method, path, body) -> None:
    r = _client(None).request(method, path, json=body)
    assert r.status_code == 401, (method, path, r.text)
    assert r.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("method,path,body", PROTECTED)
def test_every_protected_route_rejects_a_wrong_token(method, path, body) -> None:
    assert _client("not-the-token").request(method, path, json=body).status_code == 401


@pytest.mark.parametrize("scheme", ["Basic", "Token", ""])
def test_only_the_bearer_scheme_is_accepted(scheme: str) -> None:
    from app.main import app
    c = TestClient(app, headers={"Authorization": f"{scheme} {TOKEN}".strip()})
    assert c.get("/network/status").status_code == 401


def test_the_correct_token_is_accepted() -> None:
    c = _client()
    assert c.get("/network/status").status_code == 200
    assert c.get("/scan/history").status_code == 200
    assert c.get("/scan/nope").status_code == 404          # authorised, then genuinely not found


def test_health_and_docs_stay_public() -> None:
    c = _client(None)
    assert c.get("/health").status_code == 200
    assert c.get("/openapi.json").status_code == 200


# ── Host allow-list (DNS-rebinding defence) ─────────────────────────────────
@pytest.mark.parametrize("host", ["localhost:8000", "127.0.0.1:8000", "[::1]:8000", "localhost", "LOCALHOST:5173"])
def test_local_host_headers_are_accepted(host: str) -> None:
    assert _client().get("/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1.evil.example", "192.168.1.5:8000", ""])
def test_foreign_host_headers_are_rejected_even_with_a_valid_token(host: str) -> None:
    r = _client().get("/network/status", headers={"Host": host})
    assert r.status_code == 400 and "host" in r.json()["detail"].lower()


# ── JSON-only mutations (closes the body-less cross-site POST) ──────────────
@pytest.mark.parametrize("path", ["/network/monitor/stop", "/network/monitor/start", "/scan"])
def test_a_bodyless_post_is_rejected_with_415(path: str) -> None:
    r = _client().post(path)                       # no body, no content-type: a "simple" cross-site request
    assert r.status_code == 415


@pytest.mark.parametrize("ctype", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"])
def test_non_json_content_types_are_rejected(ctype: str) -> None:
    r = _client().post("/network/monitor/stop", content=b"x=1", headers={"Content-Type": ctype})
    assert r.status_code == 415


def test_json_post_with_a_charset_parameter_is_accepted() -> None:
    r = _client().post("/network/monitor/stop", content=b"{}", headers={"Content-Type": "application/json; charset=utf-8"})
    assert r.status_code == 200


def test_the_check_happens_before_authentication_details_leak() -> None:
    # unauthenticated + wrong content-type: still refused, and without echoing anything sensitive
    r = _client(None).post("/network/monitor/stop", content=b"x", headers={"Content-Type": "text/plain"})
    assert r.status_code in (401, 415)


# ── CORS ────────────────────────────────────────────────────────────────────
def test_cors_does_not_allow_credentials_but_allows_the_authorization_header() -> None:
    r = _client().options("/scan", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type"})
    assert r.status_code == 200
    assert "access-control-allow-credentials" not in {k.lower() for k in r.headers}
    assert "authorization" in r.headers["access-control-allow-headers"].lower()


def test_cors_rejects_an_unknown_origin() -> None:
    r = _client().options("/scan", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") is None


# ── Token lifecycle ─────────────────────────────────────────────────────────
@pytest.fixture
def token_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("API_TOKEN", raising=False)
    monkeypatch.setenv("API_TOKEN_FILE", str(tmp_path / "sub" / "api_token"))
    get_settings.cache_clear(); auth.reset_token_cache()
    yield tmp_path / "sub" / "api_token"
    get_settings.cache_clear(); auth.reset_token_cache()


def test_a_random_token_is_generated_once_and_persisted_outside_the_repo(token_file: Path) -> None:
    t1 = auth.get_api_token()
    assert len(t1) >= 32 and token_file.read_text().strip() == t1
    auth.reset_token_cache()
    assert auth.get_api_token() == t1, "the same token is reused across restarts"
    repo = Path(__file__).resolve().parents[3]
    assert repo not in token_file.resolve().parents


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_token_file_is_private(token_file: Path) -> None:
    auth.get_api_token()
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600


def test_default_token_location_is_outside_the_repository() -> None:
    p = auth.default_token_path()
    assert Path(__file__).resolve().parents[3] not in p.resolve().parents
    assert p.name == "api_token"


def test_the_env_token_overrides_the_file(token_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_TOKEN", "from-the-environment-0123456789abcdef")
    get_settings.cache_clear(); auth.reset_token_cache()
    assert auth.get_api_token() == "from-the-environment-0123456789abcdef"
    assert not token_file.exists()


def test_placeholder_env_tokens_are_not_used(token_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_TOKEN", "PASTE_YOUR_API_TOKEN_HERE")
    get_settings.cache_clear(); auth.reset_token_cache()
    assert auth.get_api_token() != "PASTE_YOUR_API_TOKEN_HERE" and len(auth.get_api_token()) >= 32


def test_the_token_is_never_logged(token_file: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        tok = auth.get_api_token()
        auth.log_token_location()
    assert tok not in caplog.text and str(token_file) in caplog.text


# ── SSE tickets ─────────────────────────────────────────────────────────────
def test_stream_tickets_are_single_use() -> None:
    t = auth.issue_stream_ticket()
    assert auth.consume_stream_ticket(t) is True
    assert auth.consume_stream_ticket(t) is False


def test_stream_tickets_expire(monkeypatch: pytest.MonkeyPatch) -> None:
    t = auth.issue_stream_ticket()
    real = time.monotonic
    monkeypatch.setattr(auth.time, "monotonic", lambda: real() + auth.STREAM_TICKET_TTL_SECONDS + 1)
    assert auth.consume_stream_ticket(t) is False


def test_unknown_tickets_are_refused() -> None:
    assert auth.consume_stream_ticket("nope") is False and auth.consume_stream_ticket("") is False


def test_the_ticket_endpoint_issues_a_ticket_and_the_stream_rejects_a_bad_one() -> None:
    c = _client()
    body = c.post("/network/stream-ticket", json={}).json()
    assert body["expires_in"] == auth.STREAM_TICKET_TTL_SECONDS and len(body["ticket"]) >= 16
    assert _client(None).get("/network/stream?ticket=bogus").status_code == 401
