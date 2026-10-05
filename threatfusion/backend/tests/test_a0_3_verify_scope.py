"""A0-3 — server-side scope for ``POST /verify`` (AUDIT_REPORT.md §H1).

Audit finding (High): the authorisation list came from the *same request body* that named the target,
so any caller could attest to any host and make the server send XSS-canary and SQLi probes to it —
including internal addresses — with TLS verification off.

Contract now:
* ``VERIFY_ENABLED`` is false by default; nothing is probed until an operator turns it on;
* the allowlist is **server configuration** (``VERIFY_ALLOWED_HOSTS``); ``authorized_hosts`` in the
  body is ignored (and the response says so);
* loopback is no longer implicitly in scope; internal/private targets only if the operator lists them,
  and even then never link-local/metadata;
* every probe goes through the SSRF-safe fetcher, with TLS verification on by default;
* runs are rate-limited per host;
* every call — including refused ones — writes an append-only ``verify_audit`` row.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.verify.active import ActiveVerifier, host_is_authorized
from tests.conftest import mock_site

TARGET = "http://lab.test:8099/search?q=test"


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake_dns):
    """Isolated DB + helper to (re)configure /verify via environment, like an operator would."""
    db = tmp_path / "audit.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    fake_dns.set("lab.test", "127.0.0.1")

    def configure(**kw) -> None:
        defaults = {"VERIFY_ENABLED": "true", "VERIFY_ALLOWED_HOSTS": "lab.test:8099",
                    "VERIFY_RATE_PER_MINUTE": "50", "VERIFY_TLS": "true"}
        defaults.update({k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in kw.items()})
        for k, v in defaults.items():
            monkeypatch.setenv(k, v)
        get_settings.cache_clear()
        from app.api import verify as verify_api
        verify_api.RATE_LIMITER.clear()

    def rows() -> list[sqlite3.Row]:
        con = sqlite3.connect(db)
        con.row_factory = sqlite3.Row
        try:
            return con.execute("select * from verify_audit order by id").fetchall()
        except sqlite3.OperationalError:
            return []
        finally:
            con.close()

    class E:
        pass
    e = E()
    e.configure, e.rows, e.db = configure, rows, db
    monkeypatch.delenv("VERIFY_ENABLED", raising=False)
    get_settings.cache_clear()
    yield e
    get_settings.cache_clear()


def _lab(request: httpx.Request) -> httpx.Response:
    """A deliberately vulnerable lab: reflects q raw, leaks a SQL error on a quote, boolean-differs."""
    q = request.url.params.get("q", "")
    if "'" in q and "or '1'='1" not in q.lower() and "and '1'='2" not in q.lower():
        return httpx.Response(200, text="You have an error in your SQL syntax near ''")
    if "or '1'='1" in q.lower():
        return httpx.Response(200, text="<ul>" + "<li>row</li>" * 40 + "</ul>")
    if "and '1'='2" in q.lower():
        return httpx.Response(200, text="<ul></ul>")
    return httpx.Response(200, text=f"<h1>Results for {q}</h1>")


def _post(client: TestClient, target: str = TARGET, hosts: list[str] | None = None):
    return client.post("/verify", json={"target": target, "authorized_hosts": hosts or []})


@pytest.fixture
def client() -> TestClient:
    from app.main import app
    return TestClient(app)


# ── Disabled by default ─────────────────────────────────────────────────────
def test_verify_is_disabled_by_default_even_for_loopback(env, client) -> None:
    assert Settings(_env_file=None).VERIFY_ENABLED is False
    with respx.mock(assert_all_called=False) as router:
        data = _post(client, "http://127.0.0.1:8099/user?id=1").json()
        assert len(router.calls) == 0
    assert data["success"] is False and data["authorized"] is False and data["error"] == "verify_disabled"
    assert "disabled" in data["summary"].lower()
    assert [r["outcome"] for r in env.rows()] == ["disabled"]


# ── The request body can no longer grant scope ──────────────────────────────
def test_hosts_supplied_in_the_body_are_ignored_and_refused(env, client) -> None:
    env.configure()  # enabled, but only lab.test:8099 is allowed
    with respx.mock(assert_all_called=False) as router:
        data = _post(client, "http://victim.example/p?q=1", hosts=["victim.example"]).json()
        assert len(router.calls) == 0, "no probe may leave the server for a body-attested host"
    assert data["authorized"] is False and data["success"] is False
    assert "ignored" in (data.get("notice") or "").lower()
    row = env.rows()[-1]
    assert row["outcome"] == "refused_scope" and row["host"] == "victim.example"


def test_a_host_not_in_server_config_is_refused_even_without_body_hosts(env, client) -> None:
    env.configure()
    with respx.mock(assert_all_called=False) as router:
        data = _post(client, "http://other.example/p?q=1").json()
        assert len(router.calls) == 0
    assert data["authorized"] is False
    assert env.rows()[-1]["outcome"] == "refused_scope"


@pytest.mark.parametrize("target", ["http://127.0.0.1:8099/x?q=1", "http://localhost:8099/x?q=1", "http://[::1]:8099/x?q=1"])
def test_loopback_is_no_longer_implicitly_in_scope(env, client, target: str) -> None:
    env.configure(VERIFY_ALLOWED_HOSTS="lab.test:8099")
    with respx.mock(assert_all_called=False) as router:
        data = _post(client, target).json()
        assert len(router.calls) == 0
    assert data["authorized"] is False


def test_scope_entry_with_a_port_only_matches_that_port(env, client) -> None:
    env.configure()
    data = _post(client, "http://lab.test:9999/search?q=1").json()
    assert data["authorized"] is False


def test_host_is_authorized_unit() -> None:
    assert host_is_authorized("staging.internal", {"staging.internal"})
    assert not host_is_authorized("other.internal", {"staging.internal"})
    assert not host_is_authorized("127.0.0.1", set()), "nothing is in scope by default"
    assert host_is_authorized("LAB.test", {"lab.test:8099"}, port=8099)
    assert not host_is_authorized("lab.test", {"lab.test:8099"}, port=80)
    assert host_is_authorized("lab.test", {"lab.test"}, port=1234)


# ── Configured hosts are probed — through the safe fetcher ──────────────────
def test_a_configured_host_is_verified_and_audited(env, client) -> None:
    env.configure()
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "lab.test:8099", ip="127.0.0.1", path="/search", side_effect=_lab)
        data = _post(client).json()
        assert len(router.calls) > 0 and all(c.request.url.host == "127.0.0.1" for c in router.calls), \
            "connected to the validated IP, not a re-resolved name"
    assert data["success"] is True and data["authorized"] is True
    techniques = {p["technique"] for p in data["probes"] if p["confirmed"]}
    assert {"reflected-xss", "error-sqli", "boolean-sqli"} <= techniques
    row = env.rows()[-1]
    assert row["outcome"] == "completed" and row["confirmed_count"] >= 3
    assert row["resolved_ip"] == "127.0.0.1" and row["target"] == TARGET
    assert {"reflected-xss", "error-sqli", "boolean-sqli"} <= set(json.loads(row["checks_run"]))


def test_metadata_addresses_are_refused_even_for_a_listed_host(env, client, fake_dns) -> None:
    """Listing a host lets it be internal — but never link-local / cloud metadata."""
    fake_dns.set("meta.test", "169.254.169.254")
    env.configure(VERIFY_ALLOWED_HOSTS="meta.test:8099")
    with respx.mock(assert_all_called=False) as router:
        data = _post(client, "http://meta.test:8099/x?q=1").json()
        assert len(router.calls) == 0
    assert data["success"] is True and data["confirmed_count"] == 0 and "blocked" in (data["error"] or "")
    assert env.rows()[-1]["outcome"] == "blocked"


def test_redirects_are_not_followed_by_the_verifier(env, client) -> None:
    env.configure()
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "lab.test:8099", ip="127.0.0.1", path="/search", status=302,
                  headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        data = _post(client).json()
        assert all(c.request.url.host == "127.0.0.1" for c in router.calls)
    assert data["confirmed_count"] == 0


# ── TLS verification is on by default ───────────────────────────────────────
def test_tls_verification_defaults_to_on() -> None:
    assert Settings(_env_file=None).VERIFY_TLS is True
    assert ActiveVerifier().fetcher.policy.verify_tls is True
    assert ActiveVerifier(verify_tls=False).fetcher.policy.verify_tls is False


# ── Rate limit + audit trail ────────────────────────────────────────────────
def test_runs_are_rate_limited_per_host_and_the_refusal_is_audited(env, client) -> None:
    env.configure(VERIFY_RATE_PER_MINUTE=2)
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "lab.test:8099", ip="127.0.0.1", path="/search", side_effect=_lab)
        codes = [_post(client).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert [r["outcome"] for r in env.rows()] == ["completed", "completed", "rate_limited"]


def test_every_kind_of_call_writes_exactly_one_audit_row(env, client) -> None:
    _post(client)                                   # disabled
    env.configure()
    _post(client, "http://x.example/p?q=1")         # refused_scope
    with respx.mock(assert_all_called=False) as router:
        mock_site(router, "lab.test:8099", ip="127.0.0.1", path="/search", side_effect=_lab)
        _post(client)                               # completed
    assert [r["outcome"] for r in env.rows()] == ["disabled", "refused_scope", "completed"]
    assert all(r["ts"] and r["target"] for r in env.rows())


def test_audit_table_is_append_only(env, client) -> None:
    _post(client)  # creates the table + one row
    con = sqlite3.connect(env.db)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("UPDATE verify_audit SET outcome='tampered'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("DELETE FROM verify_audit")
    con.close()
    assert len(env.rows()) == 1
