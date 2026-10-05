"""A0-5 — configuration validation (AUDIT_REPORT.md §F.2, §H9).

Audit finding: ``NVD_API_KEY`` was absent from ``.env`` so ``Settings`` fell back to the
sentinel ``PASTE_YOUR_NVD_KEY_HERE`` — a *truthy* string that ``CVEClient`` then sent to NVD
as if it were a real key.  Every CVE lookup silently returned nothing.

Contract now:
* placeholder / empty values are treated as **unset** (never sent anywhere);
* the app reports, per provider, whether it is configured (``/health`` + startup log) —
  as labels/booleans only, never values;
* a provider that is not configured is **never called** in live mode; the scan lists it
  as *skipped* and the UI says "not configured".
"""

from __future__ import annotations

import logging
from typing import Iterator

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings, is_placeholder_secret
from tests.conftest import mock_site


def _settings(**kw) -> Settings:
    # _env_file=None: never let a developer's real .env leak into a unit test.
    return Settings(_env_file=None, **kw)


# ── placeholder detection ───────────────────────────────────────────────────
@pytest.mark.parametrize("value", [
    "", "   ", "PASTE_YOUR_NVD_KEY_HERE", "paste_your_virustotal_key_here",
    "your_api_key_here", "YOUR-TOKEN-HERE", "<your key>", "changeme", "xxxxxxxx", "TODO",
])
def test_placeholders_are_detected(value: str) -> None:
    assert is_placeholder_secret(value)


@pytest.mark.parametrize("value", ["a" * 64, "f3a9c0de11", "sk_live_abc123", "AbC-123_xyz.789"])
def test_real_looking_values_are_not_placeholders(value: str) -> None:
    assert not is_placeholder_secret(value)


def test_placeholder_secret_is_normalised_to_unset() -> None:
    s = _settings(NVD_API_KEY="PASTE_YOUR_NVD_KEY_HERE", VIRUSTOTAL_API_KEY="real-looking-key-123")
    assert s.NVD_API_KEY == ""          # never truthy, so no client will send it
    assert s.VIRUSTOTAL_API_KEY == "real-looking-key-123"


def test_missing_keys_default_to_unset_not_to_a_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "NVD_API_KEY"):
        monkeypatch.delenv(name, raising=False)  # conftest sets test values
    s = _settings()
    assert s.NVD_API_KEY == "" and s.VIRUSTOTAL_API_KEY == "" and s.SHODAN_API_KEY == ""


# ── provider status table ───────────────────────────────────────────────────
def test_live_provider_status_distinguishes_missing_placeholder_configured() -> None:
    s = _settings(USE_MOCK_DATA=False, VIRUSTOTAL_API_KEY="vt-key-123456",
                  NVD_API_KEY="PASTE_YOUR_NVD_KEY_HERE")
    st = s.provider_statuses()
    assert st["virustotal"].configured and st["virustotal"].state == "configured"
    assert not st["nvd"].configured and st["nvd"].state == "placeholder"
    assert not st["wigle"].configured and st["wigle"].state == "missing"
    assert st["shodan_internetdb"].configured and st["shodan_internetdb"].state == "keyless"
    assert not any(p.mock for p in st.values())


def test_mock_mode_reports_every_provider_as_mock() -> None:
    st = _settings(USE_MOCK_DATA=True).provider_statuses()
    assert all(p.mock and p.configured for p in st.values())


def test_wigle_needs_both_halves_of_its_credential() -> None:
    st = _settings(USE_MOCK_DATA=False, WIGLE_API_NAME="AIDabc").provider_statuses()
    assert not st["wigle"].configured


def test_startup_table_lists_states_but_never_values(caplog: pytest.LogCaptureFixture) -> None:
    from app.core.config import log_provider_table

    secret = "SUPERSECRETVALUE0123456789"
    s = _settings(USE_MOCK_DATA=False, VIRUSTOTAL_API_KEY=secret, NVD_API_KEY="PASTE_YOUR_NVD_KEY_HERE")
    with caplog.at_level(logging.INFO, logger="threatfusion.config"):
        log_provider_table(s)
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "virustotal" in text and "nvd" in text
    assert "placeholder" in text and "configured" in text
    assert secret not in text


# ── /health + /scan behaviour ───────────────────────────────────────────────
@pytest.fixture
def live_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Run the app in live mode with a VT key but only a *placeholder* NVD key."""
    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    monkeypatch.setenv("NVD_API_KEY", "PASTE_YOUR_NVD_KEY_HERE")
    monkeypatch.setenv("WIGLE_API_NAME", "")
    monkeypatch.setenv("WIGLE_API_TOKEN", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_health_exposes_provider_states_without_secrets(live_env: None) -> None:
    from app.main import app

    body = TestClient(app).get("/health").json()
    assert body["mock_mode"] is False
    prov = body["providers"]
    assert prov["virustotal"] == {"configured": True, "mock": False, "state": "configured"}
    assert prov["nvd"]["configured"] is False and prov["nvd"]["state"] == "placeholder"
    assert "vt-key-for-tests-123456" not in str(body) and "PASTE_YOUR" not in str(body)


def test_scan_never_calls_an_unconfigured_provider(live_env: None, monkeypatch: pytest.MonkeyPatch, fake_dns) -> None:
    """The audit's NVD case: no real key => no request to NVD, listed as skipped."""
    import socket
    import app.core.validation as validation
    from app.main import app

    async def _ok(target):  # validation does real DNS/HTTP; not under test here
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)

    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(
            200, json={"data": {"attributes": {"last_analysis_stats": {"harmless": 60, "malicious": 0}}}})
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(
            200, json={"ports": [443], "vulns": ["CVE-2021-44228"], "cpes": [], "hostnames": [], "tags": []})
        mock_site(router, "some-site.example", text="<html></html>")
        nvd = router.get(url__regex=r"https://services\.nvd\.nist\.gov/.*").respond(404)

        resp = TestClient(app).post("/scan", json={"target": "some-site.example", "target_type": "domain"})

    result = resp.json()["result"]
    assert not nvd.called, "NVD must not be contacted without a real key"
    assert "NVD" in result["data_sources_skipped"]
    assert "NVD" not in result["data_sources_succeeded"] + result["data_sources_failed"]


def test_scan_without_virustotal_key_skips_virustotal_instead_of_sending_a_placeholder(
    monkeypatch: pytest.MonkeyPatch, fake_dns,
) -> None:
    import socket
    import app.core.validation as validation
    from app.main import app

    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "PASTE_YOUR_VIRUSTOTAL_KEY_HERE")
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    try:
        with respx.mock(assert_all_called=False) as router:
            vt = router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(401)
            router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(404)
            mock_site(router, "some-site.example", text="<html></html>")
            resp = TestClient(app).post("/scan", json={"target": "some-site.example", "target_type": "domain"})
        assert not vt.called
        assert "VirusTotal" in resp.json()["result"]["data_sources_skipped"]
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_app_layer_scorer_reports_unavailable_without_a_virustotal_key(live_env: None, monkeypatch) -> None:
    """Network layer: no VT credential => 'unavailable' with a reason, and no HTTP at all."""
    from app.network.enrichment.app_layer import AppLayerScorer

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "PASTE_YOUR_VIRUSTOTAL_KEY_HERE")
    get_settings.cache_clear()
    with respx.mock(assert_all_called=False) as router:   # unmatched request would raise
        score = await AppLayerScorer().score("example.org", "domain")
        assert len(router.calls) == 0          # asserted inside: respx clears .calls on exit
    assert score.available is False
    assert "not configured" in (score.reason or "").lower()
