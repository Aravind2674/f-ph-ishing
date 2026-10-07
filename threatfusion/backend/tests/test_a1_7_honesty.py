"""A1-7 (backend side) — two places where a scan said more, or something different, than the evidence supports.

Found while checking the evidence-first UI against a real running server:

1. The plain-language ``summary`` described the target with the *experimental* XGBoost label ("presents a low risk
   profile") while the headline severity — the transparent baseline — said MEDIUM.  The summary now follows the
   headline.
2. A **mock-mode** scan still resolved the typed host through the real DNS resolver (to pick an IP for InternetDB),
   so a demo/offline run leaked the hostname to the resolver and could show "Shodan: dns_failure" for a made-up
   name.  Mock mode must touch no network at all.
"""

from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mock_scan_client(monkeypatch: pytest.MonkeyPatch):
    import app.core.validation as validation
    from app.main import app

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    return TestClient(app)


def test_the_summary_follows_the_headline_baseline_not_the_experimental_model(mock_scan_client, monkeypatch) -> None:
    from app.ml.url_risk import UrlRiskService
    from app.models.schemas import UrlRiskAssessment

    def low(self, url):                                                                   # the URL-text model says "Low"
        return UrlRiskAssessment(score=0.01, headline_score=0.01, flagged=False), [], []

    monkeypatch.setattr(UrlRiskService, "assess", low)
    body = mock_scan_client.post("/scan", json={"target": "evil-login.example.com", "target_type": "domain"}).json()
    r = body["result"]
    assert r["baseline_label"] not in ("Low", "Unknown") and r["ml_label"] == "Low", (r["baseline_label"], r["ml_label"])
    summary = r["summary"].lower()
    assert f"{r['baseline_label'].lower()} risk profile" in summary
    assert "low risk profile" not in summary, "the experimental model's label must not describe the target"


def test_with_no_baseline_the_summary_does_not_invent_a_risk_profile(mock_scan_client, monkeypatch) -> None:
    import app.api.scan as scan_module
    monkeypatch.setattr(scan_module, "baseline_score", lambda features: None)
    r = mock_scan_client.post("/scan", json={"target": "plain.example.com", "target_type": "domain"}).json()["result"]
    assert r["baseline_score"] is None and "risk profile" not in r["summary"].lower()
    # the headline then rests on the URL text alone, and the summary says exactly that
    assert r["driven_by"] in ("url_model", None)
    if r["headline_band"]:
        assert "url text alone" in r["summary"].lower() and "no provider evidence" in r["summary"].lower()


def test_a_mock_mode_scan_makes_no_dns_lookup_at_all(mock_scan_client, monkeypatch) -> None:
    calls: list[str] = []
    real_getaddrinfo, real_gethostbyname = socket.getaddrinfo, socket.gethostbyname

    def guard(real):
        def inner(host, *a, **k):
            text = host.decode() if isinstance(host, bytes) else str(host)
            if "made-up-name" in text:                      # the TYPED target must never reach a resolver
                calls.append(text)
                raise AssertionError(f"mock mode resolved {text!r} through the real resolver")
            return real(host, *a, **k)                      # the test harness's own loopback lookups are fine
        return inner

    monkeypatch.setattr(socket, "getaddrinfo", guard(real_getaddrinfo))
    monkeypatch.setattr(socket, "gethostbyname", guard(real_gethostbyname))
    body = mock_scan_client.post("/scan", json={"target": "made-up-name.example.com", "target_type": "domain"}).json()
    r = body["result"]
    shodan = next(o for o in r["provider_results"] if o["source"] == "shodan_internetdb")
    assert body["success"] is True and shodan["status"] == "ok" and shodan["mock"] is True, shodan
    assert calls == []
