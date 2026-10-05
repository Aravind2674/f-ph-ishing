"""B11 (wiring) — the exposure assessment inside ``POST /scan``.

After InternetDB lists a host's CVEs (and NVD hydrates them), EPSS, KEV and Vulnrichment are asked about those CVEs and the
result is a separate ``ScanResult.exposure`` — **never blended into the maliciousness scores**.  Three-state all the way:
a source that failed makes its part *unknown* (and the exposure says how many CVEs it could not assess), it is never 0.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.core.feeds import FeedStore
from tests.conftest import mock_site

LOG4J, OTHER = "CVE-2021-44228", "CVE-2020-9999"
IDB = {"ports": [443], "cpes": [], "vulns": [LOG4J, OTHER], "hostnames": [], "tags": []}


def nvd_item(cve, score, sev):
    return {"cve": {"id": cve, "descriptions": [{"lang": "en", "value": f"{cve}: remote code execution via a crafted request"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": sev}}]},
                    "published": "2021-12-10T10:15:00.000"}}


KEV_DOC = {"catalogVersion": "2026.10.03", "count": 1, "vulnerabilities": [
    {"cveID": LOG4J, "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Log4Shell",
     "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"}]}
SSVC = {"containers": {"adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [{"other": {"type": "ssvc", "content": {
    "options": [{"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}], "timestamp": "2026-09-30T12:00:00Z"}}}]}]}}


@pytest.fixture
def live_scan(monkeypatch: pytest.MonkeyPatch, fake_dns):
    import app.core.validation as validation
    from fastapi.testclient import TestClient
    from app.core.config import get_settings
    from app.main import app

    for name, value in {"USE_MOCK_DATA": "false", "VIRUSTOTAL_API_KEY": "vt-key-for-tests-123456",
                        "NVD_API_KEY": "nvd-key-for-tests-123456", "RATE_LIMIT_REQUESTS_PER_MINUTE": "1000",
                        "EPSS_ENABLED": "true", "KEV_ENABLED": "true", "VULNRICHMENT_ENABLED": "true"}.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    yield TestClient(app)
    get_settings.cache_clear()


def _scan(client, *, idb=IDB, epss="ok", kev="ok", vr="ok", target="exposed.example.com", scan_id=None):
    def nvd(request: httpx.Request) -> httpx.Response:
        cve = request.url.params["cveId"]
        return httpx.Response(200, json={"vulnerabilities": [nvd_item(cve, 10.0 if cve == LOG4J else 9.8, "CRITICAL")]})

    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(200, json=idb)
        router.get(url__regex=r"https://services\.nvd\.nist\.gov/.*").mock(side_effect=nvd)
        mock_site(router, target, text="<html></html>")
        if epss == "ok":
            router.get(url__regex=r"https://api\.first\.org/data/v1/epss.*").mock(side_effect=lambda r: httpx.Response(200, json={
                "status": "OK", "data": [
                    {"cve": c, "epss": "0.94358" if c == LOG4J else "0.00040", "percentile": "0.99991" if c == LOG4J else "0.08000",
                     "date": "2026-10-03"} for c in r.url.params["cve"].split(",")]}))
        else:
            router.get(url__regex=r"https://api\.first\.org/data/v1/epss.*").respond(503)
        if kev == "ok":
            mock_site(router, "www.cisa.gov", path="/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                      text=json.dumps(KEV_DOC), headers={"content-type": "application/json"})
        else:
            mock_site(router, "www.cisa.gov", path="/sites/default/files/feeds/known_exploited_vulnerabilities.json", status=503, text="")
        if vr == "ok":
            router.get(url__regex=r"https://cveawg\.mitre\.org/api/cve/.*").mock(side_effect=lambda r: httpx.Response(
                200, json=SSVC) if r.url.path.endswith(LOG4J) else httpx.Response(404))
        else:
            router.get(url__regex=r"https://cveawg\.mitre\.org/api/cve/.*").respond(500)
        body = {"target": target, "target_type": "domain"}
        if scan_id:
            body["scan_id"] = scan_id
        return client.post("/scan", json=body).json()


def _outcome(body, source):
    return next((o for o in body["result"]["provider_results"] if o["source"] == source), None)


def test_a_kev_listed_actively_exploited_cve_dominates_the_exposure(live_scan) -> None:
    body = _scan(live_scan)
    exp = body["result"]["exposure"]
    assert exp["category"] == "Act" and exp["score"] >= 99 and exp["kev_count"] == 1
    assert [c["cve_id"] for c in exp["cves"]] == [LOG4J, OTHER], "worst first"
    top, other = exp["cves"]
    assert top["in_kev"] is True and top["kev_ransomware"] is True and top["epss"] == pytest.approx(0.94358)
    assert (top["ssvc_exploitation"], top["ssvc_automatable"], top["ssvc_technical_impact"]) == ("active", "yes", "total")
    assert top["cvss"] == 10.0 and other["cvss"] == 9.8, "severity is shown beside the exposure"
    assert other["category"] == "Track" and other["probability"] == pytest.approx(0.0004)
    assert exp["complete"] is True and exp["feed_ages"]["kev"] is not None and "SSVC-style" in exp["method"]
    for source in ("epss", "kev", "vulnrichment"):
        assert _outcome(body, source)["status"] == "ok"


def test_exposure_is_separate_from_and_never_changes_the_maliciousness_scores(live_scan, monkeypatch) -> None:
    from app.core.config import get_settings
    with_intel = _scan(live_scan, target="a-exposed.example.com")["result"]
    for name in ("EPSS_ENABLED", "KEV_ENABLED", "VULNRICHMENT_ENABLED"):
        monkeypatch.setenv(name, "false")
    get_settings.cache_clear()
    without = _scan(live_scan, target="b-exposed.example.com")["result"]
    assert with_intel["exposure"]["score"] >= 99 and without["exposure"]["score"] is None
    assert with_intel["baseline_score"] == without["baseline_score"]
    assert with_intel["features"] == without["features"], "exposure is not a model feature (yet)"


def test_an_epss_outage_leaves_those_cves_unknown_but_kev_still_counts(live_scan) -> None:
    body = _scan(live_scan, epss="down")
    exp = body["result"]["exposure"]
    assert _outcome(body, "epss")["status"] == "error" and _outcome(body, "epss")["reason"] == "server_error"
    assert exp["score"] >= 99, "the KEV-listed CVE is still assessed (observed exploitation)"
    other = next(c for c in exp["cves"] if c["cve_id"] == OTHER)
    assert other["epss"] is None and other["probability"] is None and other["category"] is None
    assert exp["complete"] is False and exp["cves_assessed"] == 1 and any("1 of 2" in n for n in exp["notes"])


def test_a_kev_feed_that_cannot_be_downloaded_makes_kev_unknown_not_absent(live_scan) -> None:
    body = _scan(live_scan, kev="down")
    exp = body["result"]["exposure"]
    assert _outcome(body, "kev")["status"] == "error" and _outcome(body, "kev")["reason"] == "feed_unavailable"
    top = next(c for c in exp["cves"] if c["cve_id"] == LOG4J)
    assert top["in_kev"] is None and top["kev_ransomware"] is None, "unknown, not 'not listed'"
    assert top["probability"] == pytest.approx(0.94358), "EPSS still gives a probability"
    assert top["category"] in ("Act", "Attend"), "the Vulnrichment SSVC points still apply"


def test_every_source_failing_makes_the_exposure_unknown_not_zero(live_scan) -> None:
    exp = _scan(live_scan, epss="down", kev="down", vr="down")["result"]["exposure"]
    assert exp["score"] is None and exp["category"] is None and exp["cves_assessed"] == 0 and exp["cves_total"] == 2


def test_a_host_with_no_listed_cves_has_a_genuine_zero_and_asks_nobody(live_scan) -> None:
    clean = {"ports": [443], "cpes": [], "vulns": [], "hostnames": [], "tags": []}
    body = _scan(live_scan, idb=clean, target="clean.example.com")
    exp = body["result"]["exposure"]
    assert exp["score"] == 0.0 and exp["cves_total"] == 0 and exp["complete"] is True
    assert all(_outcome(body, s) is None for s in ("epss", "kev", "vulnrichment")), "nothing to ask about"


def test_when_the_host_source_fails_exposure_is_unknown(live_scan) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://www\.virustotal\.com/.*").respond(404)
        router.get(url__regex=r"https://internetdb\.shodan\.io/.*").respond(503)
        mock_site(router, "down.example.com", text="<html></html>")
        body = live_scan.post("/scan", json={"target": "down.example.com", "target_type": "domain"}).json()
    assert body["result"]["exposure"] is None
    assert _outcome(body, "epss") is None and _outcome(body, "kev") is None


def test_the_intel_sources_wait_for_the_cve_list_and_run_together(live_scan) -> None:
    from app.core.scan_events import bus
    _scan(live_scan, scan_id="b11-events-0001")
    events = [e for e in bus.events("b11-events-0001") if e["type"] == "provider"]

    def first(source, running):
        return next(i for i, e in enumerate(events) if e["source"] == source and (e["status"] == "running") == running)

    nvd_done = first("nvd", False)
    starts = [first(s, True) for s in ("epss", "kev", "vulnrichment")]
    assert all(i > nvd_done for i in starts), "they need the CVE ids first"
    assert max(starts) < min(first(s, False) for s in ("epss", "kev", "vulnrichment")), "and then run side by side"


def test_each_source_can_be_switched_off(live_scan, monkeypatch) -> None:
    from app.core.config import get_settings
    monkeypatch.setenv("EPSS_ENABLED", "false")
    monkeypatch.setenv("VULNRICHMENT_ENABLED", "false")
    get_settings.cache_clear()
    body = _scan(live_scan)
    assert _outcome(body, "epss")["status"] == "skipped" and _outcome(body, "epss")["reason"] == "disabled"
    assert _outcome(body, "vulnrichment")["status"] == "skipped" and _outcome(body, "kev")["status"] == "ok"
    exp = body["result"]["exposure"]
    assert exp["score"] >= 99 and exp["cves"][0]["epss"] is None


def test_mock_mode_has_an_exposure_assessment_labelled_mock(client, monkeypatch) -> None:
    import app.core.validation as v
    from fastapi.testclient import TestClient
    from app.main import app

    async def _ok(t):
        return True, {"success": True}, t

    monkeypatch.setattr(v, "validate_domain_target", _ok)
    body = TestClient(app).post("/scan", json={"target": "apache-test.example.com", "target_type": "domain"}).json()
    r = body["result"]
    if r["shodan"] and r["shodan"]["vulns"]:
        assert r["exposure"] is not None and r["exposure"]["cves_total"] == len(set(v.upper() for v in r["shodan"]["vulns"]))
        assert all(_outcome(body, s)["mock"] for s in ("epss", "kev", "vulnrichment"))


def test_the_health_endpoint_lists_the_new_sources() -> None:
    from app.core.config import Settings
    st = Settings(_env_file=None, USE_MOCK_DATA=False).provider_statuses()
    for name in ("epss", "kev", "vulnrichment"):
        assert st[name].configured and st[name].state == "keyless"


def test_attack_paths_use_the_live_epss_and_kev_evidence_not_the_csv_snapshots(live_scan, monkeypatch) -> None:
    import app.api.scan as scan_module
    monkeypatch.setattr(scan_module._chainer, "_ollama_down_until", float("inf"))        # heuristic conditions: no LLM
    paths = _scan(live_scan)["result"]["attack_paths"]
    nodes = {n["cve_id"]: n for p in paths for n in p["nodes"]}
    assert nodes[LOG4J]["epss_score"] == pytest.approx(0.94358) and nodes[LOG4J]["is_in_kev"] is True
    assert nodes[OTHER]["epss_score"] == pytest.approx(0.0004) and nodes[OTHER]["is_in_kev"] is False
