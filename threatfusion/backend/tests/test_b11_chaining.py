"""B11 (chaining) — the attack-path model stops inventing an EPSS of 0.0 and uses the live exposure evidence.

``VulnerabilityChainer`` read EPSS/KEV from CSV snapshots in the repo root and used ``epss_cache.get(cve, 0.0)`` — a CVE the
snapshot did not know was *scored as if its exploitation probability were exactly zero* (the audit's neutral-constant
smell).  Now unknown EPSS is ``None`` and contributes nothing, and a scan hands the chainer the per-CVE evidence it already
collected (EPSS from FIRST.org, KEV from the local catalogue) so the snapshots are no longer needed for scoring.
"""

from __future__ import annotations

import pytest

from app.ml.chaining import VulnerabilityChainer
from app.models.schemas import CVEDetail, ExposureCve


def _cve(cve_id: str, cvss: float = 9.0) -> CVEDetail:
    return CVEDetail(cve_id=cve_id, description="Remote code execution via a crafted request", cvss_v3_score=cvss, severity="CRITICAL")


@pytest.fixture
def chainer(monkeypatch) -> VulnerabilityChainer:
    c = VulnerabilityChainer()
    c._initialized = True                                  # no CSV parsing
    c._ollama_down_until = float("inf")                    # heuristic conditions only: no LLM call
    return c


@pytest.mark.asyncio
async def test_unknown_epss_is_none_not_zero_and_adds_no_term(chainer) -> None:
    paths = await chainer.build_and_solve_chain([_cve("CVE-2030-0001", 9.0)])
    node = paths[0].nodes[0]
    assert node.epss_score is None, "a CVE the snapshot does not know has an UNKNOWN EPSS"
    assert paths[0].total_risk_score == pytest.approx(0.9), "probability from CVSS alone: 9.0 / 10"


@pytest.mark.asyncio
async def test_live_intel_replaces_the_csv_snapshots(chainer) -> None:
    intel = {
        "CVE-2030-0001": ExposureCve(cve_id="CVE-2030-0001", epss=0.5, epss_percentile=0.9, in_kev=False),
        "CVE-2030-0002": ExposureCve(cve_id="CVE-2030-0002", epss=0.01, in_kev=True, kev_ransomware=False),
    }
    paths = await chainer.build_and_solve_chain([_cve("CVE-2030-0001", 8.0), _cve("CVE-2030-0002", 4.0)], intel=intel)
    by_id = {n.cve_id: n for p in paths for n in p.nodes}
    assert by_id["CVE-2030-0001"].epss_score == 0.5 and by_id["CVE-2030-0001"].is_in_kev is False
    assert by_id["CVE-2030-0002"].is_in_kev is True
    single = {p.nodes[0].cve_id: p.total_risk_score for p in paths if len(p.nodes) == 1}
    assert single["CVE-2030-0001"] == pytest.approx(0.8 * 0.7 + 0.5 * 0.3, abs=0.01), "CVSS blended with EPSS"
    assert single["CVE-2030-0002"] == pytest.approx(0.99, abs=0.01), "KEV: exploitation observed in the wild"


@pytest.mark.asyncio
async def test_unknown_kev_is_not_treated_as_listed(chainer) -> None:
    intel = {"CVE-2030-0003": ExposureCve(cve_id="CVE-2030-0003", epss=None, in_kev=None)}      # both feeds failed
    paths = await chainer.build_and_solve_chain([_cve("CVE-2030-0003", 7.0)], intel=intel)
    node = paths[0].nodes[0]
    assert node.is_in_kev is False and node.epss_score is None
    assert paths[0].total_risk_score == pytest.approx(0.7)


@pytest.mark.asyncio
async def test_the_legacy_csv_snapshots_are_not_parsed_when_live_intel_is_supplied(monkeypatch) -> None:
    import app.ml.chaining as chaining
    parsed: list[str] = []
    monkeypatch.setattr(chaining.VulnerabilityChainer, "_load_epss_kev", lambda self: parsed.append("epss_kev"))
    monkeypatch.setattr(chaining.VulnerabilityChainer, "_load_exploit_db", lambda self: parsed.append("exploitdb"))
    c = VulnerabilityChainer()
    c._ollama_down_until = float("inf")
    await c.build_and_solve_chain([_cve("CVE-2030-0004")], intel={"CVE-2030-0004": ExposureCve(cve_id="CVE-2030-0004", epss=0.1)})
    assert parsed == ["exploitdb"], parsed


def test_the_node_schema_allows_unknown_epss() -> None:
    from app.models.schemas import AttackChainNode
    assert AttackChainNode(cve_id="CVE-2030-0005").epss_score is None
