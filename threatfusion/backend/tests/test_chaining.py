import pytest
from app.models.schemas import CVEDetail
from app.ml.chaining import VulnerabilityChainer

@pytest.mark.asyncio
async def test_vulnerability_chainer_parsing():
    """Verify chainer correctly parses KEV, EPSS, and Exploit-DB entries."""
    chainer = VulnerabilityChainer()
    chainer.initialize()

    # KEV Catalog Verification
    assert len(chainer.kev_cache) > 0
    assert "CVE-2026-56291" in chainer.kev_cache

    # EPSS Verification
    assert "CVE-1999-0001" in chainer.epss_cache
    assert chainer.epss_cache["CVE-1999-0001"] == 0.03351

    # Exploit-DB Verification
    assert "CVE-2009-3699" in chainer.exploit_db_cache
    assert chainer.exploit_db_cache["CVE-2009-3699"] == "16929"


@pytest.mark.asyncio
async def test_attack_graph_solver():
    """Verify directed graph construction and path solving rules."""
    chainer = VulnerabilityChainer()
    
    # Mock CVEs representing a logical chain
    cves = [
        # CVE 1: Path traversal -> Local file read. Needs network_access.
        CVEDetail(
            cve_id="CVE-2021-41773",
            description="Apache HTTP Server 2.4.49 path traversal vulnerability allowing local file read.",
            cvss_v3_score=7.5,
            severity="HIGH"
        ),
        # CVE 2: Needs local_file_read (which CVE 1 gains) -> Gaining privilege_escalation
        CVEDetail(
            cve_id="CVE-2026-45659",
            description="Local configuration exposure allows privilege escalation to remote code execution.",
            cvss_v3_score=8.8,
            severity="HIGH"
        )
    ]

    # Explicitly configure chainer to return pre/post conditions that form a chain
    async def mock_get_conditions(cve_id, description):
        if cve_id == "CVE-2021-41773":
            return ["network_access"], ["local_file_read"]
        else:
            return ["local_file_read"], ["remote_code_execution"]
            
    chainer.get_pre_and_post_conditions = mock_get_conditions

    paths = await chainer.build_and_solve_chain(cves)
    assert len(paths) > 0
    
    # Verify path risk aggregation and summary construction
    best_path = paths[0]
    assert best_path.total_risk_score > 0.0
    assert "CVE-2021-41773" in best_path.summary

