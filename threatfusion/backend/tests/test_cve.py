"""Tests for the CVE/NVD ingestion client in mock mode."""

from __future__ import annotations

import pytest

from app.ingestion.cve import CVEClient
from app.models.schemas import CVEResult


@pytest.fixture
def cve_client() -> CVEClient:
    """Create a CVE client in mock mode."""
    return CVEClient(api_key="test-key", use_mock=True)


@pytest.mark.asyncio
async def test_lookup_cves(cve_client: CVEClient) -> None:
    """Test looking up specific CVE IDs."""
    # Log4Shell is hardcoded in the mock to return a 10.0 score
    result = await cve_client.lookup_cves(["CVE-2021-44228", "CVE-2021-41773"])
    assert isinstance(result, CVEResult)
    assert result.total_cves == 2
    assert result.max_cvss_score == 10.0
    
    # Check details
    cve_dict = {cve.cve_id: cve for cve in result.cves}
    assert cve_dict["CVE-2021-44228"].severity == "CRITICAL"


@pytest.mark.asyncio
async def test_lookup_by_cpe(cve_client: CVEClient) -> None:
    """Test looking up CVEs for a CPE string."""
    result = await cve_client.lookup_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert isinstance(result, CVEResult)
    # The mock returns a couple of hardcoded CVEs for any CPE
    assert result.total_cves > 0
    assert result.max_cvss_score > 0
