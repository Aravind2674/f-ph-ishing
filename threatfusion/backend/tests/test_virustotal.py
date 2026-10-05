"""Tests for the VirusTotal ingestion client.

All tests run against mock data — no real API calls are made.
This ensures tests are fast, deterministic, and don't require API keys.
"""

from __future__ import annotations

import pytest

from app.ingestion.virustotal import VirusTotalClient
from app.models.schemas import VirusTotalResult, ProviderStatus


@pytest.fixture
def vt_client() -> VirusTotalClient:
    """Create a VirusTotal client in mock mode."""
    return VirusTotalClient(api_key="test-key", use_mock=True)


@pytest.mark.asyncio
async def test_lookup_domain_safe(vt_client: VirusTotalClient) -> None:
    """A known-safe domain should return zero malicious detections."""
    res = await vt_client.lookup_domain("google.com")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, VirusTotalResult)
    assert result.malicious_count == 0
    assert result.harmless_count > 0
    assert result.total_engines > 0
    assert result.reputation_score > 0


@pytest.mark.asyncio
async def test_lookup_domain_malicious(vt_client: VirusTotalClient) -> None:
    """A domain with 'malicious' in the name should return high malicious count."""
    res = await vt_client.lookup_domain("malicious-site.evil.com")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, VirusTotalResult)
    assert result.malicious_count > 0
    assert result.reputation_score < 0


@pytest.mark.asyncio
async def test_lookup_domain_default(vt_client: VirusTotalClient) -> None:
    """An unknown domain should return a slightly suspicious result."""
    res = await vt_client.lookup_domain("unknown-domain.xyz")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, VirusTotalResult)
    assert result.total_engines > 0
    # Should have all counts populated
    assert result.malicious_count + result.harmless_count + result.suspicious_count + result.undetected_count == result.total_engines


@pytest.mark.asyncio
async def test_lookup_url(vt_client: VirusTotalClient) -> None:
    """URL lookup should return a valid VirusTotalResult."""
    res = await vt_client.lookup_url("https://example.com/page")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, VirusTotalResult)
    assert result.total_engines > 0


@pytest.mark.asyncio
async def test_lookup_file_hash(vt_client: VirusTotalClient) -> None:
    """File hash lookup should return a valid VirusTotalResult."""
    res = await vt_client.lookup_file_hash(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, VirusTotalResult)
    assert result.total_engines > 0


@pytest.mark.asyncio
async def test_result_types(vt_client: VirusTotalClient) -> None:
    """Verify all fields have the correct types."""
    res = await vt_client.lookup_domain("example.com")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result.malicious_count, int)
    assert isinstance(result.harmless_count, int)
    assert isinstance(result.suspicious_count, int)
    assert isinstance(result.undetected_count, int)
    assert isinstance(result.total_engines, int)
    assert isinstance(result.reputation_score, int)
    assert isinstance(result.categories, dict)
