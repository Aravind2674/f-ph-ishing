"""Tests for the Shodan ingestion client in mock mode."""

from __future__ import annotations

import pytest

from app.ingestion.shodan import ShodanClient
from app.models.schemas import ShodanResult, ProviderStatus


@pytest.fixture
def shodan_client() -> ShodanClient:
    """Create a Shodan client in mock mode."""
    return ShodanClient(api_key="test-key", use_mock=True)


@pytest.mark.asyncio
async def test_lookup_ip_internetdb(shodan_client: ShodanClient) -> None:
    """Test InternetDB (free) mock lookup."""
    res = await shodan_client.lookup_ip("8.8.8.8")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, ShodanResult)
    assert 53 in result.open_ports
    assert "dns.google" in result.hostnames


@pytest.mark.asyncio
async def test_lookup_ip_private(shodan_client: ShodanClient) -> None:
    """Test that private IPs return empty results."""
    res = await shodan_client.lookup_ip("192.168.1.1")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, ShodanResult)
    assert not result.open_ports
    assert not result.hostnames


@pytest.mark.asyncio
async def test_lookup_ip_full(shodan_client: ShodanClient) -> None:
    """Test full API mock lookup."""
    res = await shodan_client.lookup_ip_full("1.2.3.4")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, ShodanResult)
    assert "vpn" in result.tags
    assert result.cpes
    assert result.vulns
