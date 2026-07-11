"""Tests for the Shodan ingestion client in mock mode."""

from __future__ import annotations

import pytest

from app.ingestion.shodan import ShodanClient
from app.models.schemas import ShodanResult


@pytest.fixture
def shodan_client() -> ShodanClient:
    """Create a Shodan client in mock mode."""
    return ShodanClient(api_key="test-key", use_mock=True)


@pytest.mark.asyncio
async def test_lookup_ip_internetdb(shodan_client: ShodanClient) -> None:
    """Test InternetDB (free) mock lookup."""
    result = await shodan_client.lookup_ip("8.8.8.8")
    assert isinstance(result, ShodanResult)
    assert 53 in result.open_ports
    assert "dns.google" in result.hostnames


@pytest.mark.asyncio
async def test_lookup_ip_private(shodan_client: ShodanClient) -> None:
    """Test that private IPs return empty results."""
    result = await shodan_client.lookup_ip("192.168.1.1")
    assert isinstance(result, ShodanResult)
    assert not result.open_ports
    assert not result.hostnames


@pytest.mark.asyncio
async def test_lookup_ip_full(shodan_client: ShodanClient) -> None:
    """Test full API mock lookup."""
    result = await shodan_client.lookup_ip_full("1.2.3.4")
    assert isinstance(result, ShodanResult)
    assert "vpn" in result.tags
    assert result.cpes
    assert result.vulns
