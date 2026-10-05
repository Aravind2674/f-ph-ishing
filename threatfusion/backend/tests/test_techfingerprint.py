"""Tests for the Technology Fingerprinting client in mock mode."""

from __future__ import annotations

import pytest

from app.ingestion.techfingerprint import TechFingerprintClient
from app.models.schemas import TechFingerprintResult, ProviderStatus


@pytest.fixture
def tech_client() -> TechFingerprintClient:
    """Create a Tech Fingerprint client in mock mode."""
    return TechFingerprintClient(use_mock=True)


@pytest.mark.asyncio
async def test_fingerprint_url_wordpress(tech_client: TechFingerprintClient) -> None:
    """Test the WordPress mock profile."""
    res = await tech_client.fingerprint_url("https://example.com/wordpress/blog")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, TechFingerprintResult)
    
    names = [t.name for t in result.technologies]
    assert "WordPress" in names
    assert "PHP" in names
    assert "Apache" in names


@pytest.mark.asyncio
async def test_fingerprint_url_react(tech_client: TechFingerprintClient) -> None:
    """Test the React/Vercel mock profile."""
    res = await tech_client.fingerprint_url("https://my-react-app.vercel.app")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, TechFingerprintResult)
    
    names = [t.name for t in result.technologies]
    assert "React" in names
    assert "Next.js" in names
    assert "Vercel" in names


@pytest.mark.asyncio
async def test_fingerprint_url_default(tech_client: TechFingerprintClient) -> None:
    """Test the default mock profile."""
    res = await tech_client.fingerprint_url("https://unknown-stack.com")
    assert res.status == ProviderStatus.OK and res.mock, res
    result = res.data
    assert isinstance(result, TechFingerprintResult)
    
    names = [t.name for t in result.technologies]
    assert "Nginx" in names
    assert "jQuery" in names
