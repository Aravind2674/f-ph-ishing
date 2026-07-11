"""Shared test fixtures for ThreatFusion backend tests.

All tests use mocked API responses — no real external API calls are ever made
during testing. This ensures tests are fast, deterministic, and don't require
API keys.
"""
import pytest
from fastapi.testclient import TestClient
import os

# Force mock mode for all tests
os.environ['USE_MOCK_DATA'] = 'true'
os.environ['VIRUSTOTAL_API_KEY'] = 'test-key'
os.environ['SHODAN_API_KEY'] = 'test-key'
os.environ['NVD_API_KEY'] = 'test-key'


@pytest.fixture
def client():
    """Create a test client for the FastAPI application.
    
    Uses mock data mode to avoid external API dependencies.
    """
    from app.main import app
    return TestClient(app)


@pytest.fixture
def sample_domain():
    """A sample domain for testing."""
    return 'example.com'


@pytest.fixture
def sample_ip():
    """A sample IP address for testing."""
    return '8.8.8.8'


@pytest.fixture
def sample_file_hash():
    """A sample SHA-256 file hash for testing."""
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
