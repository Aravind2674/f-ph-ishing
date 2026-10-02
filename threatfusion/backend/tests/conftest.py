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


# ── SSRF-safe fetcher helpers (A0-4) ─────────────────────────────────────────
# SafeFetcher resolves DNS itself and connects to the *validated IP* (not the hostname), so tests
# that mock HTTP with respx must (a) control DNS and (b) route by that IP + Host header.
PUBLIC_IP = "93.184.216.34"   # a normal public address; never contacted (respx intercepts)


class FakeDNS:
    """Deterministic resolver: unknown hosts -> PUBLIC_IP; ``set(host, ip, ...)`` overrides."""

    def __init__(self) -> None:
        self.table: dict[str, list[str]] = {}
        self.calls: list[str] = []
        self.sequences: dict[str, list[list[str]]] = {}

    def set(self, host: str, *ips: str) -> None:
        self.table[host.lower()] = list(ips)

    def sequence(self, host: str, *answers: list[str]) -> None:
        """Successive different answers for the same host (DNS-rebinding simulation)."""
        self.sequences[host.lower()] = [list(a) for a in answers]


@pytest.fixture
def fake_dns(monkeypatch):
    import ipaddress
    import app.core.safe_http as safe_http

    dns = FakeDNS()

    async def _resolve(host: str, port: int):
        literal = safe_http.parse_host_ip(host)
        if literal is not None:
            return [literal]
        h = host.lower()
        dns.calls.append(h)
        if h in dns.sequences and dns.sequences[h]:
            ips = dns.sequences[h].pop(0) if len(dns.sequences[h]) > 1 else dns.sequences[h][0]
        else:
            ips = dns.table.get(h, [PUBLIC_IP])
        return [ipaddress.ip_address(i) for i in ips]

    monkeypatch.setattr(safe_http, "resolve_host", _resolve)
    return dns


def mock_site(router, host: str, *, status: int = 200, text: str = "", path: str = "/",
              headers: dict | None = None, ip: str = PUBLIC_IP, side_effect=None, scheme: str | None = None):
    """Register a respx route for ``host`` as reached through the pinned ``ip``."""
    extra = {"scheme": scheme} if scheme else {}
    route = router.route(method="GET", host=ip, path=path, headers={"host": host}, **extra)
    if side_effect is not None:
        route.mock(side_effect=side_effect)
    else:
        route.respond(status, text=text, headers=headers or {})
    return route
