"""Shared test fixtures for ThreatFusion backend tests.

All tests use mocked API responses — no real external API calls are ever made
during testing. This ensures tests are fast, deterministic, and don't require
API keys.
"""
import pytest
from fastapi.testclient import TestClient
import os

# ── Never touch the developer's real database ────────────────────────────────
# Since A0-6 every /scan is persisted. The default DATABASE_URL resolves to backend/threatfusion.db —
# the developer's actual database (scan history, network alerts). The whole test session therefore
# runs against a throwaway file; individual tests may point DATABASE_URL at their own tmp path.
import atexit
import shutil
import tempfile
from pathlib import Path

_TEST_DB_DIR = tempfile.mkdtemp(prefix="tf_tests_")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_TEST_DB_DIR).as_posix()}/threatfusion_tests.db"
atexit.register(shutil.rmtree, _TEST_DB_DIR, ignore_errors=True)

_REAL_DB = (Path(__file__).resolve().parents[1] / "threatfusion.db").resolve()


@pytest.fixture(autouse=True)
def _guard_real_database():
    """Fail fast if any test is configured to use the real dev database."""
    from app.core.config import Settings

    resolved = Settings(_env_file=None).database_path
    assert resolved != _REAL_DB, f"test would use the real database {_REAL_DB}"
    yield


# ── Access control (A0-8) ────────────────────────────────────────────────────
# Tests run with a fixed token and the Starlette TestClient's "testserver" Host. TestClient is
# patched to send the token by default; auth tests pass `headers={"Authorization": ""}` to opt out.
os.environ["API_TOKEN"] = "test-token-0123456789abcdef0123456789abcdef"
os.environ["ALLOWED_HOSTS"] = "localhost,127.0.0.1,[::1],testserver"

_original_testclient_init = TestClient.__init__


def _testclient_init(self, *args, **kwargs):
    headers = dict(kwargs.pop("headers", None) or {})
    headers.setdefault("Authorization", f"Bearer {os.environ['API_TOKEN']}")
    _original_testclient_init(self, *args, headers=headers, **kwargs)


TestClient.__init__ = _testclient_init

# VirusTotal quota (A1-1): the free-tier limiter (4/min) is OFF by default in tests so unrelated tests aren't
# throttled; tests/test_a1_1_virustotal.py turns it on explicitly.
os.environ["VIRUSTOTAL_REQUESTS_PER_MINUTE"] = "0"
os.environ["VIRUSTOTAL_REQUESTS_PER_DAY"] = "0"
# NVD (A1-2): no real waiting when a scan-level test makes NVD answer 403/429/503 (the retry delays are tested
# with a fake clock in test_a1_2_nvd.py).
os.environ["NVD_BACKOFF_BASE_SECONDS"] = "0.01"
# Host signals (A1-3) open real sockets (TLS to :443, WHOIS, DNS) — respx cannot intercept those, so they are OFF
# by default in tests (a test that exercises them swaps in stubs/local servers and enables them explicitly).
os.environ["TLS_ENABLED"] = "false"
os.environ["RDAP_ENABLED"] = "false"
os.environ["DNS_ENABLED"] = "false"


@pytest.fixture(autouse=True)
def _fresh_provider_hub():
    """Each test gets a fresh process-wide client/limiter and an empty provider cache (the session DB is shared)."""
    import sqlite3
    from app.core.config import Settings
    from app.core.hub import hub

    from app.core.ratelimit import SCAN_LIMITER

    hub.reset()
    SCAN_LIMITER.clear()                   # the per-client /scan limit is process-global: don't leak hits between tests
    try:
        db = Settings(_env_file=None).database_path
        if db.exists():
            con = sqlite3.connect(db)
            try:
                con.execute("DELETE FROM provider_cache")
                con.commit()
            except sqlite3.OperationalError:       # table not created yet (no test has initialised the DB)
                pass
            finally:
                con.close()
    except Exception:
        pass
    yield
    hub.reset()


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
