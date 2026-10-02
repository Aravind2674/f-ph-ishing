"""
Centralised settings management for ThreatFusion.

Design decisions
----------------
* **pydantic-settings** gives us automatic env-var parsing, `.env` file
  support, and type validation — all for free.
* ``@lru_cache`` on ``get_settings()`` guarantees a single Settings
  instance across the entire process (singleton pattern without the
  boilerplate).
* ``USE_MOCK_DATA`` defaults to **True** so that the app starts cleanly
  out-of-the-box, even when the student hasn't obtained API keys yet.
  A loud console warning reminds them to switch to live data.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ── Placeholder detection (A0-5) ────────────────────────────────────────────
# `.env.example` ships values like PASTE_YOUR_NVD_KEY_HERE. If a key is simply absent from
# `.env`, the old code fell back to such a sentinel — a *truthy* string that clients then
# sent to the provider as if it were a credential (audit §F.2: NVD). Anything that looks
# like a template value is now treated as "unset", and unset means "never call".
_PLACEHOLDER_RE = re.compile(
    r"^(paste[_\-\s]?your.*"
    r"|your[_\-\s].*(here|key|token|secret).*"
    r"|<.*>"
    r"|change[_\-]?me"
    r"|todo|tbd|none|null"
    r"|x{3,}|\*{3,})$",
    re.IGNORECASE,
)

# Settings fields that hold provider credentials (values are never logged or returned).
_CREDENTIAL_FIELDS = (
    "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "NVD_API_KEY", "WIGLE_API_NAME", "WIGLE_API_TOKEN",
)


def is_placeholder_secret(value: str | None) -> bool:
    """True for empty values and template/sentinel strings (never a usable credential)."""
    v = (value or "").strip()
    return not v or bool(_PLACEHOLDER_RE.match(v))


@dataclass(frozen=True)
class ProviderConfigStatus:
    """Whether one provider can be called. Carries labels only — never credential values."""

    name: str
    configured: bool
    mock: bool
    # 'configured' | 'placeholder' | 'missing' | 'keyless' | 'local' | 'mock'
    state: str


class Settings(BaseSettings):
    """Application-wide configuration populated from environment / .env file.

    Every field maps 1-to-1 to an environment variable of the same name
    (case-insensitive thanks to pydantic-settings).
    """

    # ── External API keys ───────────────────────────────────────────────
    # Unset ("") by default — never a sentinel string. A provider whose credential is
    # unset (or still a template placeholder, see `is_placeholder_secret`) is *not
    # configured*: live mode skips it and says so, instead of sending junk upstream.
    VIRUSTOTAL_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    NVD_API_KEY: str = ""

    # ── WiGLE (Network Layer, rogue-AP signal) ──────────────────────────
    # WiGLE uses HTTP Basic auth with an API *name* + *token* (not a single
    # key). Obtain both from https://wigle.net/account after registering.
    # Left blank by default — the AP scorer degrades honestly without them.
    WIGLE_API_NAME: str = ""
    WIGLE_API_TOKEN: str = ""

    # ── Feature flags ───────────────────────────────────────────────────
    # When True, enrichment services return deterministic fake data.
    # This lets students develop the UI and ML pipeline without burning
    # API quota.
    USE_MOCK_DATA: bool = True

    # ── Database ────────────────────────────────────────────────────────
    # SQLite is the default for local development; swap to PostgreSQL in
    # production by overriding this env var.
    DATABASE_URL: str = "sqlite:///./threatfusion.db"

    # ── Model integrity (A0-7) ──────────────────────────────────────────
    # Every model artifact is checked against ml/models/manifest.json (SHA-256) before
    # it is loaded. A *mismatch* always refuses; strict mode additionally refuses files
    # the manifest does not list. Regenerate with `python -m ml.hash_models` after
    # retraining. Set false only while experimenting with an unregistered model.
    MODEL_HASH_STRICT: bool = True

    # Directory holding model artifacts. Empty = <threatfusion>/ml/models, resolved from THIS
    # file's location — never from the current working directory (the old CWD-relative lookup
    # silently left models unloaded when uvicorn was started from another folder, and the API
    # then substituted the baseline score for the ML score). A relative value is resolved
    # against the threatfusion/ directory.
    MODEL_DIR: str = ""

    # ── Outbound fetch policy (A0-4) ────────────────────────────────────
    # Ports the SSRF-safe fetcher may connect to when fetching a user-supplied target.
    # Comma-separated; "*" = any port (not recommended).
    SAFE_FETCH_PORTS: str = "80,443,8080,8443"

    # ── Observability ───────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"

    # ── Caching ─────────────────────────────────────────────────────────
    # How long enrichment results are considered fresh (seconds).
    CACHE_TTL_SECONDS: int = 3600  # 1 hour

    # ── Rate limiting ───────────────────────────────────────────────────
    # VirusTotal free tier allows 4 requests per minute; we honour that
    # globally to avoid HTTP 429 responses.
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 4

    # ── Network Layer — capture & monitoring ────────────────────────────
    # Interface names are passed straight to scapy. Empty string means
    # "let scapy pick the default interface".
    NETWORK_CAPTURE_INTERFACE: str = ""       # ARP/DNS sniff interface
    NETWORK_MONITOR_INTERFACE: str = ""       # 802.11 monitor-mode interface (deauth)
    NETWORK_GATEWAY_IP: str = ""              # optional; emphasises gateway ARP spoofing
    # Auto-start capture on API boot. Requires Npcap + elevated (Administrator)
    # process. When capture can't start it degrades honestly (see MonitorStatus).
    NETWORK_AUTO_START: bool = False
    # SSIDs the operator owns/monitors. Evil-twin detection treats a new BSSID
    # advertising one of these names as high-suspicion. Comma-separated in .env.
    NETWORK_MONITORED_SSIDS: str = ""

    # How many DNS observations before a device's baseline is "established"
    # enough to trust deviation detection. Learned from real traffic only.
    BASELINE_MIN_OBSERVATIONS: int = 15
    # WiFi scan cadence (seconds) for the AP/evil-twin sensor.
    WIFI_SCAN_INTERVAL_SECONDS: int = 30
    # Deauth flood detection: N deauth/disassoc frames within the window.
    DEAUTH_FLOOD_THRESHOLD: int = 20
    DEAUTH_WINDOW_SECONDS: int = 10

    # Names of credential fields that were present but still template placeholders
    # (recorded by the validator below so startup can say "placeholder" vs "missing").
    placeholder_fields: tuple[str, ...] = Field(default=(), exclude=True, repr=False)

    @model_validator(mode="before")
    @classmethod
    def _normalise_placeholder_credentials(cls, data: Any) -> Any:
        """Turn template values into "" and remember which fields were templates."""
        if not isinstance(data, dict):
            return data
        data = dict(data)
        flagged: list[str] = []
        for key in list(data):
            if key.upper() in _CREDENTIAL_FIELDS:
                raw = data[key]
                if isinstance(raw, str) and raw.strip() and is_placeholder_secret(raw):
                    flagged.append(key.upper())
                if isinstance(raw, str) and is_placeholder_secret(raw):
                    data[key] = ""
        data["placeholder_fields"] = tuple(flagged)
        return data

    @property
    def model_dir(self) -> Path:
        """Absolute directory that holds the model artifacts (see ``MODEL_DIR``)."""
        project_root = Path(__file__).resolve().parents[3]  # .../threatfusion
        if not self.MODEL_DIR.strip():
            return project_root / "ml" / "models"
        configured = Path(self.MODEL_DIR.strip()).expanduser()
        return (configured if configured.is_absolute() else project_root / configured).resolve()

    def _credential_state(self, *fields: str) -> tuple[bool, str]:
        """(configured?, state-label) for a provider that needs all of ``fields``."""
        if all(getattr(self, f) for f in fields):
            return True, "configured"
        if any(f in self.placeholder_fields for f in fields):
            return False, "placeholder"
        return False, "missing"

    def provider_statuses(self) -> dict[str, ProviderConfigStatus]:
        """Per-provider readiness, used by /health, the startup log and /scan gating.

        In mock mode every provider is served by the mock layer, so all are usable.
        In live mode a provider that needs a credential is usable only if it has one.
        """
        mock = self.USE_MOCK_DATA

        def status(name: str, configured: bool, state: str) -> ProviderConfigStatus:
            if mock:
                return ProviderConfigStatus(name, True, True, "mock")
            return ProviderConfigStatus(name, configured, False, state)

        vt_ok, vt_state = self._credential_state("VIRUSTOTAL_API_KEY")
        nvd_ok, nvd_state = self._credential_state("NVD_API_KEY")
        wigle_ok, wigle_state = self._credential_state("WIGLE_API_NAME", "WIGLE_API_TOKEN")
        return {
            "virustotal": status("virustotal", vt_ok, vt_state),
            "shodan_internetdb": status("shodan_internetdb", True, "keyless"),
            "nvd": status("nvd", nvd_ok, nvd_state),
            "tech_fingerprint": status("tech_fingerprint", True, "local"),
            "wigle": status("wigle", wigle_ok, wigle_state),
        }

    # ── Pydantic-settings configuration ─────────────────────────────────
    # ``env_file`` tells pydantic-settings to read a `.env` next to the
    # working directory.  ``extra="ignore"`` means unknown env vars won't
    # blow up the app (e.g. PATH, HOME, etc.).
    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton of the application settings.

    Using ``@lru_cache`` means the `.env` file is only parsed once per
    process, and every call-site shares the same instance — avoiding
    subtle bugs from inconsistent config objects.
    """
    return Settings()


def startup_warnings() -> None:
    """Emit a highly visible warning when mock mode is active.

    This runs once during the FastAPI lifespan startup so the operator
    immediately knows whether they're seeing real or synthetic data.
    """
    settings = get_settings()
    logger = logging.getLogger("threatfusion.config")

    if settings.USE_MOCK_DATA:
        banner = (
            "\n"
            "╔══════════════════════════════════════════════════════════════════╗\n"
            "║  ⚠  Running with MOCK data — set USE_MOCK_DATA=false and add   ║\n"
            "║     real API keys in .env for live results                      ║\n"
            "╚══════════════════════════════════════════════════════════════════╝\n"
        )
        logger.warning(banner)
    else:
        logger.info("Live mode active — using real API keys for enrichment.")


def log_provider_table(settings: Settings | None = None) -> None:
    """Log one line per provider: configured / placeholder / missing / mock. Never values."""
    settings = settings or get_settings()
    logger = logging.getLogger("threatfusion.config")
    rows = settings.provider_statuses()
    width = max(len(n) for n in rows)
    lines = [f"  {name:<{width}}  {'usable' if st.configured else 'NOT usable':<10} ({st.state})"
             for name, st in rows.items()]
    mode = "MOCK" if settings.USE_MOCK_DATA else "LIVE"
    logger.info("Provider configuration (%s mode):\n%s", mode, "\n".join(lines))
    unusable = [n for n, st in rows.items() if not st.configured]
    if unusable:
        logger.warning("Providers that will be skipped (not configured): %s", ", ".join(unusable))
