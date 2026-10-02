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
from functools import lru_cache
from typing import ClassVar

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide configuration populated from environment / .env file.

    Every field maps 1-to-1 to an environment variable of the same name
    (case-insensitive thanks to pydantic-settings).
    """

    # ── External API keys ───────────────────────────────────────────────
    # Default values are sentinel placeholders so the app never crashes
    # on startup; the mock layer intercepts calls when keys are missing.
    VIRUSTOTAL_API_KEY: str = "PASTE_YOUR_VIRUSTOTAL_KEY_HERE"
    SHODAN_API_KEY: str = "PASTE_YOUR_SHODAN_KEY_HERE"
    NVD_API_KEY: str = "PASTE_YOUR_NVD_KEY_HERE"

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
