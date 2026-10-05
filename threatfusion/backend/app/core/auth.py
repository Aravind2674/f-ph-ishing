"""
Local API token + SSE stream tickets (A0-8)
============================================

Why (AUDIT_REPORT.md §H3)
-------------------------
The API had no authentication, so any web page the user visited could talk to it
(``POST /network/monitor/start`` is a "simple" cross-site request) and, via DNS rebinding, read
``/network/*`` and the scan history.  Every route except ``/health`` now requires
``Authorization: Bearer <token>``.

The token
---------
* ``API_TOKEN`` in the environment wins (CI, containers).  Otherwise a random 256-bit token is
  generated on first start and stored **outside the repository** — ``%APPDATA%\\ThreatFusion\\api_token``
  on Windows, ``$XDG_CONFIG_HOME/threatfusion/api_token`` (or ``~/.config``) elsewhere, mode 0600 where
  the OS supports it — and reused on later starts.  ``API_TOKEN_FILE`` overrides the location.
* Read it with ``python -m app.core.auth`` and paste it into the dashboard's Settings page / the
  extension popup.  The token is never logged: startup logs only the *file path*.

Stream tickets
--------------
Browsers' ``EventSource`` cannot send an ``Authorization`` header, and putting the token in the URL
would leak it into uvicorn's access log.  Instead an authenticated client calls
``POST /network/stream-ticket`` and opens ``/network/stream?ticket=<one-time-ticket>``: the ticket is
random, single-use and expires after 30 s, so a copy in a log line is worthless.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional

from fastapi import Header, HTTPException, Query

from app.core.config import get_settings

logger = logging.getLogger(__name__)

STREAM_TICKET_TTL_SECONDS = 30
_MIN_TOKEN_LENGTH = 32

_token_cache: dict[str, str] = {}
_tickets: dict[str, float] = {}      # ticket -> monotonic expiry


# ── Token ───────────────────────────────────────────────────────────────────
def default_token_path() -> Path:
    """Per-user config location — deliberately not inside the repository."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "ThreatFusion"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "threatfusion"
    return base / "api_token"


def token_path() -> Path:
    configured = get_settings().API_TOKEN_FILE.strip()
    return Path(configured).expanduser() if configured else default_token_path()


def reset_token_cache() -> None:
    _token_cache.clear()


def get_api_token() -> str:
    """The token every client must present. Generated and persisted on first use."""
    settings = get_settings()
    if settings.API_TOKEN:                      # placeholders were normalised to "" by Settings
        return settings.API_TOKEN

    path = token_path()
    key = str(path)
    if key in _token_cache:
        return _token_cache[key]

    if path.exists():
        existing = path.read_text(encoding="utf-8").strip()
        if len(existing) >= _MIN_TOKEN_LENGTH:
            _token_cache[key] = existing
            return existing

    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    # 0600 on POSIX; on Windows the per-user profile directory's ACL is the protection.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    _token_cache[key] = token
    logger.info("Generated a new API token and stored it at %s", path)
    return token


def log_token_location() -> None:
    """Tell the operator where the token lives — never what it is."""
    settings = get_settings()
    if settings.API_TOKEN:
        logger.info("API access requires the token from the API_TOKEN environment variable.")
    else:
        logger.info("API access requires a Bearer token. File: %s  (print it with: python -m app.core.auth)",
                    token_path())


def verify_token(candidate: str) -> bool:
    return bool(candidate) and hmac.compare_digest(candidate.encode("utf-8"), get_api_token().encode("utf-8"))


_UNAUTHORIZED = HTTPException(
    status_code=401,
    detail="Missing or invalid API token. Send 'Authorization: Bearer <token>' "
           "(see `python -m app.core.auth`).",
    headers={"WWW-Authenticate": "Bearer"},
)


async def require_token(authorization: Optional[str] = Header(default=None)) -> None:
    """FastAPI dependency: only the ``Bearer`` scheme with the correct token passes."""
    scheme, _, credential = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not verify_token(credential.strip()):
        raise _UNAUTHORIZED


# ── Stream tickets (SSE) ────────────────────────────────────────────────────
def _purge_expired(now: float) -> None:
    for t in [t for t, exp in _tickets.items() if exp <= now]:
        del _tickets[t]


def issue_stream_ticket() -> str:
    now = time.monotonic()
    _purge_expired(now)
    ticket = secrets.token_urlsafe(16)
    _tickets[ticket] = now + STREAM_TICKET_TTL_SECONDS
    return ticket


def consume_stream_ticket(ticket: str) -> bool:
    """True exactly once per valid, unexpired ticket."""
    if not ticket:
        return False
    now = time.monotonic()
    expiry = _tickets.pop(ticket, None)
    return expiry is not None and expiry > now


async def require_token_or_ticket(
    authorization: Optional[str] = Header(default=None),
    ticket: Optional[str] = Query(default=None),
) -> None:
    """For ``/network/stream``: a Bearer token *or* a single-use stream ticket."""
    if authorization:
        await require_token(authorization)
        return
    if ticket and consume_stream_ticket(ticket):
        return
    raise _UNAUTHORIZED


if __name__ == "__main__":  # python -m app.core.auth  → print the token for pasting into the UI
    print(get_api_token())
