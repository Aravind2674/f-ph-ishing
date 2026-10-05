"""
Provider-result construction helpers (A0-1)
============================================

One place that decides what an HTTP status or an exception *means*, so every client
(VirusTotal, InternetDB, NVD, Wappalyzer, WiGLE) classifies failures identically and the
UI/verdict logic can rely on it.

Mapping
-------
=========================  ==========================  =========================
situation                  status                      reason
=========================  ==========================  =========================
2xx + parsed payload       ``ok``                      —
404                        ``not_found``               —   (provider has no record)
401 / 403                  ``error``                   ``auth``
429                        ``error``                   ``rate_limited``
5xx                        ``error``                   ``server_error``
other 4xx                  ``error``                   ``bad_request`` / ``http_<n>``
timeout                    ``error``                   ``timeout``
connection failure         ``error``                   ``network``
2xx but unusable payload   ``error``                   ``parse_error``
=========================  ==========================  =========================

Design rule: *a failure is never converted into data.*  ``data`` is set only for ``ok``.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional, TypeVar

import httpx

from app.core.safe_http import FetchError, UnsafeTargetError
from app.models.schemas import ProviderResult, ProviderStatus

T = TypeVar("T")


def start_timer() -> float:
    return time.perf_counter()


def _latency_ms(started: Optional[float]) -> Optional[float]:
    return None if started is None else round((time.perf_counter() - started) * 1000.0, 2)


def ok(source: str, data: T, *, http_status: Optional[int] = 200, started: Optional[float] = None,
       reason: Optional[str] = None, mock: bool = False) -> ProviderResult[T]:
    return ProviderResult[T](source=source, status=ProviderStatus.OK, data=data,
                             http_status=http_status, reason=reason,
                             latency_ms=_latency_ms(started), mock=mock)


def not_found(source: str, *, http_status: Optional[int] = 404,
              started: Optional[float] = None) -> ProviderResult:
    return ProviderResult(source=source, status=ProviderStatus.NOT_FOUND, http_status=http_status,
                          latency_ms=_latency_ms(started))


def error(source: str, reason: str, *, http_status: Optional[int] = None,
          started: Optional[float] = None, retry_after: Optional[float] = None) -> ProviderResult:
    return ProviderResult(source=source, status=ProviderStatus.ERROR, reason=reason,
                          http_status=http_status, latency_ms=_latency_ms(started),
                          retry_after=None if retry_after is None else round(float(retry_after), 1))


def skipped(source: str, reason: str) -> ProviderResult:
    return ProviderResult(source=source, status=ProviderStatus.SKIPPED, reason=reason)


def not_configured(source: str, reason: str = "not_configured") -> ProviderResult:
    return ProviderResult(source=source, status=ProviderStatus.NOT_CONFIGURED, reason=reason)


def from_http_status(source: str, status_code: int, *, started: Optional[float] = None,
                     forbidden_reason: str = "auth") -> Optional[ProviderResult]:
    """Result for a non-success status, or ``None`` for 2xx (caller parses the body).

    ``forbidden_reason`` lets NVD say ``auth_or_rate_limited`` because it uses 403 for both.
    """
    if 200 <= status_code < 300:
        return None
    if status_code == 404:
        return not_found(source, http_status=404, started=started)
    if status_code == 401:
        return error(source, "auth", http_status=status_code, started=started)
    if status_code == 403:
        return error(source, forbidden_reason, http_status=status_code, started=started)
    if status_code == 429:
        return error(source, "rate_limited", http_status=status_code, started=started)
    if status_code >= 500:
        return error(source, "server_error", http_status=status_code, started=started)
    if status_code == 400:
        return error(source, "bad_request", http_status=status_code, started=started)
    return error(source, f"http_{status_code}", http_status=status_code, started=started)


def from_exception(source: str, exc: BaseException, *, started: Optional[float] = None) -> ProviderResult:
    """Classify a transport-level failure (no HTTP response was received)."""
    if isinstance(exc, UnsafeTargetError):          # SSRF policy refused the destination
        return error(source, f"blocked:{exc.reason}", started=started)
    if isinstance(exc, FetchError):                  # timeout / network / dns_failure from SafeFetcher
        return error(source, exc.reason, started=started)
    if isinstance(exc, httpx.TimeoutException):
        return error(source, "timeout", started=started)
    if isinstance(exc, (httpx.ConnectError, httpx.NetworkError, httpx.ProxyError)):
        return error(source, "network", started=started)
    if isinstance(exc, httpx.HTTPError):
        return error(source, "network", started=started)
    return error(source, f"unexpected:{type(exc).__name__}", started=started)


DEFAULT_RETRY_AFTER = 60.0          # used when a 429 carries no (usable) Retry-After
MAX_RETRY_AFTER = 24 * 3600.0


def parse_retry_after(value: Optional[str], *, default: Optional[float] = DEFAULT_RETRY_AFTER,
                      now: Optional[datetime] = None) -> Optional[float]:
    """Seconds to back off from a ``Retry-After`` header (delta-seconds or an HTTP-date, RFC 9110 §10.2.3).

    A missing, negative, zero or unparseable value yields ``default`` — by default a conservative 60 s rather
    than "retry now": the provider just told us to stop, and guessing 0 would hammer it again immediately.
    Callers that have a better fallback (NVD: exponential backoff) pass ``default=None``.
    """
    if value:
        value = value.strip()
        try:
            seconds = float(value)
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                seconds = max((when - (now or datetime.now(timezone.utc))).total_seconds(), 1.0)
            except (TypeError, ValueError):
                return default
        if seconds > 0:
            return min(seconds, MAX_RETRY_AFTER)
    return default
