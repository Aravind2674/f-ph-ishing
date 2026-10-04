"""
ThreatFusion – RDAP / WHOIS registration data (A1-3)
====================================================

The **real domain age**.  ``domain_age_days`` used to be a placeholder constant (``365``, later ``None`` — see
A0-1); it now comes from the registry's own *registration* event.

How
---
1. **IANA bootstrap (RFC 9224)** — ``https://data.iana.org/rdap/dns.json`` maps a TLD to the RDAP server(s) of its
   registry.  Cached for a week.
2. ``GET <base>domain/<registered domain>`` with ``Accept: application/rdap+json`` (RFC 9083): events
   (``registration`` / ``expiration`` / ``last changed``), registrar entity, status flags, name servers.
3. **WHOIS only where a TLD has no RDAP service** — ask ``whois.iana.org`` which server is authoritative, query it
   on port 43 and read the creation date.  Free-text and brittle, hence the last resort (switchable).

Safety & privacy
----------------
* Both the bootstrap and every RDAP/WHOIS host come from *remote data*, so they are reached through
  :class:`~app.core.safe_http.SafeFetcher` / ``resolve_checked`` (all A/AAAA checked, internal ranges refused,
  connection pinned) — a poisoned bootstrap pointing at ``169.254.169.254`` is refused, not fetched.
* Only the **registered domain** is sent, never a full URL, and never a private/local name or an IP
  (``provider_block_reason``); that is what a registry's public RDAP service is for.
* Access is rate-limited by a shared limiter and honours ``Retry-After``.

Three-state: ``ok`` (with ``reason="no_registration_date"`` if the registry publishes none — the age is then
*unknown*, never 0) · ``not_found`` (the registry has no such domain) · ``error`` (timeout / rate limit / server
error / unparseable) · ``skipped`` (private name, no registered domain, or no RDAP *and* no WHOIS for the TLD).
The registration **date** is stored (not the age) so a cached record keeps ageing; use :func:`domain_age_days`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from urllib.parse import quote

from pydantic import BaseModel, Field

from app.core import privacy
from app.core import providers as prov
from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.core.safe_http import FetchError, FetchPolicy, SafeFetcher, UnsafeTargetError, parse_host_ip
from app.models.schemas import ProviderResult, ProviderStatus, RdapInfo

logger = logging.getLogger(__name__)

SOURCE = "rdap"
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_BOOTSTRAP_SOURCE = "rdap_bootstrap"
_MAX_WHOIS_BYTES = 64 * 1024


class RdapBootstrap(BaseModel):
    """The IANA bootstrap reduced to ``tld -> [base urls]`` (https first)."""

    services: dict[str, list[str]] = Field(default_factory=dict)


def domain_age_days(info: Optional[RdapInfo], now: Optional[datetime] = None) -> Optional[float]:
    """Age in days at ``now`` from the registration date, or ``None`` if unknown (never a made-up 0)."""
    if info is None or info.registered_at is None:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - info.registered_at).total_seconds() / 86400.0)


def _parse_date(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d", "%d/%m/%Y", "%Y-%m-%d %H:%M:%S", "%b %d %Y"):
            try:
                dt = datetime.strptime(text.split(" (")[0], fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class RdapClient:
    def __init__(
        self,
        use_mock: bool = True,
        *,
        policy: Optional[FetchPolicy] = None,
        cache: Optional[ProviderCache] = None,
        limiter: Optional[QuotaLimiter] = None,
        cache_ttl: float = 24 * 3600.0,
        not_found_ttl: float = 900.0,
        bootstrap_ttl: float = 7 * 24 * 3600.0,
        bootstrap_url: str = BOOTSTRAP_URL,
        max_queue_seconds: float = 10.0,
        whois_fallback: bool = True,
        iana_whois: tuple[str, int] = ("whois.iana.org", 43),
        whois_port: int = 43,
        whois_timeout: float = 6.0,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._use_mock = use_mock
        self._policy = policy
        self._fetcher: Optional[SafeFetcher] = None
        self._cache = cache if cache is not None else ProviderCache()
        self._limiter = limiter if limiter is not None else QuotaLimiter(0, 0)
        self._ttl = cache_ttl
        self._not_found_ttl = not_found_ttl
        self._bootstrap_ttl = bootstrap_ttl
        self._bootstrap_url = bootstrap_url
        self._max_queue = max_queue_seconds
        self._whois_fallback = whois_fallback
        self._iana_whois = iana_whois
        self._whois_port = whois_port
        self._whois_timeout = whois_timeout
        self._clock = clock

    def _get_fetcher(self) -> SafeFetcher:
        if self._fetcher is None:
            self._fetcher = SafeFetcher(self._policy)           # policy None -> from settings (resolved lazily)
        return self._fetcher

    async def close(self) -> None:
        return None

    # ── bootstrap ──────────────────────────────────────────────────────
    async def _bootstrap(self) -> tuple[Optional[RdapBootstrap], Optional[ProviderResult]]:
        try:
            cached = await self._cache.get(_BOOTSTRAP_SOURCE, "dns.json", RdapBootstrap)
        except Exception:
            cached = None
        if cached is not None and cached.data is not None:
            return cached.data, None
        try:
            res = await self._get_fetcher().fetch(self._bootstrap_url, headers={"Accept": "application/json"})
            if res.status_code != 200:
                raise FetchError("bootstrap_http", str(res.status_code))
            doc = json.loads(res.body.decode("utf-8", errors="replace"))
            services: dict[str, list[str]] = {}
            for entry in doc.get("services", []):
                tlds, urls = entry[0], entry[1]
                ordered = sorted(urls, key=lambda u: not str(u).lower().startswith("https://"))
                for tld in tlds:
                    services[str(tld).lower()] = [str(u) for u in ordered]
        except Exception as exc:                                  # unreachable, non-200 or unparseable
            logger.warning("RDAP bootstrap unavailable: %s", exc)
            return None, prov.error(SOURCE, "bootstrap_failed")
        boot = RdapBootstrap(services=services)
        try:
            await self._cache.put(_BOOTSTRAP_SOURCE, "dns.json", prov.ok(_BOOTSTRAP_SOURCE, boot, http_status=200),
                                  ttl_ok=self._bootstrap_ttl, ttl_not_found=60)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")
        return boot, None

    # ── parsing ────────────────────────────────────────────────────────
    @staticmethod
    def _parse(domain: str, doc: dict, server: str) -> RdapInfo:
        events = {str(e.get("eventAction", "")).lower(): _parse_date(e.get("eventDate"))
                  for e in doc.get("events", []) if isinstance(e, dict)}
        registrar = None
        for ent in doc.get("entities", []) or []:
            if isinstance(ent, dict) and "registrar" in [str(r).lower() for r in ent.get("roles", [])]:
                try:
                    for prop in ent["vcardArray"][1]:
                        if prop[0] == "fn":
                            registrar = str(prop[3])
                            break
                except (KeyError, IndexError, TypeError):
                    pass
                if registrar:
                    break
        return RdapInfo(
            domain=domain,
            registered_at=events.get("registration"),
            expires_at=events.get("expiration"),
            last_changed_at=events.get("last changed"),
            registrar=registrar,
            statuses=[str(s) for s in doc.get("status", []) if isinstance(s, str)],
            nameservers=sorted({str(n.get("ldhName", "")).lower() for n in doc.get("nameservers", [])
                                if isinstance(n, dict) and n.get("ldhName")}),
            source="rdap",
            server=server,
        )

    # ── WHOIS (only where a TLD has no RDAP) ───────────────────────────
    async def _whois_query(self, host: str, port: int, query: str) -> str:
        """One WHOIS exchange: SSRF-checked resolution, capped read, hard timeout. Raises ``FetchError``."""
        try:
            ips = await asyncio.wait_for(self._get_fetcher().resolve_checked(host, port), timeout=self._whois_timeout)
        except asyncio.TimeoutError as exc:
            raise FetchError("whois_failed", "dns timeout") from exc
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(str(ips[0]), port), timeout=self._whois_timeout)
            writer.write(f"{query}\r\n".encode("ascii", errors="ignore"))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(_MAX_WHOIS_BYTES), timeout=self._whois_timeout)
        except (asyncio.TimeoutError, OSError) as exc:
            raise FetchError("whois_failed", type(exc).__name__) from exc
        finally:
            if writer is not None:
                writer.close()
        return data.decode("utf-8", errors="replace")

    async def _whois(self, domain: str, tld: str, started: float) -> ProviderResult[RdapInfo]:
        if not self._whois_fallback:
            return prov.skipped(SOURCE, "no_rdap_for_tld")
        try:
            iana_text = await self._whois_query(self._iana_whois[0], self._iana_whois[1], tld)
            m = re.search(r"^\s*whois:\s*(\S+)", iana_text, re.IGNORECASE | re.MULTILINE)
            if not m:
                return prov.skipped(SOURCE, "no_rdap_for_tld")
            server = m.group(1).strip().lower()
            text = await self._whois_query(server, self._whois_port, domain)
        except (FetchError, UnsafeTargetError) as exc:
            logger.warning("WHOIS fallback failed for %s: %s", domain, exc)
            return prov.error(SOURCE, "whois_failed", started=started)
        created = re.search(
            r"^\s*(?:creation date|created(?: on)?|registered(?: on)?|registration time|domain registered)\s*:\s*(.+?)\s*$",
            text, re.IGNORECASE | re.MULTILINE)
        registrar = re.search(r"^\s*registrar\s*:\s*(.+?)\s*$", text, re.IGNORECASE | re.MULTILINE)
        info = RdapInfo(domain=domain, registered_at=_parse_date(created.group(1)) if created else None,
                        registrar=registrar.group(1) if registrar else None, source="whois", server=server)
        reason = None if info.registered_at else "no_registration_date"
        return prov.ok(SOURCE, info, http_status=None, started=started, reason=reason)

    # ── public ─────────────────────────────────────────────────────────
    async def lookup(self, registered_domain: Optional[str]) -> ProviderResult[RdapInfo]:
        if not registered_domain:
            return prov.skipped(SOURCE, "no_registered_domain")
        domain = registered_domain.lower().rstrip(".")
        if parse_host_ip(domain) is not None:
            return prov.skipped(SOURCE, "not_a_domain")
        blocked = privacy.provider_block_reason(domain)
        if blocked:
            return prov.skipped(SOURCE, blocked)
        if self._use_mock:
            return prov.ok(SOURCE, self._mock(domain), http_status=None, mock=True)

        key = f"rdap:{domain}"
        try:
            cached = await self._cache.get(SOURCE, key, RdapInfo)
        except Exception:
            logger.exception("provider cache read failed; continuing without it")
            cached = None
        if cached is not None:
            return cached

        started = prov.start_timer()
        boot, failure = await self._bootstrap()
        if failure is not None:
            return failure
        tld = domain.rsplit(".", 1)[-1]
        bases = boot.services.get(tld)
        if not bases:
            return await self._whois(domain, tld, started)

        wait = await self._limiter.acquire(max_wait=self._max_queue)
        if wait is not None:
            return prov.error(SOURCE, "rate_limited", retry_after=wait)
        base = bases[0]
        url = f"{base.rstrip('/')}/domain/{quote(domain)}"
        try:
            res = await self._get_fetcher().fetch(url, headers={"Accept": "application/rdap+json, application/json"})
        except Exception as exc:                                  # SafeFetcher: blocked / timeout / network
            return prov.from_exception(SOURCE, exc, started=started)
        failure = prov.from_http_status(SOURCE, res.status_code, started=started)
        if failure is not None:
            if res.status_code == 429:
                seconds = prov.parse_retry_after(res.headers.get("retry-after"))
                self._limiter.penalize(seconds)
                failure = failure.model_copy(update={"retry_after": round(seconds, 1)})
            result = failure
        else:
            try:
                doc = json.loads(res.body.decode("utf-8", errors="replace"))
                if not isinstance(doc, dict):
                    raise ValueError("RDAP response is not an object")
                info = self._parse(domain, doc, server=base)
            except (ValueError, KeyError, TypeError):
                return prov.error(SOURCE, "parse_error", http_status=res.status_code, started=started)
            reason = None if info.registered_at else "no_registration_date"
            result = prov.ok(SOURCE, info, http_status=res.status_code, started=started, reason=reason)
        try:
            await self._cache.put(SOURCE, key, result, ttl_ok=self._ttl, ttl_not_found=self._not_found_ttl)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")
        return result

    # ── mock ───────────────────────────────────────────────────────────
    def _mock(self, domain: str) -> RdapInfo:
        """Deterministic: established brands are decades old, 'evil' lookalikes were registered days ago."""
        now = self._clock()
        if any(w in domain for w in ("google", "microsoft")):
            age = 9000.0
        elif any(w in domain for w in ("evil", "malicious", "phish")):
            age = 2.0
        else:
            age = 100.0 + int(hashlib.sha256(domain.encode()).hexdigest(), 16) % 4000
        return RdapInfo(domain=domain, registered_at=now - timedelta(days=age), expires_at=now + timedelta(days=300),
                        registrar="Mock Registrar, Inc.", statuses=["client transfer prohibited"],
                        nameservers=[f"ns1.{domain}", f"ns2.{domain}"], source="rdap", server="mock")
