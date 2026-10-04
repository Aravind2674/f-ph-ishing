"""
ThreatFusion – Certificate Transparency history (B3)
====================================================

Every publicly trusted TLS certificate is written to public, append-only **Certificate Transparency** logs.  crt.sh indexes
them, so we can ask "what certificates have ever been issued for this host, and when?" without touching the host.

Why it is a phishing signal (and where it is weak)
--------------------------------------------------
* A phishing site usually gets its first certificate days — often hours — before it goes live; an established site has
  years of them.  ``cert_first_seen_days`` and ``cert_count_30d`` (a burst of recent issuance) capture that.
* Free, automated DV issuers (Let's Encrypt, ZeroSSL…) make certificates cheap for attackers — but they also serve a large
  share of legitimate sites, so ``issuer_is_free_dv`` is only a weak hint and is reported, never treated as a verdict.
* Phishing kits often put several brand-like names on one certificate: ``san_brand_keyword_hits`` counts the other names
  on the host's certificates that imitate a protected brand (the B4 detector, applied to each name).
* First-seen-in-CT is **not** the registration date — a domain can exist for years with no certificate; RDAP (A1-3) is the
  registration source.  The two are shown side by side.

Three-state: ``ok`` · ``not_found`` (the logs have no certificate for the host — itself informative, but never a number) ·
``error`` (crt.sh is frequently overloaded: ``server_error`` / ``timeout`` / ``rate_limited`` / ``parse_error`` /
``response_too_large``; failures are never cached and never become features) · ``skipped`` (private name / IP).

Privacy: only the host name is sent (never a URL, path or query).  Reached through the SSRF-guarded fetcher.
The cached record keeps the raw timestamps; :func:`derive` recomputes the ages on every read so a cached answer keeps ageing.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from urllib.parse import quote

from app.core import privacy
from app.core import providers as prov
from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.core.safe_http import FetchPolicy, SafeFetcher, parse_host_ip
from app.models.schemas import CtCert, CtInfo, ProviderResult

logger = logging.getLogger(__name__)

SOURCE = "ct"
BASE_URL = "https://crt.sh/"
MAX_CERTS_KEPT = 300
MAX_SAN_NAMES = 100
WINDOW_DAYS = 30

# Issuers that hand out free / automated domain-validated certificates (matched on the issuer name, case-insensitive).
FREE_DV_ISSUERS = ("let's encrypt", "lets encrypt", "zerossl", "buypass", "google trust services", "cpanel", "cloudflare")


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_free_dv(issuer: Optional[str]) -> Optional[bool]:
    """``None`` when there is no issuer to judge; otherwise whether it is a free / automated DV issuer."""
    if not issuer:
        return None
    low = issuer.lower()
    return any(name in low for name in FREE_DV_ISSUERS)


def _issuer_short(issuer_name: Any) -> Optional[str]:
    """crt.sh gives a DN (``C=US, O=Let's Encrypt, CN=R3``): keep the organisation (or the whole string)."""
    if not isinstance(issuer_name, str) or not issuer_name.strip():
        return None
    for part in issuer_name.split(","):
        key, _, val = part.strip().partition("=")
        if key.strip().upper() == "O" and val.strip():
            return val.strip()
    return issuer_name.strip()


# ── brand-like names on the certificates ────────────────────────────────────
_index = None


def _curated_index():
    global _index
    if _index is None:
        from app.ml.brands import BrandIndex
        _index = BrandIndex.build()
    return _index


def brand_hits(names: list[str], host: str) -> list[str]:
    """``'name -> Brand'`` for each SAN name (other than the host itself) that the B4 detector flags as a look-alike."""
    from app.ml.lookalike import assess_lookalike

    index = _curated_index()
    own = {host, f"www.{host}"}
    hits: list[str] = []
    for name in names:
        if name in own:
            continue
        check = assess_lookalike(name, index)
        if check.status == "lookalike" and check.match is not None:
            hits.append(f"{name} -> {check.match.brand}")
    return hits


# ── parsing & derivation ────────────────────────────────────────────────────
def parse_entries(host: str, rows: list[Any]) -> CtInfo:
    """Build a :class:`CtInfo` from crt.sh's JSON rows (deduplicating the precertificate / certificate pair)."""
    seen: set[str] = set()
    certs: list[CtCert] = []
    names: dict[str, None] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ident = str(row.get("serial_number") or row.get("id") or id(row))
        if ident in seen:
            continue
        seen.add(ident)
        logged = _parse_time(row.get("entry_timestamp"))
        not_before = _parse_time(row.get("not_before"))
        certs.append(CtCert(logged_at=logged, not_before=not_before, issuer=_issuer_short(row.get("issuer_name"))))
        for raw in str(row.get("name_value") or "").splitlines():
            name = raw.strip().lower().lstrip("*.")
            if name:
                names.setdefault(name, None)
    stamps = [t for c in certs for t in (c.logged_at, c.not_before) if t is not None]
    first_seen = min(stamps) if stamps else None
    certs.sort(key=lambda c: c.logged_at or c.not_before or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    san = list(names)[:MAX_SAN_NAMES]
    return CtInfo(host=host, certs_total=len(certs), certs=certs[:MAX_CERTS_KEPT], san_names=san,
                  first_seen=first_seen, truncated=len(certs) > MAX_CERTS_KEPT,
                  san_brand_hits=brand_hits(san, host), san_brand_keyword_hits=0)


def derive(info: CtInfo, now: Optional[datetime] = None) -> CtInfo:
    """Recompute the age-dependent fields from the stored timestamps (so a cached answer keeps ageing)."""
    now = now or datetime.now(timezone.utc)
    window = now - timedelta(days=WINDOW_DAYS)
    first_days = None if info.first_seen is None else max(0.0, (now - info.first_seen).total_seconds() / 86400.0)
    recent = sum(1 for c in info.certs if (c.logged_at or c.not_before) is not None and (c.logged_at or c.not_before) >= window)
    newest = info.certs[0] if info.certs else None
    issuer = newest.issuer if newest else None
    return info.model_copy(update={
        "cert_first_seen_days": first_days,
        "cert_count_30d": recent if info.certs else None,
        "latest_issuer": issuer,
        "issuer_is_free_dv": is_free_dv(issuer),
        "san_brand_keyword_hits": len(info.san_brand_hits),
    })


class CtClient:
    def __init__(
        self,
        use_mock: bool = True,
        *,
        policy: Optional[FetchPolicy] = None,
        base_url: str = BASE_URL,
        cache: Optional[ProviderCache] = None,
        limiter: Optional[QuotaLimiter] = None,
        cache_ttl: float = 6 * 3600.0,
        not_found_ttl: float = 900.0,
        max_bytes: int = 6 * 1024 * 1024,
        max_queue_seconds: float = 10.0,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._use_mock = use_mock
        self._policy = policy
        self._base = base_url
        self._fetcher: Optional[SafeFetcher] = None
        self._cache = cache if cache is not None else ProviderCache()
        self._limiter = limiter if limiter is not None else QuotaLimiter(0, 0)
        self._ttl = cache_ttl
        self._not_found_ttl = not_found_ttl
        self._max_bytes = max_bytes
        self._max_queue = max_queue_seconds
        self._clock = clock

    def _get_fetcher(self) -> SafeFetcher:
        if self._fetcher is None:
            self._fetcher = SafeFetcher(self._policy or FetchPolicy.from_settings(max_bytes=self._max_bytes))
        return self._fetcher

    async def close(self) -> None:
        return None

    async def lookup(self, host: Optional[str]) -> ProviderResult[CtInfo]:
        if not host:
            return prov.skipped(SOURCE, "no_host")
        name = host.lower().rstrip(".")
        if parse_host_ip(name) is not None:
            return prov.skipped(SOURCE, "not_a_domain")
        blocked = privacy.provider_block_reason(name)
        if blocked:
            return prov.skipped(SOURCE, blocked)
        if self._use_mock:
            return prov.ok(SOURCE, derive(self._mock(name), self._clock()), http_status=None, mock=True)

        key = f"ct:{name}"
        try:
            cached = await self._cache.get(SOURCE, key, CtInfo)
        except Exception:
            logger.exception("provider cache read failed; continuing without it")
            cached = None
        if cached is not None:
            if cached.data is not None:
                cached = cached.model_copy(update={"data": derive(cached.data, self._clock())})
            return cached

        started = prov.start_timer()
        wait = await self._limiter.acquire(max_wait=self._max_queue)
        if wait is not None:
            return prov.error(SOURCE, "rate_limited", retry_after=wait)
        url = f"{self._base}?q={quote(name)}&output=json"
        try:
            res = await self._get_fetcher().fetch(url, headers={"Accept": "application/json"})
        except Exception as exc:                                  # blocked / timeout / network / too large
            reason = getattr(exc, "reason", "")
            if reason in ("too_large", "response_too_large"):
                return prov.error(SOURCE, "response_too_large", started=started)
            return prov.from_exception(SOURCE, exc, started=started)
        failure = prov.from_http_status(SOURCE, res.status_code, started=started)
        if failure is not None:
            if res.status_code == 429:
                seconds = prov.parse_retry_after(res.headers.get("retry-after"))
                self._limiter.penalize(seconds)
                failure = failure.model_copy(update={"retry_after": round(seconds, 1)})
            return failure                                        # a failure is never cached (A0-1)
        if res.truncated:
            return prov.error(SOURCE, "response_too_large", http_status=res.status_code, started=started)
        rows = _load_rows(res.body)
        if rows is None:
            return prov.error(SOURCE, "parse_error", http_status=res.status_code, started=started)
        if not rows:
            result: ProviderResult = prov.not_found(SOURCE, http_status=res.status_code, started=started)
        else:
            result = prov.ok(SOURCE, derive(parse_entries(name, rows), self._clock()), http_status=res.status_code, started=started)
        try:
            await self._cache.put(SOURCE, key, result, ttl_ok=self._ttl, ttl_not_found=self._not_found_ttl)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")
        return result

    # ── mock ───────────────────────────────────────────────────────────
    def _mock(self, host: str) -> CtInfo:
        """Deterministic: established brands have years of certificates, 'evil' hosts got theirs a few days ago."""
        now = self._clock()
        if any(w in host for w in ("google", "microsoft")):
            ages, issuer = [3000, 2200, 1500, 800, 200, 40], "DigiCert Inc"
        elif any(w in host for w in ("evil", "malicious", "phish")):
            ages, issuer = [4, 3, 2, 1], "Let's Encrypt"
        else:
            base = 200 + int(hashlib.sha256(host.encode()).hexdigest(), 16) % 1500
            ages, issuer = [base, base - 90, base - 180], "Let's Encrypt"
        certs = [CtCert(logged_at=now - timedelta(days=a), not_before=now - timedelta(days=a), issuer=issuer)
                 for a in sorted((max(a, 0) for a in ages))]
        names = [host, f"www.{host}"]
        return CtInfo(host=host, certs_total=len(certs), certs=certs, san_names=names,
                      first_seen=min(c.logged_at for c in certs), san_brand_hits=brand_hits(names, host))


def _load_rows(body: bytes) -> Optional[list[Any]]:
    """crt.sh's JSON array — or, from its older/overloaded paths, one JSON object per line.  ``None`` = not JSON."""
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            return doc
        return [doc] if isinstance(doc, dict) else None
    except ValueError:
        rows = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                return None
            if isinstance(obj, dict):
                rows.append(obj)
        return rows or None
