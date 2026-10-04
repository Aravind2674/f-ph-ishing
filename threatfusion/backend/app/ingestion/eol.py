"""
ThreatFusion – end-of-life data from endoflife.date (A1-4)
===========================================================

``tech_has_known_eol_component`` / ``tech_has_eol_cms_version`` used to be decided by ``EOL_SET`` — six
hard-coded strings such as ``"jQuery 1"`` and ``"PHP 5"``.  WordPress was not in it, so the CMS flag could never be
1, and the list was frozen the day it was typed.  The lifecycle facts now come from **endoflife.date**
(a public, community-maintained API), keyed by *release cycle*:

1. :data:`EOL_SLUGS` maps a Wappalyzer technology name to the endoflife.date product slug.
2. ``GET <base>/<slug>.json`` → the product's cycles (``cycle``, ``eol`` = ``false`` | ``true`` | a date,
   ``latest``).  The newer v1 shape (``result.releases[]``) is understood too.  Cached locally for a week.
3. :func:`evaluate` matches the *detected version* to a cycle by the longest dotted prefix (``5.6.40`` → ``5.6``,
   ``1.12.4`` → ``1``) and decides: EOL date ≤ today (or ``eol: true``) ⇒ **end-of-life**; ``false`` or a future date
   ⇒ **supported**; no matching cycle / unparseable version / unknown product ⇒ **unknown** — never guessed.

Three-state & privacy
---------------------
A lookup that fails leaves that technology's ``eol`` as ``None`` (unknown) — an outage never reads as "not EOL" —
and the scan says so (``endoflife`` outcome: error / partial).  Only a *product slug* (``php``, ``wordpress``)
is sent to endoflife.date — nothing about the target.  Requests go through the SSRF-safe fetcher like every
other remote-controlled URL, and answers are cached (failures never).

.. note::  The slug table is built from endoflife.date's published product names.  A wrong slug simply 404s
   (→ unknown, harmless); verify/extend it with one approved live call when convenient.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import date, datetime
from typing import Callable, Optional

from pydantic import BaseModel, Field

from app.core import providers as prov
from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.core.safe_http import FetchPolicy, SafeFetcher
from app.models.schemas import DetectedTechnology, ProviderResult, ProviderStatus, TechFingerprintResult

logger = logging.getLogger(__name__)

SOURCE = "endoflife"
DEFAULT_BASE_URL = "https://endoflife.date/api"

# Wappalyzer technology name (lower-case) -> endoflife.date product slug.
EOL_SLUGS: dict[str, str] = {
    # CMS & e-commerce
    "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla", "magento": "magento", "typo3 cms": "typo3",
    "typo3": "typo3", "umbraco": "umbraco", "moodle": "moodle", "nextcloud": "nextcloud", "prestashop": "prestashop",
    # languages & runtimes
    "php": "php", "python": "python", "node.js": "nodejs", "ruby": "ruby", "go": "go", "java": "oracle-jdk",
    # frameworks
    "ruby on rails": "rails", "django": "django", "laravel": "laravel", "symfony": "symfony",
    "spring": "spring-framework", "spring framework": "spring-framework", "express": "express",
    "angularjs": "angularjs", "angular": "angular", "react": "react", "vue.js": "vue", "next.js": "nextjs",
    "nuxt.js": "nuxt", "ember.js": "emberjs", "jquery": "jquery", "bootstrap": "bootstrap",
    # servers & platforms
    "nginx": "nginx", "apache http server": "apache-http-server", "apache": "apache-http-server",
    "apache tomcat": "tomcat", "tomcat": "tomcat", "microsoft iis": "iis", "iis": "iis", "openssl": "openssl",
    "microsoft asp.net": "dotnet", "asp.net": "dotnet",
    # databases & infra
    "mysql": "mysql", "mariadb": "mariadb", "postgresql": "postgresql", "redis": "redis", "mongodb": "mongodb",
    "elasticsearch": "elasticsearch", "grafana": "grafana", "gitlab": "gitlab",
    # operating systems
    "ubuntu": "ubuntu", "debian": "debian", "centos": "centos",
}


def slug_for(name: Optional[str]) -> Optional[str]:
    return EOL_SLUGS.get((name or "").strip().lower())


# ── models ──────────────────────────────────────────────────────────────────
class EolCycle(BaseModel):
    cycle: str
    eol_date: Optional[str] = None            # ISO date the cycle reaches / reached end of life
    eol_flag: Optional[bool] = None           # the API's boolean form (true = already EOL)
    latest: Optional[str] = None


class EolProduct(BaseModel):
    slug: str
    cycles: list[EolCycle] = Field(default_factory=list)


class EolVerdict(BaseModel):
    """The lifecycle verdict for one detected technology (``eol=None`` = unknown)."""

    eol: Optional[bool] = None
    eol_date: Optional[str] = None
    cycle: Optional[str] = None
    latest: Optional[str] = None
    reason: Optional[str] = Field(None, description="Why unknown: unparseable_version | no_matching_cycle | no_eol_data")


class EolReport(BaseModel):
    """Verdicts keyed by technology name."""

    items: dict[str, EolVerdict] = Field(default_factory=dict)


# ── parsing & evaluation (pure) ─────────────────────────────────────────────
def _iso(value: object) -> Optional[str]:
    if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}", value):
        return value[:10]
    return None


def parse_product(slug: str, payload: object) -> EolProduct:
    """Normalise an endoflife.date response (legacy list *or* v1 ``result.releases``). Raises ``ValueError``."""
    cycles: list[EolCycle] = []
    if isinstance(payload, list):
        for row in payload:
            if not isinstance(row, dict) or "cycle" not in row:
                continue
            eol = row.get("eol")
            cycles.append(EolCycle(
                cycle=str(row["cycle"]), eol_date=_iso(eol), eol_flag=eol if isinstance(eol, bool) else None,
                latest=str(row["latest"]) if row.get("latest") else None))
    elif isinstance(payload, dict) and isinstance(payload.get("result"), dict) \
            and isinstance(payload["result"].get("releases"), list):
        for row in payload["result"]["releases"]:
            if not isinstance(row, dict) or "name" not in row:
                continue
            latest = row.get("latest")
            cycles.append(EolCycle(
                cycle=str(row["name"]), eol_date=_iso(row.get("eolFrom")),
                eol_flag=row.get("isEol") if isinstance(row.get("isEol"), bool) else None,
                latest=str(latest.get("name")) if isinstance(latest, dict) and latest.get("name") else None))
    else:
        raise ValueError("unrecognised endoflife.date response")
    if not cycles:
        raise ValueError("no release cycles in response")
    return EolProduct(slug=slug, cycles=cycles)


def _numeric_parts(version: Optional[str]) -> Optional[list[str]]:
    m = re.match(r"^\s*v?(\d+(?:\.\d+)*)", version or "")
    return m.group(1).split(".") if m else None


def evaluate(product: EolProduct, version: Optional[str], today: Optional[date] = None) -> EolVerdict:
    """Is ``version`` of this product end-of-life on ``today``? Longest dotted-prefix cycle match; else unknown."""
    today = today or date.today()
    parts = _numeric_parts(version)
    if not parts:
        return EolVerdict(reason="unparseable_version")
    by_cycle = {c.cycle: c for c in product.cycles}
    for n in range(len(parts), 0, -1):
        cycle = by_cycle.get(".".join(parts[:n]))
        if cycle is None:
            continue
        if cycle.eol_date:
            eol = date.fromisoformat(cycle.eol_date) <= today
        elif cycle.eol_flag is not None:
            eol = cycle.eol_flag
        else:
            return EolVerdict(cycle=cycle.cycle, latest=cycle.latest, reason="no_eol_data")
        return EolVerdict(eol=eol, eol_date=cycle.eol_date, cycle=cycle.cycle, latest=cycle.latest)
    return EolVerdict(reason="no_matching_cycle")


def assessable(technologies: list[DetectedTechnology]) -> list[DetectedTechnology]:
    """Technologies we can ask about: a *version* is detected and the product is in the slug table."""
    return [t for t in technologies if t.version and slug_for(t.name)]


def apply_eol(tech: TechFingerprintResult, report: EolReport) -> TechFingerprintResult:
    """A copy of ``tech`` whose technologies carry their lifecycle verdicts."""
    out: list[DetectedTechnology] = []
    assessed = 0
    for t in tech.technologies:
        v = report.items.get(t.name)
        if v is None:
            out.append(t)
            continue
        if v.eol is not None:
            assessed += 1
        out.append(t.model_copy(update={"eol": v.eol, "eol_date": v.eol_date, "eol_cycle": v.cycle,
                                        "latest_version": v.latest}))
    return tech.model_copy(update={"technologies": out, "eol_assessed": assessed})


# ── mock data (deterministic, labelled) ─────────────────────────────────────
_MOCK_PRODUCTS: dict[str, list[tuple[str, object]]] = {
    "wordpress": [("6.8", False), ("6.1", "2023-01-01"), ("4.9", True)],
    "php": [("8.4", "2028-12-31"), ("7.4", "2022-11-28"), ("5.6", "2018-12-31")],
    "jquery": [("3", False), ("2", True), ("1", True)],
    "angularjs": [("1", "2022-01-01")],
    "drupal": [("10", False), ("9", "2023-11-01")],
    "joomla": [("5", False), ("4", False), ("3", True)],
    "nginx": [("1.27", False), ("1.21", True)],
    "apache-http-server": [("2.4", False), ("2.2", True)],
    "react": [("19", False), ("18", False), ("15", True)],
}


def _mock_product(slug: str) -> Optional[EolProduct]:
    rows = _MOCK_PRODUCTS.get(slug)
    if rows is None:
        return None
    return EolProduct(slug=slug, cycles=[
        EolCycle(cycle=c, eol_date=e if isinstance(e, str) else None, eol_flag=e if isinstance(e, bool) else None)
        for c, e in rows])


# ── the client ──────────────────────────────────────────────────────────────
class EolClient:
    def __init__(
        self,
        use_mock: bool = True,
        *,
        policy: Optional[FetchPolicy] = None,
        cache: Optional[ProviderCache] = None,
        limiter: Optional[QuotaLimiter] = None,
        base_url: str = DEFAULT_BASE_URL,
        cache_ttl: float = 7 * 24 * 3600.0,
        not_found_ttl: float = 24 * 3600.0,
        max_concurrency: int = 4,
        max_queue_seconds: float = 10.0,
        clock: Callable[[], date] = date.today,
    ) -> None:
        self._use_mock = use_mock
        self._policy = policy
        self._fetcher: Optional[SafeFetcher] = None
        self._cache = cache if cache is not None else ProviderCache()
        self._limiter = limiter if limiter is not None else QuotaLimiter(0, 0)
        self._base = base_url.rstrip("/")
        self._ttl = cache_ttl
        self._not_found_ttl = not_found_ttl
        self._concurrency = max(1, max_concurrency)
        self._max_queue = max_queue_seconds
        self._clock = clock

    def _get_fetcher(self) -> SafeFetcher:
        if self._fetcher is None:
            self._fetcher = SafeFetcher(self._policy)
        return self._fetcher

    async def close(self) -> None:
        return None

    async def _product(self, slug: str) -> ProviderResult[EolProduct]:
        key = f"product:{slug}"
        try:
            cached = await self._cache.get(SOURCE, key, EolProduct)
        except Exception:
            logger.exception("provider cache read failed; continuing without it")
            cached = None
        if cached is not None:
            return cached
        started = prov.start_timer()
        wait = await self._limiter.acquire(max_wait=self._max_queue)
        if wait is not None:
            return prov.error(SOURCE, "rate_limited", retry_after=wait)
        try:
            res = await self._get_fetcher().fetch(f"{self._base}/{slug}.json", headers={"Accept": "application/json"})
        except Exception as exc:                          # blocked / timeout / network
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
                product = parse_product(slug, json.loads(res.body.decode("utf-8", errors="replace")))
            except (ValueError, TypeError):
                return prov.error(SOURCE, "parse_error", http_status=res.status_code, started=started)
            result = prov.ok(SOURCE, product, http_status=res.status_code, started=started)
        try:
            await self._cache.put(SOURCE, key, result, ttl_ok=self._ttl, ttl_not_found=self._not_found_ttl)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")
        return result

    async def assess(self, technologies: list[DetectedTechnology]) -> ProviderResult[EolReport]:
        """Lifecycle verdicts for the assessable technologies (each product is fetched once)."""
        todo = assessable(technologies)
        if not todo:
            return prov.skipped(SOURCE, "no_assessable_technologies")
        today = self._clock()
        started = prov.start_timer()
        slugs = sorted({slug_for(t.name) for t in todo})                     # type: ignore[arg-type]

        if self._use_mock:
            products = {s: _mock_product(s) for s in slugs}
            items = {t.name: evaluate(products[slug_for(t.name)], t.version, today) if products[slug_for(t.name)]
                     else EolVerdict(reason="no_eol_data") for t in todo}
            return prov.ok(SOURCE, EolReport(items=items), http_status=None, mock=True)

        gate = asyncio.Semaphore(self._concurrency)

        async def one(slug: str) -> ProviderResult[EolProduct]:
            async with gate:
                return await self._product(slug)

        results = dict(zip(slugs, await asyncio.gather(*(one(s) for s in slugs))))
        ok_products = {s: r.data for s, r in results.items() if r.ok}
        if not ok_products:
            failures = list(results.values())
            errors = [f for f in failures if f.status == ProviderStatus.ERROR]
            chosen = errors[0] if errors else failures[0]
            return chosen.model_copy(update={"latency_ms": prov._latency_ms(started)})

        items = {t.name: evaluate(ok_products[slug_for(t.name)], t.version, today)
                 for t in todo if slug_for(t.name) in ok_products}
        reason = f"partial:{len(ok_products)}/{len(slugs)}" if len(ok_products) < len(slugs) else None
        all_cached = all(r.cached for r in results.values() if r.ok) and len(ok_products) == len(slugs)
        out = prov.ok(SOURCE, EolReport(items=items), http_status=None if all_cached else 200,
                      started=None if all_cached else started, reason=reason)
        return out.model_copy(update={"cached": True}) if all_cached else out
