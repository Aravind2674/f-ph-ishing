"""
ThreatFusion – local bulk feeds: OpenPhish, PhishTank, Tranco (B2)
==================================================================

A **bulk feed** is a public list that is downloaded once, kept in the local feed store (``core/feeds.py``) and refreshed on a
schedule.  Looking a target up costs no quota, makes no network call — nothing about the target ever leaves the machine —
and every answer carries the feed's **age**, so the UI can say "OpenPhish list, 3 h old" instead of implying it is live.

* **OpenPhish** community feed — one phishing URL per line, refreshed every 12 h.
* **PhishTank** — the verified-online JSON dump (records the targeted brand), refreshed every 12 h; an app key is optional.
* **Tranco** — the research-grade popularity ranking (top N kept), refreshed daily.  It is a *prior*, not a verdict: a
  popular domain is less likely to be a phishing site, but compromised popular sites exist, so it never sets ``listed``.

Honesty rules (shared with the KEV feed, B11)
---------------------------------------------
* A feed that was **never downloaded** is *unknown* (``error / feed_unavailable``) — never "not listed".  The first lookup
  starts a background download (these files are tens of MB: never inline in a scan) and the next scans use it.
* A failed refresh keeps the previous copy; answers are then ``ok`` but marked ``stale`` (``reason = "stale_feed"``).
* A download that parses to nothing, or shrinks a ≥ 200-entry list to under a quarter, is refused (``parse_error`` /
  ``suspicious_shrink``): a truncated or poisoned file must not erase a good list.
* "Not listed" is **absence of evidence**: blocklists are always behind the attackers.

Matching: a feed URL is stored three ways — ``u:`` host+path+query, ``p:`` host+path, ``h:`` host — so a scan can say *how*
it matched: ``exact_url``, ``url_path`` (same page, different query) or ``host`` (the host serves other listed pages —
often a compromised legitimate site, a weaker signal).
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import weakref
import zipfile
from typing import Any, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel

from app.core import providers as prov
from app.core.feeds import FeedStore
from app.core.safe_http import FetchPolicy, SafeFetcher
from app.ingestion.reputation import Subject, _host_reason, _is_bad_host
from app.models.schemas import ProviderResult, ReputationVerdict

logger = logging.getLogger(__name__)

SHRINK_FLOOR = 200            # only lists at least this big are protected by the shrink guard
SHRINK_RATIO = 0.25


class FeedMeta(BaseModel):
    count: int


def split_url(raw: str) -> Optional[tuple[str, str, str]]:
    """``(host+port+path+query, host+port+path, host)`` of a URL, lower-cased, no scheme / fragment / trailing slash."""
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        p = urlsplit(raw)
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port
    except ValueError:
        return None
    if not host:
        return None
    port_text = f":{port}" if port and port not in (80, 443) else ""
    path = p.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    base = f"{host}{port_text}{path}"
    return (base + (f"?{p.query}" if p.query else "")), base, host


class BulkFeed:
    """A downloadable list kept in the local feed store. Subclasses supply ``parse`` (and optionally ``match``)."""

    source = ""
    display = ""
    default_url = ""
    category = "phishing"
    max_bytes = 64 * 1024 * 1024

    def __init__(
        self,
        use_mock: bool = True,
        *,
        store: FeedStore,
        url: Optional[str] = None,
        max_age_hours: float = 12.0,
        policy: Optional[FetchPolicy] = None,
        headers: Optional[dict[str, str]] = None,
        top_n: int = 100_000,
    ) -> None:
        self._use_mock = use_mock
        self._store = store
        self._url = url or self.default_url
        self._max_age_days = max_age_hours / 24.0
        self._policy = policy
        self._headers = headers or {}
        self._top_n = top_n
        self._fetcher: Optional[SafeFetcher] = None
        self._locks: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = weakref.WeakKeyDictionary()
        self._background: Optional[asyncio.Task] = None

    # ── hooks ──────────────────────────────────────────────────────────
    def parse(self, body: bytes) -> dict[str, Any]:
        raise NotImplementedError

    def mock_verdict(self, s: Subject) -> Optional[ReputationVerdict]:
        return None

    # ── plumbing ───────────────────────────────────────────────────────
    def _get_fetcher(self) -> SafeFetcher:
        if self._fetcher is None:
            policy = self._policy or FetchPolicy.from_settings(max_bytes=self.max_bytes, total_timeout=120.0, request_timeout=60.0)
            self._fetcher = SafeFetcher(policy)
        return self._fetcher

    def _lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        lock = self._locks.get(loop)
        if lock is None:
            lock = self._locks[loop] = asyncio.Lock()
        return lock

    async def close(self) -> None:
        task, self._background = self._background, None
        if task is not None and not task.done():
            task.cancel()

    # ── refresh ────────────────────────────────────────────────────────
    async def refresh(self) -> ProviderResult[FeedMeta]:
        """Download the list now. On any failure the previous copy is left untouched."""
        started = prov.start_timer()
        try:
            res = await self._get_fetcher().fetch(self._url, headers=self._headers)
        except Exception as exc:
            return prov.from_exception(self.source, exc, started=started)
        if res.status_code == 404:
            return prov.error(self.source, "not_found_upstream", http_status=404, started=started)
        failure = prov.from_http_status(self.source, res.status_code, started=started)
        if failure is not None:
            return failure
        if res.truncated:
            return prov.error(self.source, "response_too_large", http_status=res.status_code, started=started)
        try:
            entries = await asyncio.to_thread(self.parse, res.body)
            if not entries:
                raise ValueError("empty feed")
        except (ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile, UnicodeError):
            return prov.error(self.source, "parse_error", http_status=res.status_code, started=started)
        previous = await self._store.count(self.source)
        if previous >= SHRINK_FLOOR and len(entries) < previous * SHRINK_RATIO:
            logger.warning("%s download has %d entries but the local copy has %d: refused", self.source, len(entries), previous)
            return prov.error(self.source, "suspicious_shrink", http_status=res.status_code, started=started)
        await self._store.replace(self.source, entries, source_url=self.source)      # never store a URL that may hold a key
        logger.info("%s feed refreshed: %d entries", self.source, len(entries))
        return prov.ok(self.source, FeedMeta(count=len(entries)), http_status=res.status_code, started=started)

    async def ensure_fresh(self) -> Optional[ProviderResult[FeedMeta]]:
        """Refresh if the local copy is missing or older than ``max_age``. ``None`` when it was already fresh."""
        age = await self._store.age_days(self.source)
        if age is not None and age <= self._max_age_days:
            return None
        async with self._lock():
            age = await self._store.age_days(self.source)
            if age is not None and age <= self._max_age_days:
                return None
            return await self.refresh()

    def kick(self) -> None:
        """Start a background refresh (at most one at a time). Used when a scan finds the feed missing or stale."""
        if self._use_mock or (self._background is not None and not self._background.done()):
            return
        self._background = asyncio.get_running_loop().create_task(self._safe_refresh(), name=f"{self.source}-refresh")

    async def _safe_refresh(self) -> None:
        try:
            result = await self.ensure_fresh()
            if result is not None and not result.ok:
                logger.warning("%s refresh failed (%s); keeping the previous copy", self.source, result.reason)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("%s refresh crashed", self.source)

    # ── lookup ─────────────────────────────────────────────────────────
    def candidates(self, s: Subject) -> list[tuple[str, str]]:
        """``(feed key, how it would match)`` from the strongest match to the weakest."""
        parts = split_url(s.url) if s.kind == "url" and s.url else None
        if parts:
            full, base, host = parts
            return [(f"u:{full}", "exact_url"), (f"p:{base}", "url_path"), (f"h:{host}", "host")]
        host = (s.host or "").lower()
        return [(f"p:{host}/", "exact_url"), (f"h:{host}", "host")]

    def verdict_for(self, s: Subject, rows: dict[str, Any], age: Optional[float], stale: bool) -> Optional[ReputationVerdict]:
        """The strongest match among ``rows``, or ``None`` if the feed does not list the target."""
        for key, label in self.candidates(s):
            if key not in rows:
                continue
            row = rows[key] if isinstance(rows[key], dict) else {}
            brand = row.get("target")
            brand = brand if brand and brand != "Other" else None
            what = {"exact_url": "this exact URL", "url_path": "this page (a different query string)",
                    "host": f"{row.get('n', 1)} other URL(s) on this host"}[label]
            return ReputationVerdict(
                source=self.source, listed=True, category=self.category, match=label,
                detail=f"listed by {self.display}: {what}" + (f" — targets {brand}" if brand else ""),
                reference=row.get("ref"), last_seen=row.get("t"), feed_age_days=age, stale=stale, extra={"brand": brand})
        return None

    async def lookup(self, s: Subject) -> ProviderResult[ReputationVerdict]:
        reason = _host_reason(s)
        if reason:
            return prov.skipped(self.source, reason)
        if self._use_mock:
            verdict = self.mock_verdict(s)
            if verdict is None:
                return prov.not_found(self.source, http_status=None).model_copy(update={"mock": True})
            return prov.ok(self.source, verdict.model_copy(update={"feed_age_days": 0.0}), http_status=None, mock=True)
        meta = await self._store.meta(self.source)
        if meta is None:
            self.kick()
            return prov.error(self.source, "feed_unavailable")            # never downloaded: UNKNOWN, not "not listed"
        age = await self._store.age_days(self.source)
        stale = age is not None and age > self._max_age_days
        if stale:
            self.kick()
        rows = await self._store.get_many(self.source, [k for k, _ in self.candidates(s)])
        verdict = self.verdict_for(s, rows, None if age is None else round(age, 3), stale)
        if verdict is None:
            return prov.not_found(self.source, http_status=None)
        return prov.ok(self.source, verdict, http_status=None, reason="stale_feed" if stale else None)


# ── OpenPhish ───────────────────────────────────────────────────────────────
class OpenPhishFeed(BulkFeed):
    source = "openphish"
    display = "OpenPhish"
    default_url = "https://openphish.com/feed.txt"
    max_bytes = 16 * 1024 * 1024

    def parse(self, body: bytes) -> dict[str, Any]:
        urls = [ln.strip() for ln in body.decode("utf-8", errors="replace").splitlines() if ln.strip()]
        if urls and not all("/" in u or "." in u for u in urls[:20]):
            raise ValueError("not a URL list")
        return _index(((u, {}) for u in urls))

    def mock_verdict(self, s: Subject) -> Optional[ReputationVerdict]:
        if not _is_bad_host(s):
            return None
        return ReputationVerdict(source=self.source, listed=True, category="phishing", match="host",
                                 detail="listed by OpenPhish: 1 other URL(s) on this host")


# ── PhishTank ───────────────────────────────────────────────────────────────
class PhishTankFeed(BulkFeed):
    source = "phishtank"
    display = "PhishTank"
    default_url = "https://data.phishtank.com/data/online-valid.json"
    max_bytes = 96 * 1024 * 1024

    def parse(self, body: bytes) -> dict[str, Any]:
        doc = json.loads(body.decode("utf-8", errors="replace"))
        if not isinstance(doc, list):
            raise ValueError("not a list")
        items = []
        for r in doc:
            if not isinstance(r, dict) or not r.get("url"):
                continue
            items.append((str(r["url"]), {"target": r.get("target"), "t": r.get("verification_time") or r.get("submission_time"),
                                          "ref": r.get("phish_detail_url")}))
        return _index(items)

    def mock_verdict(self, s: Subject) -> Optional[ReputationVerdict]:
        if not _is_bad_host(s):
            return None
        return ReputationVerdict(source=self.source, listed=True, category="phishing", match="host",
                                 detail="listed by PhishTank: 1 other URL(s) on this host — targets PayPal",
                                 extra={"brand": "PayPal"})


def _index(items) -> dict[str, Any]:
    """Feed URLs → ``u:`` / ``p:`` / ``h:`` entries (first record wins; ``h:`` carries a count)."""
    entries: dict[str, Any] = {}
    hosts: dict[str, int] = {}
    for raw, meta in items:
        parts = split_url(raw)
        if parts is None:
            continue
        full, base, host = parts
        meta = {k: v for k, v in meta.items() if v}
        entries.setdefault(f"u:{full}", meta)
        entries.setdefault(f"p:{base}", meta)
        hosts[host] = hosts.get(host, 0) + 1
        entries.setdefault(f"h:{host}", dict(meta))
    for host, n in hosts.items():
        entries[f"h:{host}"] = {**entries[f"h:{host}"], "n": n}
    return entries


# ── abuse.ch SSLBL: JA3 fingerprints of malware TLS clients ─────────────────
class Ja3BlacklistFeed(BulkFeed):
    """The SSLBL JA3 blacklist: ``ja3_md5,Firstseen,Lastseen,Listingreason`` (``#`` lines are comments).

    A JA3 hash identifies a *TLS client implementation*, not a host, so a listing means "this TLS stack has been seen in malware", and
    the same stack can belong to legitimate software: abuse.ch itself says these are not false-positive tested.  Callers cap the severity.
    "Not downloaded yet" is *unknown* (``feed_unavailable``), never "not listed".  No fingerprint is hard-coded anywhere in this project.
    """

    source = "sslbl_ja3"
    display = "abuse.ch SSLBL"
    default_url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
    category = "malware_tls_client"
    max_bytes = 8 * 1024 * 1024

    def parse(self, body: bytes) -> dict[str, Any]:
        entries: dict[str, Any] = {}
        for row in csv.reader(io.StringIO(body.decode("utf-8", errors="replace"))):
            if not row or row[0].lstrip().startswith("#"):
                continue
            ja3 = row[0].strip().lower()
            if len(ja3) != 32 or any(c not in "0123456789abcdef" for c in ja3):
                continue                                              # a header, a blank, or a line that is not a JA3 MD5
            meta = {"first": row[1].strip() if len(row) > 1 else "", "last": row[2].strip() if len(row) > 2 else "",
                    "reason": row[3].strip() if len(row) > 3 else ""}
            entries[ja3] = {k: v for k, v in meta.items() if v}
        return entries

    async def match(self, ja3: str) -> tuple[str, Optional[dict[str, Any]]]:
        """``("listed", row)`` · ``("not_listed", None)`` · ``("unavailable", None)`` (never downloaded: unknown) for a JA3 MD5."""
        if await self._store.meta(self.source) is None:
            self.kick()                                               # (a no-op in mock mode: mock never downloads)
            return "unavailable", None
        age = await self._store.age_days(self.source)
        if age is not None and age > self._max_age_days:
            self.kick()
        row = await self._store.get(self.source, (ja3 or "").lower())
        return ("listed", row if isinstance(row, dict) else {}) if row is not None else ("not_listed", None)


# ── Tranco ──────────────────────────────────────────────────────────────────
class TrancoFeed(BulkFeed):
    """Tranco popularity ranking: ``{domain: rank}`` for the top N. A prior, never a verdict."""

    source = "tranco"
    display = "Tranco"
    default_url = "https://tranco-list.eu/top-1m.csv.zip"
    max_bytes = 48 * 1024 * 1024
    category = "popular"

    def parse(self, body: bytes) -> dict[str, Any]:
        raw = body
        if body[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(body)) as z:
                raw = z.read(z.namelist()[0])
        ranks: dict[str, int] = {}
        for row in csv.reader(io.StringIO(raw.decode("utf-8", errors="replace"))):
            if len(row) < 2 or not row[0].strip().isdigit():
                continue
            rank = int(row[0])
            if rank > self._top_n:
                continue                                            # (the real file is sorted; do not rely on it)
            ranks[row[1].strip().lower()] = rank
        return ranks

    async def rank_of(self, domain: Optional[str]) -> tuple[Optional[int], Optional[float], bool]:
        """``(rank, feed age in days, stale)`` — rank ``None`` = outside the top N (or the feed is missing)."""
        if not domain:
            return None, None, False
        age = await self._store.age_days(self.source)
        rank = await self._store.get(self.source, domain.lower())
        return (int(rank) if rank is not None else None), age, bool(age is not None and age > self._max_age_days)

    async def lookup(self, s: Subject) -> ProviderResult[ReputationVerdict]:
        if s.kind not in ("url", "domain") or not (s.registered_domain or s.host):
            return prov.skipped(self.source, "not_applicable")
        reason = _host_reason(s)
        if reason:
            return prov.skipped(self.source, reason)
        domain = (s.registered_domain or s.host or "").lower()
        if self._use_mock:
            rank = {"google.com": 1, "microsoft.com": 4}.get(domain)
            if rank is None:
                return prov.not_found(self.source, http_status=None).model_copy(update={"mock": True})
            return prov.ok(self.source, self._verdict(domain, rank, 0.0, False), http_status=None, mock=True)
        if await self._store.meta(self.source) is None:
            self.kick()
            return prov.error(self.source, "feed_unavailable")
        rank, age, stale = await self.rank_of(domain)
        if stale:
            self.kick()
        if rank is None:
            return prov.not_found(self.source, http_status=None)
        return prov.ok(self.source, self._verdict(domain, rank, age, stale), http_status=None,
                       reason="stale_feed" if stale else None)

    def _verdict(self, domain: str, rank: int, age: Optional[float], stale: bool) -> ReputationVerdict:
        return ReputationVerdict(source=self.source, listed=False, category="popular", match="host",
                                 detail=f"{domain} is ranked #{rank:,} in the Tranco popularity list",
                                 feed_age_days=None if age is None else round(age, 3), stale=stale, extra={"rank": rank})
