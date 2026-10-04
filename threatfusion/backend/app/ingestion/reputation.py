"""
ThreatFusion – independent reputation channels (B2)
===================================================

VirusTotal's free quota is small and the first model collapsed onto it.  These channels answer the same question — *is this
target known to be bad?* — from sources that do not depend on VirusTotal, so fusion (B7) has several independent opinions and
the verdict does not vanish when one provider is down.  Each channel is one small subclass of :class:`Channel`:

========== ============================================ ====================== =========================================
source     what it knows                                 asked about            key
========== ============================================ ====================== =========================================
urlhaus    malware-distribution URLs / hosts (abuse.ch)  URL, host or IP        ``ABUSECH_AUTH_KEY`` (required)
threatfox  malware IOCs: C2 hosts, IPs, hashes (abuse.ch) host, IP or hash       ``ABUSECH_AUTH_KEY`` (required)
safebrowsing Google Safe Browsing (phishing / malware)    the public URL         ``GOOGLE_SAFE_BROWSING_API_KEY``
abuseipdb  community abuse reports for an IP             IP                     ``ABUSEIPDB_API_KEY``
urlscan    prior public scans + verdicts (search only)    host                   optional ``URLSCAN_API_KEY``
otx        AlienVault threat-intel pulses                 host, IP or hash       ``OTX_API_KEY``
greynoise  mass-scanner noise vs targeted (Community)    IP                     optional ``GREYNOISE_API_KEY``
========== ============================================ ====================== =========================================

(OpenPhish, PhishTank and Tranco are *local bulk feeds*: see ``blocklists.py``.)

Rules every channel follows
---------------------------
* **Three-state (A0-1)**: ``ok`` (a record; ``ReputationVerdict.listed`` says whether it is a *bad* one) · ``not_found``
  (answered, no record — absence of evidence, never "safe") · ``error`` (timeout / rate limit / auth / unparseable; never
  cached, never a feature) · ``skipped`` (not applicable to this target) · ``not_configured`` (key missing).
* **Privacy (A0-10)**: only the host name, the resolved *public* IP, a hash or the already-trimmed public URL leave the
  machine; private and local names/IPs are refused before any request.  urlscan is **search only** — nothing is ever submitted.
  API keys travel in headers, never in a URL (URLs end up in logs).
* **Shared infrastructure (A1-1)**: a per-channel rate limiter that honours ``Retry-After``, the SQLite provider cache
  (answers keyed by a hash of the query), no live calls in tests.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote

import httpx

from app.core import privacy
from app.core import providers as prov
from app.core.cache import ProviderCache
from app.core.quota import QuotaLimiter
from app.core.safe_http import blocked_reason, parse_host_ip
from app.models.schemas import ProviderResult, ReputationVerdict

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Subject:
    """What a channel is asked about — already reduced to what may leave the machine."""

    kind: str                                  # url | domain | ip | hash
    host: Optional[str] = None                 # canonical host (domain/url targets; the IP literal for ip targets)
    ip: Optional[str] = None                   # a public IP to ask IP channels about (the target itself or a resolved one)
    url: Optional[str] = None                  # privacy-trimmed URL (scheme://host/path) unless the user opted in
    registered_domain: Optional[str] = None
    hash: Optional[str] = None


class _Reject(Exception):
    """The upstream understood the request but refused it: report ``error`` with this reason."""


@dataclass
class Request:
    method: str
    url: str
    params: Optional[dict] = None
    json: Optional[dict] = None
    data: Optional[dict] = None
    headers: Optional[dict] = None


def _short(text: Any, n: int = 160) -> Optional[str]:
    if text is None:
        return None
    s = str(text).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


class Channel:
    """One independent reputation source. Subclasses supply ``applies`` / ``query`` / ``request`` / ``parse`` / ``mock``."""

    source = ""
    needs_key = True
    base_url = ""

    def __init__(
        self,
        use_mock: bool = True,
        *,
        api_key: str = "",
        base_url: Optional[str] = None,
        cache: Optional[ProviderCache] = None,
        limiter: Optional[QuotaLimiter] = None,
        cache_ttl: float = 6 * 3600.0,
        not_found_ttl: float = 900.0,
        max_queue_seconds: float = 10.0,
        timeout: float = 15.0,
        **options: Any,
    ) -> None:
        self._use_mock = use_mock
        self._key = api_key
        if base_url:
            self.base_url = base_url
        self._cache = cache if cache is not None else ProviderCache()
        self._limiter = limiter if limiter is not None else QuotaLimiter(0, 0)
        self._ttl = cache_ttl
        self._not_found_ttl = not_found_ttl
        self._max_queue = max_queue_seconds
        self._timeout = timeout
        self.options = options
        self._client: Optional[httpx.AsyncClient] = None
        self._client_loop: Optional[asyncio.AbstractEventLoop] = None

    # ── hooks ──────────────────────────────────────────────────────────
    def applies(self, s: Subject) -> Optional[str]:
        """``None`` if the channel can answer for this subject, else the reason to skip."""
        raise NotImplementedError

    def query(self, s: Subject) -> str:
        """The exact thing asked (also the cache key material)."""
        raise NotImplementedError

    def request(self, s: Subject) -> Request:
        raise NotImplementedError

    def parse(self, s: Subject, response: httpx.Response) -> Optional[ReputationVerdict]:
        """``None`` = the source has no record. Raise ``ValueError`` for an unparseable body, ``_Reject`` for a refusal."""
        raise NotImplementedError

    def mock(self, s: Subject) -> Optional[ReputationVerdict]:
        raise NotImplementedError

    # ── plumbing ───────────────────────────────────────────────────────
    async def _get_client(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._client_loop is not loop:
            self._client = httpx.AsyncClient(timeout=self._timeout, headers={"Accept": "application/json"})
            self._client_loop = loop
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except RuntimeError:
                pass
            self._client = None
            self._client_loop = None

    def _cache_key(self, s: Subject) -> str:
        return hashlib.sha256(f"{self.source}|{self.query(s)}".encode()).hexdigest()[:40]

    async def lookup(self, s: Subject) -> ProviderResult[ReputationVerdict]:
        reason = self.applies(s)
        if reason:
            return prov.skipped(self.source, reason)
        if self._use_mock:
            verdict = self.mock(s)
            if verdict is None:
                return prov.not_found(self.source, http_status=None).model_copy(update={"mock": True})
            return prov.ok(self.source, verdict, http_status=None, mock=True)
        if self.needs_key and not self._key:
            return prov.not_configured(self.source)

        key = self._cache_key(s)
        try:
            cached = await self._cache.get(self.source, key, ReputationVerdict)
        except Exception:
            logger.exception("provider cache read failed; continuing without it")
            cached = None
        if cached is not None:
            return cached

        wait = await self._limiter.acquire(max_wait=self._max_queue)
        if wait is not None:
            return prov.error(self.source, "rate_limited", retry_after=wait)
        started = prov.start_timer()
        req = self.request(s)
        client = await self._get_client()
        try:
            response = await client.request(req.method, req.url, params=req.params, json=req.json, data=req.data,
                                            headers=req.headers)
        except Exception as exc:
            logger.warning("%s request failed: %s", self.source, type(exc).__name__)
            return prov.from_exception(self.source, exc, started=started)
        failure = prov.from_http_status(self.source, response.status_code, started=started)
        if failure is not None:
            if response.status_code == 429:
                seconds = prov.parse_retry_after(response.headers.get("retry-after"))
                self._limiter.penalize(seconds)
                return failure.model_copy(update={"retry_after": round(seconds, 1)})
            if response.status_code != 404:
                return failure                                          # never cached
            result: ProviderResult = failure                           # 404: the source answered "no such record"
        else:
            try:
                verdict = self.parse(s, response)
            except _Reject as rej:
                return prov.error(self.source, str(rej), http_status=response.status_code, started=started)
            except (ValueError, KeyError, TypeError, AttributeError):
                return prov.error(self.source, "parse_error", http_status=response.status_code, started=started)
            result = (prov.not_found(self.source, http_status=response.status_code, started=started) if verdict is None
                      else prov.ok(self.source, verdict, http_status=response.status_code, started=started))
        try:
            await self._cache.put(self.source, key, result, ttl_ok=self._ttl, ttl_not_found=self._not_found_ttl)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")
        return result


# ── shared applicability checks ─────────────────────────────────────────────
def _host_reason(s: Subject) -> Optional[str]:
    if s.kind not in ("url", "domain", "ip") or not s.host:
        return "not_applicable"
    return privacy.provider_block_reason(s.host)


def _ip_reason(s: Subject) -> Optional[str]:
    if not s.ip:
        return "no_resolved_ip" if s.kind == "domain" or s.kind == "url" else "not_applicable"
    ip = parse_host_ip(s.ip)
    if ip is None or blocked_reason(ip) is not None:
        return "private_address"
    return None


def _is_bad_host(s: Subject) -> bool:
    h = (s.host or "").lower()
    return any(w in h for w in ("evil", "malicious", "phish"))


# ── URLhaus ─────────────────────────────────────────────────────────────────
class UrlhausChannel(Channel):
    """abuse.ch URLhaus: is this URL (or host) known to distribute malware?  Needs the free abuse.ch Auth-Key."""

    source = "urlhaus"
    base_url = "https://urlhaus-api.abuse.ch/v1/"

    def applies(self, s: Subject) -> Optional[str]:
        return _host_reason(s)

    def _by_url(self, s: Subject) -> bool:
        return s.kind == "url" and bool(s.url)

    def query(self, s: Subject) -> str:
        return f"url:{s.url}" if self._by_url(s) else f"host:{s.host}"

    def request(self, s: Subject) -> Request:
        headers = {"Auth-Key": self._key}
        if self._by_url(s):
            return Request("POST", self.base_url + "url/", data={"url": s.url}, headers=headers)
        return Request("POST", self.base_url + "host/", data={"host": s.host}, headers=headers)

    def parse(self, s: Subject, response: httpx.Response) -> Optional[ReputationVerdict]:
        doc = response.json()
        status = doc["query_status"]
        if status == "no_results":
            return None
        if status in ("invalid_url", "invalid_host"):
            raise _Reject("bad_request")
        if status != "ok":
            raise ValueError(status)
        if self._by_url(s):
            online = str(doc.get("url_status", "")).lower() == "online"
            tags = ", ".join(doc.get("tags") or [])
            return ReputationVerdict(
                source=self.source, listed=True, category="malware", match="exact_url",
                detail=_short(f"{doc.get('threat', 'malware')} — {'online' if online else 'offline'}" + (f" — {tags}" if tags else "")),
                reference=doc.get("urlhaus_reference"), last_seen=doc.get("date_added"), extra={"online": online})
        urls = doc.get("urls") or []
        count = int(doc.get("url_count") or len(urls))
        if count <= 0:
            return None
        online_n = sum(1 for u in urls if str(u.get("url_status", "")).lower() == "online")
        return ReputationVerdict(
            source=self.source, listed=True, category="malware", match="host",
            detail=f"{count} malware URL{'s' if count != 1 else ''} recorded on this host ({online_n} online)",
            reference=doc.get("urlhaus_reference"), last_seen=doc.get("firstseen"), extra={"urls": count, "online": online_n})

    def mock(self, s: Subject) -> Optional[ReputationVerdict]:
        if not _is_bad_host(s):
            return None
        return ReputationVerdict(source=self.source, listed=True, category="malware", match="host",
                                 detail="2 malware URLs recorded on this host (1 online)",
                                 reference="https://urlhaus.abuse.ch/host/mock/", extra={"urls": 2, "online": 1})


# ── ThreatFox ───────────────────────────────────────────────────────────────
class ThreatFoxChannel(Channel):
    """abuse.ch ThreatFox: is this host / IP / hash a known malware indicator of compromise?  Needs the Auth-Key."""

    source = "threatfox"
    base_url = "https://threatfox-api.abuse.ch/api/v1/"
    _CATEGORY = {"botnet_cc": "botnet_c2", "payload_delivery": "malware", "payload": "malware"}

    def applies(self, s: Subject) -> Optional[str]:
        if s.kind == "hash" and s.hash:
            return None
        if s.kind == "ip":
            return _ip_reason(s) if s.ip else "not_applicable"
        return _host_reason(s)

    def _term(self, s: Subject) -> str:
        return (s.hash if s.kind == "hash" else s.ip if s.kind == "ip" else s.host) or ""

    def query(self, s: Subject) -> str:
        return self._term(s)

    def request(self, s: Subject) -> Request:
        return Request("POST", self.base_url, json={"query": "search_ioc", "search_term": self._term(s)},
                       headers={"Auth-Key": self._key})

    def parse(self, s: Subject, response: httpx.Response) -> Optional[ReputationVerdict]:
        doc = response.json()
        status = doc["query_status"]
        if status == "no_result":
            return None
        if status in ("illegal_search_term", "illegal_ioc"):
            raise _Reject("bad_request")
        if status != "ok":
            raise ValueError(status)
        rows = [r for r in doc["data"] if isinstance(r, dict)]
        if not rows:
            return None
        first = rows[0]
        threat = str(first.get("threat_type", ""))
        return ReputationVerdict(
            source=self.source, listed=True, category=self._CATEGORY.get(threat, "malware"), match="ioc",
            detail=_short(f"{first.get('malware_printable') or first.get('malware') or 'malware'} ({threat or 'ioc'}), "
                          f"confidence {first.get('confidence_level', '?')}%"),
            reference=f"https://threatfox.abuse.ch/ioc/{first['id']}/" if first.get("id") else None,
            last_seen=first.get("last_seen") or first.get("first_seen"), extra={"iocs": len(rows)})

    def mock(self, s: Subject) -> Optional[ReputationVerdict]:
        if s.kind == "hash" or not _is_bad_host(s):
            return None
        return ReputationVerdict(source=self.source, listed=True, category="botnet_c2", match="ioc",
                                 detail="Mock Loader (botnet_cc), confidence 75%", reference="https://threatfox.abuse.ch/ioc/0/",
                                 extra={"iocs": 1})


# ── Google Safe Browsing ────────────────────────────────────────────────────
class SafeBrowsingChannel(Channel):
    """Google Safe Browsing Lookup API v4 (non-commercial use; commercial use needs Web Risk). Key goes in a header."""

    source = "safebrowsing"
    base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    _TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
    _CATEGORY = {"SOCIAL_ENGINEERING": "social_engineering", "MALWARE": "malware",
                 "UNWANTED_SOFTWARE": "malware", "POTENTIALLY_HARMFUL_APPLICATION": "malware"}

    def applies(self, s: Subject) -> Optional[str]:
        return _host_reason(s)

    def _url(self, s: Subject) -> str:
        return s.url if s.kind == "url" and s.url else f"http://{s.host}/"

    def query(self, s: Subject) -> str:
        return self._url(s)

    def request(self, s: Subject) -> Request:
        body = {"client": {"clientId": "threatfusion", "clientVersion": str(self.options.get("client_version", "1"))},
                "threatInfo": {"threatTypes": self._TYPES, "platformTypes": ["ANY_PLATFORM"],
                               "threatEntryTypes": ["URL"], "threatEntries": [{"url": self._url(s)}]}}
        return Request("POST", self.base_url, json=body, headers={"X-Goog-Api-Key": self._key})

    def parse(self, s: Subject, response: httpx.Response) -> Optional[ReputationVerdict]:
        doc = response.json()
        if not isinstance(doc, dict):
            raise ValueError("not an object")
        matches = doc.get("matches") or []
        if not matches:
            return None                                              # an empty object = no match
        types = sorted({str(m.get("threatType", "")) for m in matches})
        category = "social_engineering" if "SOCIAL_ENGINEERING" in types else self._CATEGORY.get(types[0], "malware")
        return ReputationVerdict(source=self.source, listed=True, category=category, match="exact_url",
                                 detail=_short("Google Safe Browsing: " + ", ".join(t.replace("_", " ").lower() for t in types)),
                                 extra={"threat_types": ",".join(types)})

    def mock(self, s: Subject) -> Optional[ReputationVerdict]:
        if not _is_bad_host(s):
            return None
        return ReputationVerdict(source=self.source, listed=True, category="social_engineering", match="exact_url",
                                 detail="Google Safe Browsing: social engineering", extra={"threat_types": "SOCIAL_ENGINEERING"})


# ── AbuseIPDB ───────────────────────────────────────────────────────────────
class AbuseIpdbChannel(Channel):
    """AbuseIPDB: the community's abuse-confidence score for an IP address (last 90 days)."""

    source = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2/check"

    def applies(self, s: Subject) -> Optional[str]:
        return _ip_reason(s)

    def query(self, s: Subject) -> str:
        return s.ip or ""

    def request(self, s: Subject) -> Request:
        return Request("GET", self.base_url, params={"ipAddress": s.ip, "maxAgeInDays": 90},
                       headers={"Key": self._key})

    def parse(self, s: Subject, response: httpx.Response) -> Optional[ReputationVerdict]:
        data = response.json()["data"]
        reports = int(data.get("totalReports") or 0)
        if reports == 0:
            return None                                              # no reports: no record, not "score 0"
        score = float(data["abuseConfidenceScore"])
        threshold = float(self.options.get("min_confidence", 50))
        return ReputationVerdict(
            source=self.source, listed=score >= threshold, category="abuse", match="ip", score=score,
            detail=_short(f"{reports} abuse report{'s' if reports != 1 else ''} in 90 days, confidence {score:.0f}%"
                          + (f" · {data['isp']}" if data.get("isp") else "")),
            reference=f"https://www.abuseipdb.com/check/{quote(s.ip or '')}", last_seen=data.get("lastReportedAt"),
            extra={"reports": reports, "country": data.get("countryCode"), "usage": data.get("usageType")})

    def mock(self, s: Subject) -> Optional[ReputationVerdict]:
        if not _is_bad_host(s):
            return None
        return ReputationVerdict(source=self.source, listed=True, category="abuse", match="ip", score=87.0,
                                 detail="42 abuse reports in 90 days, confidence 87%", extra={"reports": 42})


# ── urlscan.io (search only) ────────────────────────────────────────────────
class UrlscanChannel(Channel):
    """urlscan.io **search**: prior public scans of this host and their verdicts. Nothing is ever submitted."""

    source = "urlscan"
    needs_key = False
    base_url = "https://urlscan.io/api/v1/search/"

    def applies(self, s: Subject) -> Optional[str]:
        return _host_reason(s)

    def query(self, s: Subject) -> str:
        return f"{'ip' if s.kind == 'ip' else 'domain'}:{s.host}"

    def request(self, s: Subject) -> Request:
        headers = {"API-Key": self._key} if self._key else None
        return Request("GET", self.base_url, params={"q": self.query(s), "size": 20}, headers=headers)

    def parse(self, s: Subject, response: httpx.Response) -> Optional[ReputationVerdict]:
        results = [r for r in (response.json().get("results") or []) if isinstance(r, dict)]
        if not results:
            return None
        bad = [r for r in results if ((r.get("verdicts") or {}).get("overall") or {}).get("malicious") is True]
        pick = (bad or results)[0]
        rid = pick.get("_id")
        times = sorted(str((r.get("task") or {}).get("time", "")) for r in results)
        return ReputationVerdict(
            source=self.source, listed=bool(bad), category="phishing" if bad else None, match="host",
            detail=f"{len(results)} prior public scan{'s' if len(results) != 1 else ''}, {len(bad)} judged malicious",
            reference=f"https://urlscan.io/result/{rid}/" if rid else None, last_seen=times[-1] or None,
            extra={"scans": len(results), "malicious_scans": len(bad),
                   "screenshot": pick.get("screenshot") or (f"https://urlscan.io/screenshots/{rid}.png" if rid else None)})

    def mock(self, s: Subject) -> Optional[ReputationVerdict]:
        if not _is_bad_host(s):
            return None
        return ReputationVerdict(source=self.source, listed=True, category="phishing", match="host",
                                 detail="3 prior public scans, 2 judged malicious", reference="https://urlscan.io/result/mock/",
                                 extra={"scans": 3, "malicious_scans": 2})


# ── AlienVault OTX ──────────────────────────────────────────────────────────
class OtxChannel(Channel):
    """AlienVault OTX: is the indicator mentioned in community threat-intel pulses?  (A mention is context, not proof.)"""

    source = "otx"
    base_url = "https://otx.alienvault.com/api/v1/indicators"

    def applies(self, s: Subject) -> Optional[str]:
        if s.kind == "hash" and s.hash:
            return None
        if s.kind == "ip":
            return _ip_reason(s) if s.ip else "not_applicable"
        return _host_reason(s)

    def _indicator(self, s: Subject) -> tuple[str, str]:
        if s.kind == "hash":
            return "file", s.hash or ""
        if s.kind == "ip":
            return ("IPv6" if ":" in (s.ip or "") else "IPv4"), s.ip or ""
        return ("domain" if s.host == s.registered_domain else "hostname"), s.host or ""

    def query(self, s: Subject) -> str:
        kind, value = self._indicator(s)
        return f"{kind}/{value}"

    def request(self, s: Subject) -> Request:
        kind, value = self._indicator(s)
        return Request("GET", f"{self.base_url}/{kind}/{quote(value, safe='')}/general", headers={"X-OTX-API-KEY": self._key})

    def parse(self, s: Subject, response: httpx.Response) -> Optional[ReputationVerdict]:
        doc = response.json()
        info = doc.get("pulse_info") or {}
        count = int(info.get("count") or 0)
        if count <= 0:
            return None
        names = [str(p.get("name")) for p in (info.get("pulses") or [])[:2] if isinstance(p, dict) and p.get("name")]
        kind, value = self._indicator(s)
        return ReputationVerdict(
            source=self.source, listed=count >= int(self.options.get("min_pulses", 1)), category="threat_intel",
            match="ioc" if kind == "file" else ("ip" if kind.startswith("IP") else "host"),
            detail=_short(f"mentioned in {count} threat-intel pulse{'s' if count != 1 else ''}"
                          + (f", e.g. {'; '.join(names)}" if names else "")),
            reference=f"https://otx.alienvault.com/indicator/{kind}/{quote(value, safe='')}", extra={"pulses": count})

    def mock(self, s: Subject) -> Optional[ReputationVerdict]:
        if s.kind == "hash" or not _is_bad_host(s):
            return None
        return ReputationVerdict(source=self.source, listed=True, category="threat_intel", match="host",
                                 detail="mentioned in 2 threat-intel pulses, e.g. Mock Phishing Wave", extra={"pulses": 2})


# ── GreyNoise Community ─────────────────────────────────────────────────────
class GreyNoiseChannel(Channel):
    """GreyNoise Community: is this IP just a mass internet scanner (noise), a known-benign service, or targeted?"""

    source = "greynoise"
    needs_key = False
    base_url = "https://api.greynoise.io/v3/community/"

    def applies(self, s: Subject) -> Optional[str]:
        return _ip_reason(s)

    def query(self, s: Subject) -> str:
        return s.ip or ""

    def request(self, s: Subject) -> Request:
        headers = {"key": self._key} if self._key else None
        return Request("GET", self.base_url + quote(s.ip or "", safe=""), headers=headers)

    def parse(self, s: Subject, response: httpx.Response) -> Optional[ReputationVerdict]:
        doc = response.json()
        noise, riot = bool(doc.get("noise")), bool(doc.get("riot"))
        if not noise and not riot:
            return None
        cls = str(doc.get("classification") or "unknown").lower()
        name = doc.get("name")
        if riot or cls == "benign":
            category, detail = "benign", "a known benign service" + (f" ({name})" if name else "")
        elif cls == "malicious":
            category, detail = "scanner", "observed scanning the internet and classified malicious"
        else:
            category, detail = "scanner", "observed scanning the internet (mass-scanner noise, not targeted)"
        return ReputationVerdict(source=self.source, listed=cls == "malicious", category=category, match="ip", detail=_short(detail),
                                 reference=doc.get("link"), last_seen=doc.get("last_seen"),
                                 extra={"noise": noise, "riot": riot, "classification": cls})

    def mock(self, s: Subject) -> Optional[ReputationVerdict]:
        return None


CHANNEL_CLASSES: dict[str, type[Channel]] = {
    c.source: c for c in (UrlhausChannel, ThreatFoxChannel, SafeBrowsingChannel, AbuseIpdbChannel, UrlscanChannel, OtxChannel,
                          GreyNoiseChannel)
}

PlannedCall = Callable[[], Awaitable[ProviderResult]]
