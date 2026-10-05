"""
ThreatFusion – Technology Fingerprinting Client
================================================

Detects web technologies (frameworks, CMS, servers, analytics, CDNs, …) with the open-source Wappalyzer
fingerprint rules, through the ``python-Wappalyzer`` engine.

What A1-4 fixed
---------------
* **Data.**  The repo carried an unused 1.2 MB ``wappalyzer_tech.json`` ("3,965 technologies").  It was measured
  and **deleted**: it cannot be loaded as-is (absent fields are ``null``, which crashes the engine), and once
  repaired it detects *less* than the engine's own bundled data — most of its 3,965 names have no pattern this
  engine can use (1,186 technologies / 1,732 usable patterns vs the bundled 1,137 / 1,884), and it lacks the
  ``scripts`` version patterns for jQuery and AngularJS that end-of-life checks depend on.  The bundled data is used;
  ``WAPPALYZER_DATA_FILE`` can point at a newer file in the same format.
* **Warnings.**  Loading used to print a flood of "unbalanced parenthesis / Possible nested set" warnings, because the
  fingerprints are written for JavaScript regexes.  :func:`load_wappalyzer` translates the JS-only syntax
  (``[^]``, named groups, inline flags, nested sets), validates every pattern *before* handing it to the engine, and
  replaces the few that cannot be expressed in Python with a never-matching pattern — counted in :class:`LoadStats`,
  never silently.
* **Confidence.**  Every technology used to get ``confidence=100``.  It is now Wappalyzer's real confidence (the sum
  of the matching patterns' confidences, capped at 100); an *implied* technology (inferred from another) is flagged
  ``implied`` with confidence 50.
* **State leak.**  The engine stores detected versions/confidence *on the shared technology records*, so a version
  seen on site A showed up on site B.  :func:`analyze_page` resets that state under a lock for every page (and runs in
  a worker thread — analysis is CPU-heavy and used to block the event loop).
* **Laziness.**  The 4k-technology data is loaded on first use (or warmed at start-up), not at import time.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
import threading
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx

with warnings.catch_warnings():                       # python-Wappalyzer imports pkg_resources (setuptools deprecation)
    warnings.simplefilter("ignore")
    from Wappalyzer import Wappalyzer, WebPage

from app.core import providers as prov
from app.core.safe_http import FetchError, FetchPolicy, SafeFetcher, UnsafeTargetError
from app.models.schemas import DetectedTechnology, ProviderResult, TechFingerprintResult

logger = logging.getLogger(__name__)

SOURCE = "tech_fingerprint"
_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/120.0.0.0 Safari/537.36")
_LIB_DATA = Path(sys.modules[Wappalyzer.__module__.split(".")[0]].__file__).parent / "data" / "technologies.json"
_NEVER_MATCHES = "(?!x)x"
_IMPLIED_CONFIDENCE = 50
_PATTERN_FIELDS = ("url", "html", "scripts")          # string / list of strings
_MAPPED_FIELDS = ("headers", "meta")                   # {name: string}


# ── loading & sanitising the fingerprint data ───────────────────────────────
@dataclass(frozen=True)
class LoadStats:
    source: str
    technologies: int
    patterns: int
    fixed_patterns: int               # JS-only syntax translated to Python (e.g. ``[^]`` -> ``[\s\S]``)
    unusable_patterns: int            # JS-only syntax Python's ``re`` cannot express (replaced by a never-match)


def _escape_class_specials(expr: str) -> str:
    """Inside ``[...]`` escape ``[`` and doubled ``&&`` ``||`` ``~~`` ``--`` (JS treats them literally; Python's
    ``re`` warns about "possible nested set / set operation")."""
    out: list[str] = []
    in_class = False
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == "\\" and i + 1 < len(expr):
            out.append(expr[i:i + 2]); i += 2; continue
        if not in_class:
            if c == "[":
                in_class = True
                out.append(c)
                if expr[i + 1:i + 2] == "^":
                    out.append("^"); i += 1
                if expr[i + 1:i + 2] == "]":              # a leading ']' is a literal in POSIX but not in JS: keep as-is
                    pass
            else:
                out.append(c)
        else:
            if c == "]":
                in_class = False
                out.append(c)
            elif c == "[":
                out.append("\\[")
            elif c in "&|~-" and expr[i + 1:i + 2] == c:
                out.append("\\" + c)
            else:
                out.append(c)
        i += 1
    return "".join(out)


def _fix_js_regex(expr: str) -> str:
    expr = expr.replace("[^]", r"[\s\S]").replace("[]", "(?!x)x")
    expr = re.sub(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", r"(?P<\1>", expr)         # JS named groups
    expr = re.sub(r"\(\?[imsx]+\)", "", expr)                                    # inline flags are not JS
    expr = re.sub(r"\\u\{([0-9A-Fa-f]+)\}", lambda m: chr(int(m.group(1), 16)), expr)
    return _escape_class_specials(expr)


def _compiles(expr: str) -> bool:
    with warnings.catch_warnings():
        warnings.simplefilter("error")                  # a FutureWarning counts as "not clean"
        try:
            re.compile(expr, re.IGNORECASE)
            return True
        except (re.error, Warning, RecursionError, OverflowError):
            return False


def _sanitise_pattern(raw: str, counter: list[int]) -> str:
    """``regex\\;attr:value\\;…`` → the same with a Python-valid regex (or a never-match)."""
    counter[0] += 1
    regex, sep, attrs = raw.partition("\\;")
    if not _compiles(regex):
        fixed = _fix_js_regex(regex)
        if _compiles(fixed):
            counter[2] += 1
            regex = fixed
        else:
            counter[1] += 1
            regex = _NEVER_MATCHES
    return regex + sep + attrs


def build_wappalyzer(technologies: dict[str, dict[str, Any]], categories: dict[str, Any],
                     source: str = "memory") -> tuple[Wappalyzer, LoadStats]:
    """Sanitise every pattern, then construct the engine (which then has nothing to warn about)."""
    counter = [0, 0, 0]                                 # patterns seen, unusable, fixed
    for tech in technologies.values():
        # The repo's file writes absent fields as ``null`` (the engine only copes with a missing key) — that alone is
        # why it could never be loaded. Drop the nulls.
        for key in [k for k, v in tech.items() if v is None]:
            del tech[key]
        for key in _PATTERN_FIELDS:
            value = tech.get(key)
            if isinstance(value, str):
                tech[key] = _sanitise_pattern(value, counter)
            elif isinstance(value, list):
                tech[key] = [_sanitise_pattern(v, counter) for v in value if isinstance(v, str)]
        for key in _MAPPED_FIELDS:
            value = tech.get(key)
            if isinstance(value, dict):
                # The engine takes ONE pattern per header/meta name; newer data files may give a list (keep the first).
                tech[key] = {k: _sanitise_pattern(v if isinstance(v, str) else v[0], counter)
                             for k, v in value.items()
                             if isinstance(v, str) or (isinstance(v, list) and v and isinstance(v[0], str))}
            elif value is not None:
                tech.pop(key, None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        wapp = Wappalyzer(categories=categories, technologies=technologies)
    return wapp, LoadStats(source=source, technologies=len(technologies), patterns=counter[0],
                           fixed_patterns=counter[2], unusable_patterns=counter[1])


def load_wappalyzer(path: Optional[Path] = None) -> tuple[Wappalyzer, LoadStats]:
    """Load the fingerprint data (``path``/``WAPPALYZER_DATA_FILE`` first, else the engine's bundled data) without
    emitting warnings."""
    if path is None:
        from app.core.config import get_settings
        path = get_settings().WAPPALYZER_DATA_FILE or None
    candidates = ([Path(path)] if path else []) + [_LIB_DATA]
    last: Optional[Exception] = None
    for candidate in candidates:
        try:
            doc = json.loads(candidate.read_text(encoding="utf-8"))
            wapp, stats = build_wappalyzer(doc["technologies"], doc["categories"], source=str(candidate))
            logger.info("Wappalyzer data loaded from %s: %d technologies, %d patterns (%d JS patterns translated, "
                        "%d unusable)", candidate.name, stats.technologies, stats.patterns, stats.fixed_patterns,
                        stats.unusable_patterns)
            return wapp, stats
        except Exception as exc:                        # missing/corrupt file: try the next source
            last = exc
            logger.warning("Could not load Wappalyzer data from %s: %s", candidate, exc)
    raise RuntimeError(f"no usable Wappalyzer data: {last}")


_LOAD_LOCK = threading.Lock()
_LOADED: Optional[tuple[Wappalyzer, LoadStats]] = None
_ANALYZE_LOCK = threading.Lock()


def get_wappalyzer() -> Optional[Wappalyzer]:
    """The process-wide engine, loaded on first use (thread-safe). ``None`` if no data could be loaded."""
    global _LOADED
    with _LOAD_LOCK:
        if _LOADED is None:
            try:
                _LOADED = load_wappalyzer()
            except Exception:
                logger.exception("Failed to load Wappalyzer")
                return None
        return _LOADED[0]


def warm_up() -> None:
    """Load the fingerprint data now (called off the event loop at start-up)."""
    get_wappalyzer()


# ── analysis ────────────────────────────────────────────────────────────────
_STATE_KEYS = ("detected", "confidence", "confidenceTotal", "versions")


def analyze_page(wapp: Wappalyzer, url: str, html: str, headers: dict[str, str]) -> list[DetectedTechnology]:
    """Fingerprint one page. Synchronous and CPU-heavy: call it from a worker thread.

    The engine records its findings *on the shared technology dicts*; they are cleared first, under a lock, so one
    page can never inherit another's versions or confidence (and concurrent analyses cannot interleave).
    """
    lowered = {str(k).lower(): v for k, v in headers.items()}
    with _ANALYZE_LOCK:
        for tech in wapp.technologies.values():
            for key in _STATE_KEYS:
                tech.pop(key, None)
        page = WebPage(url=url, html=html, headers=lowered)
        detected = wapp.analyze(page)                    # direct detections plus implied technologies
        out: list[DetectedTechnology] = []
        for name in sorted(detected):
            record = wapp.technologies.get(name, {})
            total = record.get("confidenceTotal")
            implied = total is None                      # never matched a pattern itself: inferred from another tech
            versions = wapp.get_versions(name) if name in wapp.technologies else []
            out.append(DetectedTechnology(
                name=name,
                version=versions[0] if versions else None,
                categories=[c for c in wapp.get_categories(name) if c],
                confidence=_IMPLIED_CONFIDENCE if implied else max(0, min(100, int(total))),
                implied=implied,
            ))
        return out


class TechFingerprintClient:
    """Async technology fingerprinting client using Wappalyzer data."""

    def __init__(self, use_mock: bool = True) -> None:
        self._use_mock: bool = use_mock
        self._fetcher: Optional[SafeFetcher] = None
        logger.info(
            "TechFingerprintClient initialised (mock_mode=%s)", self._use_mock
        )

    def _get_fetcher(self) -> SafeFetcher:
        """The target is user-supplied, so it is only ever fetched through the SSRF-safe fetcher
        (validated + pinned IP, per-hop redirect checks, size/time caps) — never a raw client."""
        if self._fetcher is None:
            self._fetcher = SafeFetcher(FetchPolicy.from_settings(
                max_bytes=2 * 1024 * 1024, total_timeout=15.0, request_timeout=10.0))
        return self._fetcher

    async def close(self) -> None:
        """Nothing to release: the fetcher opens (and closes) a client per request."""
        self._fetcher = None

    def _generate_mock(self, url: str) -> TechFingerprintResult:
        import hashlib
        import random
        
        url_lower = url.lower()
        techs = []
        
        # Seed based on URL to generate unique but deterministic technologies
        seed_val = int(hashlib.md5(url.encode('utf-8')).hexdigest(), 16)
        rng = random.Random(seed_val)
        
        if "wordpress" in url_lower:
            techs.extend([
                DetectedTechnology(name="WordPress", version="6.1", categories=["CMS"], confidence=100),
                DetectedTechnology(name="PHP", categories=["Programming languages"], confidence=100),
                DetectedTechnology(name="Apache", categories=["Web servers"], confidence=100)
            ])
        elif "react" in url_lower or "vercel" in url_lower:
            techs.extend([
                DetectedTechnology(name="React", categories=["JavaScript frameworks"], confidence=100),
                DetectedTechnology(name="Next.js", categories=["Web frameworks"], confidence=100),
                DetectedTechnology(name="Vercel", categories=["PaaS"], confidence=100)
            ])
        else:
            # Generate deterministic mix of popular technologies
            web_servers = [("Nginx", "1.21.0"), ("Apache", "2.4.41"), ("LiteSpeed", None)]
            js_libs = [("jQuery", "3.6.0"), ("Lodash", "4.17.21"), ("React", "18.2.0")]
            analytics = [("Google Analytics", None), ("Mixpanel", None), ("Hotjar", None)]
            cms = [("Drupal", "9.2"), ("Joomla", "4.0"), ("Shopify", None), (None, None)]
            
            server_name, server_ver = rng.choice(web_servers)
            js_name, js_ver = rng.choice(js_libs)
            anal_name = rng.choice(analytics)[0]
            cms_name, cms_ver = rng.choice(cms)
            
            if server_name:
                techs.append(DetectedTechnology(name=server_name, version=server_ver, categories=["Web servers"], confidence=100))
            if js_name:
                techs.append(DetectedTechnology(name=js_name, version=js_ver, categories=["JavaScript libraries"], confidence=100))
            if anal_name:
                techs.append(DetectedTechnology(name=anal_name, categories=["Analytics"], confidence=95))
            if cms_name:
                techs.append(DetectedTechnology(name=cms_name, version=cms_ver, categories=["CMS"], confidence=100))
                
        return TechFingerprintResult(
            technologies=techs,
            headers_analyzed=rng.randint(8, 20),
            scripts_analyzed=rng.randint(3, 12)
        )

    async def fingerprint_url(self, url: str) -> ProviderResult[TechFingerprintResult]:
        """Detect web technologies used by the page at ``url``.

        Returns a ``ProviderResult`` (A0-1).  "Nothing detected" on a page we *did* fetch is a
        genuine ``ok`` answer; but a 5xx, a timeout, a Cloudflare/bot challenge page or a missing
        Wappalyzer are ``error`` — they used to come back as an empty result and were counted as
        a successful fingerprint.
        """
        if self._use_mock:
            return prov.ok(SOURCE, self._generate_mock(url), http_status=None, mock=True)

        started = prov.start_timer()
        # Load (first use) / look up the engine in a worker thread: 4k technologies, regex-heavy, must not block the loop.
        wapp = await asyncio.to_thread(get_wappalyzer)
        if wapp is None:
            return prov.error(SOURCE, "wappalyzer_unavailable", started=started)
        try:
            fetched = await self._get_fetcher().fetch(url, headers={"User-Agent": _USER_AGENT})
        except (UnsafeTargetError, FetchError) as e:
            logger.warning("Tech fingerprinting refused/failed for %s: %s", url, e)
            return prov.from_exception(SOURCE, e, started=started)

        if fetched.status_code >= 500:
            return prov.error(SOURCE, "server_error", http_status=fetched.status_code, started=started)

        html = fetched.text

        # Check for bot-block / challenge pages
        is_short = len(html) < 20000
        lower_html = html.lower()
        is_challenge = is_short and any(marker in lower_html for marker in ["just a moment", "attention required", "cloudflare"])
        if is_challenge:
            logger.warning("Response from %s appears to be a Cloudflare/bot challenge page. Skipping tech fingerprinting.", url)
            return prov.error(SOURCE, "bot_challenge", http_status=fetched.status_code, started=started)

        try:
            headers = {k: v for k, v in fetched.headers.items()}
            detected = await asyncio.to_thread(analyze_page, wapp, url, html, headers)
            scripts_count = len(re.findall(r'<script', html, re.IGNORECASE))
        except Exception as e:  # Wappalyzer rule/regex failures must not look like "no tech"
            logger.warning("Tech fingerprint analysis failed for %s: %s", url, e)
            return prov.error(SOURCE, "analysis_failed", http_status=fetched.status_code, started=started)

        return prov.ok(SOURCE, TechFingerprintResult(
            technologies=detected,
            headers_analyzed=len(headers),
            scripts_analyzed=scripts_count,
        ), http_status=fetched.status_code, started=started)
