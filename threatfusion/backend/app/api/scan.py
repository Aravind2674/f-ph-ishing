"""
ThreatFusion – Scan API Endpoints
=================================

Handles IOC submission, fan-out enrichment, ML scoring, and history retrieval.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import weakref
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Path, Query, Request, status, Depends
from fastapi.responses import StreamingResponse

from app.ingestion.cve import specific_cpe_names
from app.ingestion.eol import apply_eol, assessable
from app.ml.exposure import assess_exposure
from app.ml.lookalike import assess_lookalike
from app.ingestion.reputation import Subject
from app.ingestion.reputation_set import EVIDENCE_SOURCES, LOCAL_FEEDS, SOURCES as REPUTATION_SOURCES, pick_public_ip, summarize, with_ip
from app.ingestion.shodan import ShodanClient
from app.ingestion.techfingerprint import TechFingerprintClient
from app.ml.baseline import baseline_score, baseline_terms
from app.ml.verdict import headline_verdict
from app.ml.features import FEATURE_SCHEMA_VERSION, extract_features_with_coverage
from app.ml.runtime import url_risk_service
import app as _app_pkg
from app.core import providers as prov
from app.core.artifacts import model_path, model_version
from app.core.auth import STREAM_TICKET_TTL_SECONDS, issue_stream_ticket, require_token, require_token_or_ticket
from app.core.config import get_settings
from app.core.hub import hub
from app.core.ratelimit import scan_rate_limit
from app.core.scan_events import bus
from app.core.scan_store import ScanStore
from app.core import privacy, safe_http
from app.core.safe_http import FetchError, blocked_reason
from app.core.targets import Target, canonicalize
from app.models.schemas import (
    BrandCheck,
    CanonicalTarget,
    ProviderResult,
    ProviderStatus,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    FastRequest,
    FastVerdict,
    ScanResult,
    TargetType,
    UrlRiskTerm,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"], dependencies=[Depends(require_token)])
# The SSE stream authenticates with a Bearer token OR a single-use ticket (EventSource cannot send headers), so it
# lives on its own router, mounted by main.py next to ``router``.
stream_router = APIRouter(prefix="/scan", tags=["scan"], dependencies=[Depends(require_token_or_ticket)])

# Process-wide bound on provider calls in flight (A1-5). asyncio primitives belong to one event loop, so the gate is
# kept per loop (production has exactly one; each TestClient request has its own) and rebuilt if the limit changes.
_GATES: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, tuple[int, asyncio.Semaphore]]" = weakref.WeakKeyDictionary()


def provider_gate() -> asyncio.Semaphore:
    limit = max(1, get_settings().SCAN_MAX_CONCURRENT_PROVIDERS)
    loop = asyncio.get_running_loop()
    held = _GATES.get(loop)
    if held is None or held[0] != limit:
        held = _GATES[loop] = (limit, asyncio.Semaphore(limit))
    return held[1]

# ── Persistence ─────────────────────────────────────────────────────────
# Scans are stored in SQLite (core/scan_store.py), so history survives restarts. This used to be a
# module-level dict (and the `scans` table was created but never written).
_store = ScanStore()

# ── ML models (A2) ──────────────────────────────────────────────────────
# The URL-level models (calibrated tree model + character CNN + the transparent baseline + stacked fusion) live in one
# process-wide service (``app.ml.runtime``): integrity-checked against the SHA-256 manifest, validated against their model
# cards, SHAP explainer built once. A component that cannot load is left out and reported (``/health``); the API never
# substitutes the baseline for a missing ML score.
# One chainer per process: it parses the EPSS / KEV / Exploit-DB CSVs on first use, which must happen once, not
# once per scan (it used to be constructed inside create_scan, re-reading ~300k rows for every CVE-bearing scan).
from app.ml.chaining import VulnerabilityChainer  # noqa: E402

_chainer = VulnerabilityChainer()


def _baseline_label(score: float | None) -> str:
    """Severity band of the baseline heuristic; "Unknown" when there was no evidence at all."""
    return "Unknown" if score is None else _get_ml_label(score)


def _get_ml_label(score: float) -> str:
    """Map a continuous probability [0, 1] to a qualitative label."""
    if score < 0.25:
        return "Low"
    if score < 0.50:
        return "Medium"
    if score < 0.75:
        return "High"
    return "Critical"



# Display names used in the data_sources_* lists (kept for the existing UI).
_LABEL = {
    "virustotal": "VirusTotal",
    "shodan_internetdb": "Shodan",
    "nvd": "NVD",
    "epss": "EPSS",
    "kev": "KEV",
    "vulnrichment": "Vulnrichment",
    "tech_fingerprint": "TechFingerprint",
    "endoflife": "EndOfLife",
    "tls": "TLS",
    "rdap": "RDAP",
    "dns": "DNS",
    "ct": "CertTransparency",
    "openphish": "OpenPhish",
    "phishtank": "PhishTank",
    "urlhaus": "URLhaus",
    "threatfox": "ThreatFox",
    "safebrowsing": "SafeBrowsing",
    "urlscan": "urlscan",
    "otx": "OTX",
    "abuseipdb": "AbuseIPDB",
    "greynoise": "GreyNoise",
    "tranco": "Tranco",
}


def _bucket_sources(outcomes: list[ProviderResult]) -> dict[str, list[str]]:
    """Group provider outcomes by *status* — and only by status (A0-1).

    ok → succeeded · not_found → not_found · error → failed · not_configured → skipped.
    A provider that was not applicable to the target type (status ``skipped``) is kept in
    ``provider_results`` for provenance but not listed: it is neither a success nor a gap.
    """
    out: dict[str, list[str]] = {"succeeded": [], "not_found": [], "failed": [], "skipped": []}
    for o in outcomes:
        label = _LABEL.get(o.source, o.source)
        if o.status == ProviderStatus.OK:
            out["succeeded"].append(label)
        elif o.status == ProviderStatus.NOT_FOUND:
            out["not_found"].append(label)
        elif o.status == ProviderStatus.ERROR:
            out["failed"].append(label)
        elif o.status == ProviderStatus.NOT_CONFIGURED:
            out["skipped"].append(label)
    return out


def _reason_text(res: ProviderResult | None) -> str:
    if res is None:
        return "not queried"
    if res.status == ProviderStatus.NOT_FOUND:
        return "no record of this target"
    if res.status == ProviderStatus.NOT_CONFIGURED:
        return "not configured"
    http = f", HTTP {res.http_status}" if res.http_status else ""
    return f"{res.reason or res.status.value}{http}"


_B2_SOURCES = frozenset(REPUTATION_SOURCES)
_REPUTATION_EVIDENCE = frozenset({"virustotal"}) | EVIDENCE_SOURCES


def _assess_verdict(outcomes: list[ProviderResult], vt_res: ProviderResult | None) -> tuple[str, str | None]:
    """Is the evidence complete, partial, or missing entirely?

    Reputation evidence comes from VirusTotal and the independent channels of B2 (blocklists, abuse.ch, Safe Browsing,
    AbuseIPDB, urlscan, OTX).  If **none** of them has a record, there is no maliciousness evidence: the verdict is
    **unknown** — never "Low".  (The URL-lexical neural score is shown separately and is not enough on its own to call a
    target low-risk.)  For the B2 channels "no record" is a normal answer, not a gap; an error or a missing key is a gap.
    """
    if not any(o.ok and o.source in _REPUTATION_EVIDENCE for o in outcomes):
        return "unknown", (
            "No reputation source answered (VirusTotal: " + _reason_text(vt_res) + "). "
            "Absence of evidence is not evidence of safety."
        )
    applicable = [o for o in outcomes if o.status in (
        ProviderStatus.OK, ProviderStatus.NOT_FOUND, ProviderStatus.ERROR, ProviderStatus.NOT_CONFIGURED)]

    def _is_gap(o: ProviderResult) -> bool:
        if o.status == ProviderStatus.OK:
            return False
        return not (o.status == ProviderStatus.NOT_FOUND and o.source in _B2_SOURCES)

    missing = [(_LABEL.get(o.source, o.source), o) for o in applicable if _is_gap(o)]
    if missing:
        names = ", ".join(f"{n} ({_reason_text(o)})" for n, o in missing)
        return "partial", f"{len(applicable) - len(missing)} of {len(applicable)} sources answered; missing: {names}."
    return "ok", None


def _build_summary(verdict_status: str, verdict_reason: str | None, risk_label: str | None,
                   vt, shodan, cve, brand_check: BrandCheck | None = None, listed_by: list[str] | None = None,
                   url_flagged: bool = False, provider_evidence: bool = True) -> str:
    """Plain-language summary that never claims more than the evidence supports."""
    if verdict_status == "unknown":
        text = f"Risk could not be assessed from provider evidence. {verdict_reason}"
        return text + (" The URL text itself looks like phishing." if url_flagged else "")
    parts = []
    # The label of the HEADLINE: the higher-risk band of the URL model and the provider evidence.
    if risk_label and risk_label != "Unknown":
        if provider_evidence:
            parts.append(f"This target presents a {risk_label.lower()} risk profile.")
        else:        # only the URL text speaks: say so rather than claim a profile of the target
            parts.append(f"The URL text alone scores {risk_label.lower()} risk; there is no provider evidence.")
    if vt is not None:
        if vt.malicious_count > 0:
            parts.append(f"It is flagged by {vt.malicious_count} AV engines.")
        else:
            parts.append("No AV engine flagged it at the time of the last VirusTotal analysis.")
    if shodan is not None and shodan.open_ports:
        parts.append(f"There are {len(shodan.open_ports)} exposed ports"
                     + (f", with {len(cve.cves)} known CVEs detected." if cve is not None and cve.cves
                        else "."))
    if listed_by:
        parts.append("It is listed by " + ", ".join(_LABEL.get(s, s) for s in listed_by) + ".")
    if brand_check is not None and brand_check.match is not None:
        m = brand_check.match
        parts.append(f"The domain name imitates {m.brand} ({m.kind.replace('_', ' ')}).")
    if verdict_status == "partial" and verdict_reason:
        parts.append(f"Partial evidence: {verdict_reason}")
    return " ".join(parts)


def _canonical_view(t: Target) -> CanonicalTarget:
    """The API view of a canonical Target — never carries the query, fragment or credentials."""
    return CanonicalTarget(
        kind=t.kind, host=t.host, registered_domain=t.registered_domain, subdomain=t.subdomain, ip=t.ip,
        port=t.port, scheme=t.scheme, url=t.url_public, has_userinfo=t.has_userinfo, hash=t.hash,
        hash_type=t.hash_type,
    )


_FORMAT_MESSAGES = {
    TargetType.DOMAIN: "Invalid domain format.\nPlease enter a valid website domain.",
    TargetType.URL: "Invalid URL format.\nPlease enter a valid http(s) URL.",
    TargetType.IP: "Invalid IP address.\nPlease enter a single IPv4 or IPv6 address (no CIDR range or path).",
    TargetType.FILE_HASH: "Invalid file hash.\nPlease enter a 32, 40 or 64 digit hexadecimal MD5, SHA-1 or SHA-256 hash.",
}


def _format_error(t: Target) -> dict:
    """The 400 body for a target that failed canonicalisation (no provider has been contacted)."""
    if t.problem == "empty":
        return {"success": False, "stage": "normalize", "message": "Empty or invalid target.", "problem": t.problem}
    return {"success": False, "stage": "format", "message": _FORMAT_MESSAGES[t.kind], "problem": t.problem}


# ── Endpoints ───────────────────────────────────────────────────────────

@router.post("", response_model=ScanResponse, summary="Submit a new IOC scan",
             dependencies=[Depends(scan_rate_limit)])
async def create_scan(request: ScanRequest) -> ScanResponse:
    """Accept an IOC and run the enrichment and scoring pipeline.

    ``mode: "sync"`` (the default) returns the full result when the scan is done. ``mode: "async"`` (B1) returns the
    **fast-tier verdict** (local lists, brand check, URL-text models, a recent scan: nothing leaves the machine) plus a
    ``scan_id`` at once and runs the slow tier as a background job whose progress streams over SSE.
    """
    if request.mode == "async":
        return await _start_async_scan(request)
    return await _execute_scan(request)


@router.post("/fast", response_model=FastVerdict, summary="Fast tier only: local checks, no provider calls",
             dependencies=[Depends(scan_rate_limit)])
async def fast_scan(request: FastRequest) -> FastVerdict:
    """The first answer, from local data only (B1). Used by the browser extension; never sends anything to a third party."""
    from app.core.fast import fast_check, recent_scan_summary

    async def recent(t):
        return await recent_scan_summary(_store, t)

    return await fast_check(request.target, request.target_type, send_full_url=request.send_full_url, recent_scan_lookup=recent)


async def _start_async_scan(request: ScanRequest):
    from fastapi.responses import JSONResponse
    from app.core.fast import fast_check, recent_scan_summary
    from app.core.jobs import JOBS, QueueFull

    settings = get_settings()
    target = canonicalize(request.target, request.target_type)
    if not target.valid:
        return JSONResponse(status_code=400, content=_format_error(target))
    scan_id = request.scan_id or str(uuid4())
    if JOBS.has(scan_id) or bus.is_started(scan_id) or await _store.get(scan_id) is not None:
        return JSONResponse(status_code=409, content={"success": False, "detail": f"scan_id '{scan_id}' is already used."})

    async def recent(t):
        return await recent_scan_summary(_store, t)

    fast = await fast_check(request.target, request.target_type, send_full_url=request.send_full_url, recent_scan_lookup=recent)
    sync_request = request.model_copy(update={"scan_id": scan_id, "mode": "sync"})

    async def job() -> str | None:
        resp = await _execute_scan(sync_request)
        if isinstance(resp, ScanResponse):
            return None if resp.success else (resp.error or "the scan failed")
        # a JSONResponse: the target failed validation after the fast answer (e.g. the name does not resolve)
        try:
            detail = json.loads(bytes(resp.body)).get("message") or "validation failed"
        except Exception:
            detail = "validation failed"
        bus.publish(scan_id, {"type": "error", "scan_id": scan_id, "message": "The scan could not be started."})
        return str(detail)

    JOBS.max_concurrent, JOBS.max_pending = settings.SCAN_MAX_CONCURRENT_JOBS, settings.SCAN_MAX_PENDING_JOBS
    try:
        JOBS.submit(scan_id, job)
    except QueueFull:
        return JSONResponse(status_code=429, content={"success": False, "detail": "Too many scans are waiting; try again shortly."})
    return ScanResponse(success=True, result=None, error=None, scan_id=scan_id, status="running", fast=fast)


async def _execute_scan(request: ScanRequest) -> ScanResponse:
    """The slow tier: the full enrichment + scoring pipeline (what ``create_scan`` used to be)."""
    # ── 0. Canonicalise, then validate ──────────────────────────────────────
    # One parser for every component (A1-6): from here on providers see `target`, never the typed string.
    from fastapi.responses import JSONResponse
    target = canonicalize(request.target, request.target_type)
    if not target.valid:
        return JSONResponse(status_code=400, content=_format_error(target))
    if request.target_type in (TargetType.DOMAIN, TargetType.URL):
        from app.core.validation import validate_domain_target
        is_valid, validation_data, normalized = await validate_domain_target(target.host)
        if not is_valid:
            return JSONResponse(status_code=400, content=validation_data)


    scan_id = request.scan_id or str(uuid4())
    if request.scan_id and (bus.is_started(scan_id) or await _store.get(scan_id) is not None):
        return JSONResponse(status_code=409, content={"success": False, "detail": f"scan_id '{scan_id}' is already used."})
    logger.info("Starting scan %s (%s)", scan_id, request.target_type)

    from app.core.config import get_settings
    settings = get_settings()
    use_mock = settings.USE_MOCK_DATA
    providers = settings.provider_statuses()

    vt_client = hub.virustotal()          # process-wide: shared quota + persistent cache (A1-1); never closed per scan
    shodan_client = ShodanClient(api_key=settings.SHODAN_API_KEY, use_mock=use_mock)
    cve_client = hub.nvd()                # process-wide: shared rate window + persistent CVE cache (A1-2)
    tech_client = TechFingerprintClient(use_mock=use_mock)

    # Every provider call yields a ProviderResult; its *status* — not truthiness — decides
    # whether it counts as a success, a gap, or a failure (A0-1). (Collected after the concurrent phase.)

    # Privacy (A0-10): third parties and the target itself receive only scheme://host/path unless the user
    # opted in — the query string/fragment/credentials are where tokens and personal data live.
    outbound_url = (target.url_full if request.send_full_url else target.url_public) or ""
    # A domain-type target may have been typed as a URL; providers only ever see the canonical host (or IP).
    outbound_host = target.host or ""

    # Time budget (A0-9): one overall deadline for the provider lookups plus a cap per lookup, so a slow
    # or hung provider becomes `error/timeout` instead of holding the scan (and a worker) open.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + settings.SCAN_DEADLINE_SECONDS

    def _budget() -> float:
        return min(float(settings.PROVIDER_TIMEOUT_SECONDS), deadline - loop.time())

    async def _safe(call, source: str) -> ProviderResult:
        """Run a provider lookup within the time budget.

        Clients return ProviderResults and normally never raise; this guards against an unexpected
        exception (reported as an error, never as clean data) and enforces the deadline.
        """
        timeout = _budget()
        if timeout <= 0:                       # the scan's budget is already spent
            call.close()                       # (never awaited — avoid the "coroutine never awaited" warning)
            return prov.error(source, "timeout")
        try:
            return await asyncio.wait_for(call, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("%s lookup timed out after %.1fs", source, timeout)
            return prov.error(source, "timeout")
        except Exception as e:
            logger.exception("Unexpected error in %s lookup", source)
            return prov.error(source, f"unexpected:{type(e).__name__}")

    # ── Live progress (A1-5) ────────────────────────────────────────────────
    # Events carry provider names / statuses / reasons / timings only — never the target or any finding.
    def _emit(event: dict) -> None:
        bus.publish(scan_id, event)

    def _done(res: ProviderResult) -> ProviderResult:
        _emit({"type": "provider", "source": res.source, "status": res.status.value, "reason": res.reason,
               "cached": res.cached, "mock": res.mock, "latency_ms": res.latency_ms, "retry_after": res.retry_after})
        return res

    async def _track(source: str, make_call, *, enabled: bool = True) -> ProviderResult:
        """One provider call: switchable, bounded by the process-wide gate, announced as it starts and ends.

        ``make_call`` creates the coroutine only once the gate is held (a never-awaited coroutine would warn). The
        switches govern *live* probing; mock mode is synthetic and touches no network, so it always runs.
        """
        if not enabled and not use_mock:
            return _done(prov.skipped(source, "disabled"))
        _emit({"type": "provider", "source": source, "status": "running"})
        async with provider_gate():
            res = await _safe(make_call(), source)
        return _done(res)

    tt = request.target_type
    rep_set = hub.reputation()
    rep_kind = "hash" if tt == TargetType.FILE_HASH else tt.value      # the channels' name for a file-hash target
    expected = (["virustotal"] + (["shodan_internetdb"] if tt in (TargetType.IP, TargetType.DOMAIN) else [])
                + (["tech_fingerprint", "tls", "rdap", "dns", "ct"] if tt in (TargetType.URL, TargetType.DOMAIN) else [])
                + rep_set.applicable_sources(rep_kind))
    _emit({"type": "start", "scan_id": scan_id, "target_type": tt.value, "providers": expected, "mock": use_mock})

    try:
        # ── 1. Data enrichment — independent providers run CONCURRENTLY (A1-5) ───────────────────────
        # Chains: [VirusTotal] · [InternetDB → NVD] · [tech fingerprint → end-of-life] · [TLS] · [RDAP] · [DNS].
        # Only genuinely dependent steps wait for their parent: NVD needs InternetDB's CVE/CPE list, the EOL check needs
        # the detected versions. A provider that raises is reported as an error and never sinks the others.

        async def vt_chain() -> ProviderResult | None:
            # needs a real key in live mode; never send a placeholder upstream
            if not providers["virustotal"].configured:
                return _done(prov.not_configured("virustotal"))
            if tt == TargetType.DOMAIN:
                return await _track("virustotal", lambda: vt_client.lookup_domain(outbound_host))
            if tt == TargetType.IP:
                return await _track("virustotal", lambda: vt_client.lookup_ip(outbound_host))
            if tt == TargetType.URL:
                return await _track("virustotal", lambda: vt_client.lookup_url(outbound_url))
            if tt == TargetType.FILE_HASH:
                return await _track("virustotal", lambda: vt_client.lookup_file_hash(target.hash))
            return None

        async def shodan_chain() -> tuple[ProviderResult | None, ProviderResult | None, list[ProviderResult], object]:
            # Shodan InternetDB (only relevant for IPs and Domains) …
            if tt not in (TargetType.IP, TargetType.DOMAIN):
                return None, None, [], None
            _emit({"type": "provider", "source": "shodan_internetdb", "status": "running"})
            ip_target = outbound_host
            dns_failure: ProviderResult | None = None
            if tt == TargetType.DOMAIN and not use_mock:
                # (Live only. Mock mode is synthetic: it must not leak the typed host to a real resolver, and the mock
                # InternetDB answer does not depend on the IP.)
                try:
                    # Async, all A/AAAA records (the old blocking, IPv4-only gethostbyname is gone).
                    resolved = await asyncio.wait_for(safe_http.resolve_host(outbound_host.strip(), 443),
                                                      timeout=max(0.1, min(10.0, _budget())))
                except FetchError as e:
                    logger.warning("DNS resolution failed for %s: %s", outbound_host, e)
                    dns_failure = prov.error("shodan_internetdb", e.reason)
                except asyncio.TimeoutError:
                    dns_failure = prov.error("shodan_internetdb", "timeout")
                else:
                    # InternetDB is keyed by public IPv4. We never contact the target here, but an
                    # internal/reserved answer is meaningless to look up.
                    public_v4 = [i for i in resolved
                                 if isinstance(i, ipaddress.IPv4Address) and blocked_reason(i) is None]
                    if public_v4:
                        ip_target = str(public_v4[0])
                    else:
                        dns_failure = prov.error("shodan_internetdb", "no_public_ipv4")
            if dns_failure is not None:
                shodan_res = _done(dns_failure)
            else:
                async with provider_gate():
                    shodan_res = _done(await _safe(shodan_client.lookup_ip(ip_target), "shodan_internetdb"))
            shodan_data = shodan_res.data if shodan_res.ok else None

            # … then NVD: the CVE IDs InternetDB listed plus (live mode) its versioned CPEs, in one lookup that has
            # its own deadline and keeps whatever finished (A1-2). Needs a real key.
            cve_res: ProviderResult | None = None
            cpes = [] if use_mock or not settings.NVD_LOOKUP_BY_CPE or shodan_data is None else shodan_data.cpes
            if shodan_data is not None and (shodan_data.vulns or specific_cpe_names(cpes)):
                if not providers["nvd"].configured:
                    cve_res = _done(prov.not_configured("nvd"))
                else:
                    cve_res = await _track("nvd", lambda: cve_client.lookup_for_host(shodan_data.vulns, cpes))

            # … then the exploit-informed exposure (B11): EPSS (likelihood), KEV (observed exploitation) and CISA's SSVC
            # decision points for the host's CVEs, all asked together. Only when InternetDB answered: otherwise "this host
            # has no CVEs" is unknown, and so is its exposure. Kept apart from the maliciousness scores.
            intel: list[ProviderResult] = []
            exposure_data = None
            if shodan_data is not None:
                cve_data = cve_res.data if cve_res is not None and cve_res.ok else None
                cvss_by_id = {d.cve_id.upper(): d.cvss_v3_score for d in (cve_data.cves if cve_data else [])}
                listed = list(dict.fromkeys([v.upper() for v in shodan_data.vulns] + list(cvss_by_id)))
                listed.sort(key=lambda c: -(cvss_by_id.get(c) or 0.0))              # highest severity first when capped
                listed = listed[: settings.EXPOSURE_MAX_CVES]
                epss_rows = kev_rows = ssvc_rows = None
                ages: dict[str, float | None] = {}
                if listed:
                    epss_res, kev_res, vr_res = await asyncio.gather(
                        _track("epss", lambda: hub.epss().lookup(listed), enabled=settings.EPSS_ENABLED),
                        _track("kev", lambda: hub.kev().lookup(listed), enabled=settings.KEV_ENABLED),
                        _track("vulnrichment", lambda: hub.vulnrichment().lookup(listed), enabled=settings.VULNRICHMENT_ENABLED),
                    )
                    intel = [epss_res, kev_res, vr_res]
                    # three-state: ok -> the rows; "answered, nothing" -> {}; failed / skipped / disabled -> None (unknown)
                    epss_rows = (epss_res.data.rows if epss_res.ok else {} if epss_res.status == ProviderStatus.NOT_FOUND else None)
                    ssvc_rows = (vr_res.data.rows if vr_res.ok else {} if vr_res.status == ProviderStatus.NOT_FOUND else None)
                    if kev_res.ok:
                        kev_rows = kev_res.data.entries
                        ages["kev"] = kev_res.data.age_days
                exposure_data = assess_exposure(listed, cvss=cvss_by_id, epss=epss_rows, kev=kev_rows, ssvc=ssvc_rows,
                                                cves_listed_by_host=True, feed_ages=ages)
            return shodan_res, cve_res, intel, exposure_data

        async def tech_chain() -> tuple[ProviderResult | None, ProviderResult | None, object]:
            # Technology fingerprinting (URLs/Domains) …
            if tt not in (TargetType.URL, TargetType.DOMAIN):
                return None, None, None
            target_url = outbound_url if tt == TargetType.URL else f"https://{outbound_host}"
            tech_res = await _track("tech_fingerprint", lambda: tech_client.fingerprint_url(target_url))
            tech_data = tech_res.data if tech_res.ok else None
            # … then end-of-life (A1-4): endoflife.date for the detected technologies *that have a version*. Unknown
            # stays unknown: a failed lookup leaves ``eol=None`` and is reported as its own outcome.
            eol_res: ProviderResult | None = None
            if tech_data is not None and assessable(tech_data.technologies):
                eol_res = await _track("endoflife", lambda: hub.eol().assess(tech_data.technologies),
                                       enabled=settings.EOL_ENABLED)
                if eol_res.ok:
                    tech_data = apply_eol(tech_data, eol_res.data)
            return tech_res, eol_res, tech_data

        async def host_signal(source: str, enabled: bool, make_call) -> ProviderResult | None:
            # Host signals (A1-3): the certificate, the registration record (real domain age) and DNS facts. They get
            # the canonical *host* / *registered domain* only — never a URL (privacy, A0-10).
            if tt not in (TargetType.URL, TargetType.DOMAIN):
                return None
            return await _track(source, make_call, enabled=enabled)

        # DNS runs as its own task because the IP-based reputation channels (AbuseIPDB, GreyNoise) wait for its answer.
        dns_task = asyncio.ensure_future(
            host_signal("dns", settings.DNS_ENABLED, lambda: hub.dns().lookup(target.host, target.registered_domain)))
        switches = {
            "openphish": settings.OPENPHISH_ENABLED, "phishtank": settings.PHISHTANK_ENABLED, "tranco": settings.TRANCO_ENABLED,
            "urlhaus": settings.URLHAUS_ENABLED, "threatfox": settings.THREATFOX_ENABLED,
            "safebrowsing": settings.SAFEBROWSING_ENABLED, "urlscan": settings.URLSCAN_ENABLED, "otx": settings.OTX_ENABLED,
            "abuseipdb": settings.ABUSEIPDB_ENABLED, "greynoise": settings.GREYNOISE_ENABLED,
        }

        async def reputation_chain() -> list[ProviderResult]:
            # Independent reputation channels (B2). Each is asked only what may leave the machine: the canonical host,
            # a resolved *public* IP, a hash or the privacy-trimmed URL. They run concurrently; the IP ones wait for DNS.
            subject = Subject(
                kind=rep_kind, host=outbound_host or None, registered_domain=target.registered_domain,
                url=outbound_url if tt == TargetType.URL else None, hash=target.hash if tt == TargetType.FILE_HASH else None,
                ip=target.ip if tt == TargetType.IP else None)

            async def one(p) -> ProviderResult:
                s = subject
                if p.needs_ip and tt in (TargetType.URL, TargetType.DOMAIN):
                    dns_res_ = await dns_task
                    resolved = (dns_res_.data.a or []) + (dns_res_.data.aaaa or []) if dns_res_ is not None and dns_res_.ok else []
                    s = with_ip(subject, pick_public_ip(resolved))
                return await _track(p.source, lambda: p.call(s), enabled=p.enabled)

            plan = rep_set.plan(rep_kind, switches)
            return list(await asyncio.gather(*(one(p) for p in plan))) if plan else []

        (vt_res, (shodan_res, cve_res, intel_res, exposure), (tech_res, eol_res, tech),
         tls_res, rdap_res, dns_res, ct_res, rep_results) = await asyncio.gather(
            vt_chain(),
            shodan_chain(),
            tech_chain(),
            host_signal("tls", settings.TLS_ENABLED, lambda: hub.tls().lookup(target.host)),
            host_signal("rdap", settings.RDAP_ENABLED, lambda: hub.rdap().lookup(target.registered_domain)),
            dns_task,
            host_signal("ct", settings.CT_ENABLED, lambda: hub.ct().lookup(target.host)),
            reputation_chain(),
        )
        # A stable provenance order, whatever finished first.
        outcomes = [r for r in (vt_res, shodan_res, cve_res, *intel_res, tech_res, eol_res, tls_res, rdap_res, dns_res, ct_res,
                                  *rep_results)
                    if r is not None]
        vt = vt_res.data if vt_res is not None and vt_res.ok else None
        shodan = shodan_res.data if shodan_res is not None and shodan_res.ok else None
        cve = cve_res.data if cve_res is not None and cve_res.ok else None
        tls = tls_res.data if tls_res is not None and tls_res.ok else None
        rdap = rdap_res.data if rdap_res is not None and rdap_res.ok else None
        dns = dns_res.data if dns_res is not None and dns_res.ok else None
        ct = ct_res.data if ct_res is not None and ct_res.ok else None
        feed_ages: dict[str, float | None] = {}
        if not use_mock:
            for feed_name in LOCAL_FEEDS:
                if any(r.source == feed_name for r in rep_results):
                    feed_ages[feed_name] = await hub.feeds.age_days(feed_name)
        reputation = summarize(rep_results, feed_ages)

        # ── 1b. Predictive Vulnerability Chaining ───────────────────────
        attack_paths = []
        if cve and cve.cves:
            try:
                # First use parses the EPSS/KEV/Exploit-DB CSVs (hundreds of thousands of rows): do that in a
                # worker thread so the event loop (SSE heartbeats, other requests) keeps ticking (A0-9).
                intel = {c.cve_id: c for c in exposure.cves} if exposure is not None else None      # live EPSS/KEV (B11)
                await asyncio.to_thread(_chainer.initialize, legacy_epss_kev=intel is None)
                # Bounded by what is left of the scan's deadline: attack paths are a bonus, never a reason to hold the
                # scan (and a worker) open — a hung or slow chainer just yields no paths.
                attack_paths = await asyncio.wait_for(_chainer.build_and_solve_chain(cve.cves, intel=intel),
                                                      timeout=max(0.5, deadline - loop.time()))
            except Exception as e:
                logger.warning("Vulnerability chaining failed or ran out of time: %s", e)

        # ── 1c. Brand impersonation (B4) ────────────────────────────────
        # Local and deterministic (no network, no quota): the canonical host against the protected brands. Reported next
        # to the maliciousness scores — a domain can imitate a brand and still have no external reputation yet.
        brand_check: BrandCheck | None = None
        if settings.LOOKALIKE_ENABLED and tt in (TargetType.URL, TargetType.DOMAIN) and target.host:
            _emit({"type": "stage", "stage": "lookalike"})
            try:
                brand_check = assess_lookalike(target.host, await hub.brands(), threshold=settings.LOOKALIKE_THRESHOLD)
            except Exception:
                logger.exception("Brand look-alike check failed")        # a gap in coverage, never a failed scan

        # ── 2. Feature Engineering (unknown stays None; coverage reported) ─
        _emit({"type": "stage", "stage": "features"})
        features, coverage = extract_features_with_coverage(vt, shodan, cve, tech, tls, rdap, dns, ct)

        # ── 3. Provider-evidence score ──────────────────────────────────
        _emit({"type": "stage", "stage": "scoring"})
        # Is the evidence complete, partial, or missing? When no reputation source answered, a score built from the host signals
        # alone (tech stack, certificate) would read "0 = nothing found" — so there is no score: None, not a reassuring 0.0.
        verdict_status, verdict_reason = _assess_verdict(outcomes, vt_res)
        b_score = None if verdict_status == "unknown" else baseline_score(features)

        # ── 4. URL-level ML (A2): calibrated tree model + char CNN + stacked fusion, SHAP evidence ──────────
        # These models read the URL *text* only (canonicalised: scheme / www do not matter), so they apply to URL and
        # domain targets and work even when no provider has heard of the target. They are CPU-bound and synchronous:
        # run in a worker thread so the event loop (SSE heartbeat, other requests) keeps ticking.
        m_score = None
        m_label = "Unknown"
        explanations = []
        neural_score = None
        neural_label = None
        neural_url_score = None
        neural_explanations = []
        url_risk = None
        ml = url_risk_service()
        if tt not in (TargetType.URL, TargetType.DOMAIN):
            ml_status = "not_applicable"                       # an IP or a hash has no URL text to read
        elif not ml.loaded:
            ml_status = "model_not_loaded"
            logger.warning("URL model not loaded (%s): reporting no ML score (baseline is NOT substituted).", ml.problems)
        else:
            try:
                url_risk, explanations, neural_explanations = await asyncio.to_thread(ml.assess, request.target)
                ml_status = "ok"
                m_score = url_risk.headline_score
                m_label = ml.band(m_score)
                neural_score = url_risk.cnn_score
                neural_url_score = url_risk.cnn_score
                neural_label = ml.band(neural_score) if neural_score is not None else None
            except Exception as e:
                logger.exception("URL model scoring failed: %s", e)
                ml_status = "error"

        # ── 4b. Headline: the higher-risk band of the two channels; neither score is touched ──────────
        verdict = headline_verdict(b_score, _baseline_label(b_score), m_score, m_label)
        provider_terms = ([UrlRiskTerm(text=text, weight=round(points, 4)) for text, points in baseline_terms(features)]
                          if b_score is not None else [])

        # ── 5. Plain-language summary ───────────────────────────────────
        summary_text = _build_summary(verdict_status, verdict_reason, verdict.headline_band, vt, shodan, cve, brand_check,
                                      reputation.listed_by if reputation else None,
                                      url_flagged=bool(url_risk is not None and url_risk.flagged),
                                      provider_evidence=b_score is not None)
        buckets = _bucket_sources(outcomes)

        # Assemble the final payload
        result = ScanResult(
            scan_id=scan_id,
            target=request.target,
            target_type=request.target_type,
            timestamp=datetime.now(timezone.utc),
            canonical=_canonical_view(target),
            virustotal=vt,
            shodan=shodan,
            cve=cve,
            tech_fingerprint=tech,
            tls=tls,
            rdap=rdap,
            dns=dns,
            ct=ct,
            reputation=reputation,
            exposure=exposure,
            brand_check=brand_check,
            lookalike_of=brand_check.match if brand_check is not None else None,
            features=features,
            feature_coverage=coverage,
            baseline_score=b_score,
            baseline_label=_baseline_label(b_score),
            url_risk=url_risk,
            ml_score=m_score,
            ml_label=m_label,
            ml_status=ml_status,
            headline_band=verdict.headline_band,
            driven_by=verdict.driven_by,
            agreement=verdict.agreement,
            baseline_terms=provider_terms,
            neural_score=neural_score,
            neural_label=neural_label,
            neural_url_score=neural_url_score,
            neural_explanations=neural_explanations,
            explanations=explanations,
            attack_paths=attack_paths,
            summary=summary_text,
            provider_results=[o.outcome() for o in outcomes],
            model_versions={
                "url_xgb": model_version("url_xgb.ubj") if ml.loaded else "not_loaded",
                "url_cnn": model_version("url_cnn.pt") if ml.cnn_loaded else "not_loaded",
                "url_fusion": model_version("url_fusion.json") if ml.fusion_loaded else "not_loaded",
            },
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            app_version=_app_pkg.APP_VERSION,
            verdict_status=verdict_status,
            verdict_reason=verdict_reason,
            data_sources_succeeded=buckets["succeeded"],
            data_sources_failed=buckets["failed"],
            data_sources_not_found=buckets["not_found"],
            data_sources_skipped=buckets["skipped"],
            mock_mode=use_mock
        )

        # Persist (history, provenance). A storage failure must be loud but must not discard a
        # result we already computed.
        try:
            await _store.save(result)
        except Exception:
            logger.exception("Scan %s was computed but could not be persisted", scan_id)

        _emit({"type": "done", "scan_id": scan_id, "verdict_status": verdict_status, "success": True})
        return ScanResponse(success=True, result=result, error=None)

    except Exception as e:
        logger.exception("Critical error during scan processing.")
        try:  # keep a record of the failure (status='error'); it is not listed in history
            await _store.save_failure(scan_id, request.target, request.target_type.value, str(e))
        except Exception:
            logger.exception("Could not record failed scan %s", scan_id)
        _emit({"type": "error", "scan_id": scan_id, "message": "The scan failed."})      # no internals in events
        return ScanResponse(success=False, result=None, error=str(e))

    finally:
        # Ensure all async clients are closed
        await shodan_client.close()
        await tech_client.close()


@router.get("/history", response_model=list[ScanHistoryItem], summary="List scan history")
async def get_history(
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of items"),
    offset: int = Query(0, ge=0, description="Items to skip (newest first)"),
) -> list[ScanHistoryItem]:
    """Retrieve past scans from the database, newest first."""
    return await _store.history(limit=limit, offset=offset)


@router.get("/{scan_id}", response_model=ScanResponse, summary="Retrieve a specific scan")
async def get_scan(scan_id: str) -> ScanResponse:
    """Fetch the full stored result (evidence, provenance, summary) for a single scan."""
    from app.core.jobs import JOBS

    result = await _store.get(scan_id)
    if result is None and JOBS.state(scan_id) in ("queued", "running"):
        return ScanResponse(success=True, result=None, error=None, scan_id=scan_id, status="running")
    if result is None and JOBS.state(scan_id) == "error":
        return ScanResponse(success=False, result=None, error=JOBS.error(scan_id) or "the scan failed", scan_id=scan_id, status="error")
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found."
        )
    return ScanResponse(success=True, result=result, error=None)


# ── Live progress (A1-5) ────────────────────────────────────────────────

@router.post("/events-ticket", summary="Issue a single-use ticket for the scan-events stream")
async def scan_events_ticket() -> dict:
    """EventSource cannot send an Authorization header; trade the token for a 30 s one-time ticket."""
    return {"ticket": issue_stream_ticket(), "expires_in": STREAM_TICKET_TTL_SECONDS}


@stream_router.get("/{scan_id}/events", summary="Live per-provider progress of a scan (Server-Sent Events)")
async def scan_events(
    request: Request,
    scan_id: str = Path(..., pattern=r"^[A-Za-z0-9_-]{8,64}$"),
) -> StreamingResponse:
    """Stream ``start`` / ``provider`` / ``stage`` / ``done`` events for ``scan_id``.

    Subscribe *before* POSTing the scan (use the ``scan_id`` field) to watch it from the first provider call; a finished
    scan's events are replayed for a couple of minutes. Events hold names, statuses, reasons and timings only — fetch
    the findings with ``GET /scan/{scan_id}``. Authenticate with the Bearer token or a ticket from
    ``POST /scan/events-ticket``.
    """
    wait = float(get_settings().SCAN_EVENTS_WAIT_SECONDS)

    async def stream():
        async for event in bus.subscribe(scan_id, wait_seconds=wait):
            if event is None:
                yield ": keep-alive\n\n"
                if await request.is_disconnected():
                    break
                continue
            yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
