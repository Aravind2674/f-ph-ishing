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
from app.ingestion.shodan import ShodanClient
from app.ingestion.techfingerprint import TechFingerprintClient
from app.ml.baseline import baseline_score
from app.ml.explain import explain_prediction
from app.ml.features import FEATURE_SCHEMA_VERSION, extract_features_with_coverage
from app.ml.fusion_model import FusionModel
from app.ml.neural_fusion import NeuralFusionModel
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
    CanonicalTarget,
    ProviderResult,
    ProviderStatus,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    ScanResult,
    TargetType,
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

# ── ML Model Initialization ─────────────────────────────────────────────
_model = FusionModel()
# Located via the configured model directory (absolute; independent of the working directory).
# If it cannot be loaded the API reports ml_score=None / ml_status="model_not_loaded" — it never
# substitutes the baseline score for it.
_fusion_path = model_path("fusion_model.json")
if _fusion_path is None:
    logger.error("fusion_model.json not found in %s — no ML score will be produced",
                 get_settings().model_dir)
else:
    try:
        _model.load(_fusion_path)
    except Exception as e:  # incl. ArtifactIntegrityError: refuse the file, keep the API up
        logger.error("XGBoost fusion model NOT loaded from %s: %s", _fusion_path, e)

# ── Neural Fusion Model (char-CNN + tabular) ────────────────────────────
# One chainer per process: it parses the EPSS / KEV / Exploit-DB CSVs on first use, which must happen once, not
# once per scan (it used to be constructed inside create_scan, re-reading ~300k rows for every CVE-bearing scan).
from app.ml.chaining import VulnerabilityChainer  # noqa: E402

_chainer = VulnerabilityChainer()

# Optional deep-learning model that also reads the raw URL string. Loaded
# best-effort: if the checkpoint is absent the pipeline silently falls back to
# the XGBoost/baseline scores, so this never breaks an existing deployment.
_neural_model = NeuralFusionModel()
_neural_path = model_path("neural_fusion.pt")
if _neural_path is not None:
    try:
        _neural_model.load(_neural_path)
    except Exception as e:  # pragma: no cover - defensive load guard
        logger.warning("Neural fusion model failed to load: %s", e)


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
    "tech_fingerprint": "TechFingerprint",
    "endoflife": "EndOfLife",
    "tls": "TLS",
    "rdap": "RDAP",
    "dns": "DNS",
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


def _assess_verdict(outcomes: list[ProviderResult], vt_res: ProviderResult | None) -> tuple[str, str | None]:
    """Is the evidence complete, partial, or missing entirely?

    VirusTotal is today's only *reputation* source, so without it there is no maliciousness
    evidence: the verdict is **unknown** — never "Low".  (The URL-lexical neural score is shown
    separately and is not enough on its own to call a target low-risk.)
    """
    if vt_res is None or not vt_res.ok:
        return "unknown", (
            "No reputation source answered (VirusTotal: " + _reason_text(vt_res) + "). "
            "Absence of evidence is not evidence of safety."
        )
    applicable = [o for o in outcomes if o.status in (
        ProviderStatus.OK, ProviderStatus.NOT_FOUND, ProviderStatus.ERROR, ProviderStatus.NOT_CONFIGURED)]
    missing = [(_LABEL.get(o.source, o.source), o) for o in applicable if o.status != ProviderStatus.OK]
    if missing:
        names = ", ".join(f"{n} ({_reason_text(o)})" for n, o in missing)
        return "partial", f"{len(applicable) - len(missing)} of {len(applicable)} sources answered; missing: {names}."
    return "ok", None


def _build_summary(verdict_status: str, verdict_reason: str | None, ml_label: str | None,
                   vt, shodan, cve) -> str:
    """Plain-language summary that never claims more than the evidence supports."""
    if verdict_status == "unknown":
        return f"Risk could not be assessed. {verdict_reason}"
    parts = []
    if ml_label and ml_label != "Unknown":
        parts.append(f"This target presents a {ml_label.lower()} risk profile.")
    if vt is not None:
        if vt.malicious_count > 0:
            parts.append(f"It is flagged by {vt.malicious_count} AV engines.")
        else:
            parts.append("No AV engine flagged it at the time of the last VirusTotal analysis.")
    if shodan is not None and shodan.open_ports:
        parts.append(f"There are {len(shodan.open_ports)} exposed ports"
                     + (f", with {len(cve.cves)} known CVEs detected." if cve is not None and cve.cves
                        else "."))
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
    """Accept an IOC and run the full enrichment and ML scoring pipeline.
    
    This endpoint executes synchronously for demonstration purposes.
    """
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
    expected = (["virustotal"] + (["shodan_internetdb"] if tt in (TargetType.IP, TargetType.DOMAIN) else [])
                + (["tech_fingerprint", "tls", "rdap", "dns"] if tt in (TargetType.URL, TargetType.DOMAIN) else []))
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

        async def shodan_chain() -> tuple[ProviderResult | None, ProviderResult | None]:
            # Shodan InternetDB (only relevant for IPs and Domains) …
            if tt not in (TargetType.IP, TargetType.DOMAIN):
                return None, None
            _emit({"type": "provider", "source": "shodan_internetdb", "status": "running"})
            ip_target = outbound_host
            dns_failure: ProviderResult | None = None
            if tt == TargetType.DOMAIN:
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
            return shodan_res, cve_res

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

        (vt_res, (shodan_res, cve_res), (tech_res, eol_res, tech),
         tls_res, rdap_res, dns_res) = await asyncio.gather(
            vt_chain(),
            shodan_chain(),
            tech_chain(),
            host_signal("tls", settings.TLS_ENABLED, lambda: hub.tls().lookup(target.host)),
            host_signal("rdap", settings.RDAP_ENABLED, lambda: hub.rdap().lookup(target.registered_domain)),
            host_signal("dns", settings.DNS_ENABLED, lambda: hub.dns().lookup(target.host, target.registered_domain)),
        )
        # A stable provenance order, whatever finished first.
        outcomes = [r for r in (vt_res, shodan_res, cve_res, tech_res, eol_res, tls_res, rdap_res, dns_res)
                    if r is not None]
        vt = vt_res.data if vt_res is not None and vt_res.ok else None
        shodan = shodan_res.data if shodan_res is not None and shodan_res.ok else None
        cve = cve_res.data if cve_res is not None and cve_res.ok else None
        tls = tls_res.data if tls_res is not None and tls_res.ok else None
        rdap = rdap_res.data if rdap_res is not None and rdap_res.ok else None
        dns = dns_res.data if dns_res is not None and dns_res.ok else None

        # ── 1b. Predictive Vulnerability Chaining ───────────────────────
        attack_paths = []
        if cve and cve.cves:
            try:
                # First use parses the EPSS/KEV/Exploit-DB CSVs (hundreds of thousands of rows): do that in a
                # worker thread so the event loop (SSE heartbeats, other requests) keeps ticking (A0-9).
                await asyncio.to_thread(_chainer.initialize)
                attack_paths = await _chainer.build_and_solve_chain(cve.cves)
            except Exception as e:
                logger.warning("Vulnerability chaining failed: %s", e)

        # ── 2. Feature Engineering (unknown stays None; coverage reported) ─
        _emit({"type": "stage", "stage": "features"})
        features, coverage = extract_features_with_coverage(vt, shodan, cve, tech, tls, rdap, dns)

        # ── 3. Rule-Based Baseline ──────────────────────────────────────
        _emit({"type": "stage", "stage": "scoring"})
        # With no evidence at all there is nothing to score: None, not a reassuring 0.0.
        any_ok = any(o.ok for o in outcomes)
        b_score = baseline_score(features) if any_ok else None

        # ── 4. ML Fusion Model & SHAP ───────────────────────────────────
        # The deployed XGBoost model reads VirusTotal features only (audit §E), so without a
        # VirusTotal answer it has nothing to score: report that instead of a made-up "Low".
        m_score = None
        m_label = "Unknown"
        explanations = []
        if not _model.is_loaded:
            ml_status = "model_not_loaded"
            logger.warning("ML model not loaded: reporting no ML score (baseline is NOT substituted).")
        elif not coverage.has_virustotal:
            ml_status = "insufficient_evidence"
        else:
            ml_status = "ok"
            # XGBoost + SHAP are CPU-bound and synchronous: run them in worker threads so the event loop
            # (SSE heartbeat, other requests) keeps ticking while they work.
            m_score = await asyncio.to_thread(_model.predict_proba, features)
            m_label = _get_ml_label(m_score)
            explanations = await asyncio.to_thread(explain_prediction, _model, features)

        # ── 4b. Neural Fusion Model (char-CNN + tabular) ────────────────
        # Reads the raw URL string, so it can flag lexical phishing patterns
        # even when no external source has ever seen the target (zero-day). It deliberately gets the string
        # *as typed*: it runs locally (nothing leaves the machine) and the very things canonicalisation
        # strips — `paypal.com@evil.example` userinfo, odd casing, encodings — are its lexical signal.
        neural_score = None
        neural_label = None
        neural_url_score = None
        neural_explanations = []
        if _neural_model.is_loaded:
            try:
                neural_score = await asyncio.to_thread(_neural_model.predict_proba, request.target, features)
                neural_label = _get_ml_label(neural_score)
                neural_url_score = await asyncio.to_thread(_neural_model.predict_url_only, request.target)
                # String-lexical explanations only make sense for URL/domain targets.
                if request.target_type in (TargetType.URL, TargetType.DOMAIN):
                    neural_explanations = await asyncio.to_thread(_neural_model.explain_url, request.target)
            except Exception as e:
                logger.warning("Neural fusion scoring failed: %s", e)

        # ── 5. Verdict status + plain-language summary ──────────────────
        verdict_status, verdict_reason = _assess_verdict(outcomes, vt_res)
        summary_text = _build_summary(verdict_status, verdict_reason, m_label, vt, shodan, cve)
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
            features=features,
            feature_coverage=coverage,
            baseline_score=b_score,
            baseline_label=_baseline_label(b_score),
            ml_score=m_score,
            ml_label=m_label,
            ml_status=ml_status,
            neural_score=neural_score,
            neural_label=neural_label,
            neural_url_score=neural_url_score,
            neural_explanations=neural_explanations,
            explanations=explanations,
            attack_paths=attack_paths,
            summary=summary_text,
            provider_results=[o.outcome() for o in outcomes],
            model_versions={
                "xgboost_fusion": model_version("fusion_model.json") if _model.is_loaded else "not_loaded",
                "neural_url": model_version("neural_fusion.pt") if _neural_model.is_loaded else "not_loaded",
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
    result = await _store.get(scan_id)
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
