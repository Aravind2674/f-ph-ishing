"""
ThreatFusion – Pydantic v2 API Schemas
=======================================

This module is the **single source of truth** for every data shape that
enters or leaves the ThreatFusion system.  It is deliberately kept in one
file (rather than split per‑domain) so that:

1.  Circular‑import issues are impossible.
2.  A reviewer (or viva examiner) can read the entire data contract in one
    sitting.
3.  The FastAPI ``/docs`` page auto‑generates from these models, so naming
    and docstrings here directly affect the developer experience.

Conventions
-----------
* ``Field(default_factory=…)`` is used for mutable defaults (lists, dicts)
  to avoid the classic shared‑mutable‑default bug.
* Every ``Field`` carries a ``description`` so the OpenAPI JSON schema is
  self‑documenting.
* Optional fields default to ``None``; this lets the orchestrator skip data
  sources that are unreachable without invalidating the whole response.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Generic, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TargetType(str, Enum):
    """Supported scan‑target types.

    Using ``str, Enum`` (a *value enum*) lets FastAPI serialise the variant
    as a plain string in JSON while still giving us exhaustive matching in
    Python.  This is the idiomatic Pydantic v2 pattern.
    """

    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    FILE_HASH = "file_hash"


class ProviderStatus(str, Enum):
    """Outcome of one provider lookup — five *distinct* states (A0-1).

    The original code collapsed all of these into "an empty result object", which then
    flowed into the feature vector as zeros and was reported as a *successful* query.
    An outage therefore looked exactly like a clean target.  Keeping the states apart is
    what lets the UI say "unavailable" and the verdict say "unknown".
    """

    OK = "ok"                          # the provider answered with usable data
    NOT_FOUND = "not_found"            # the provider answered: it has no record of this target
    ERROR = "error"                    # the lookup failed (auth, rate limit, timeout, 5xx, bad payload…)
    SKIPPED = "skipped"                # deliberately not run (not applicable to this target type)
    NOT_CONFIGURED = "not_configured"  # needs a credential that is missing / still a placeholder


class ProviderOutcome(BaseModel):
    """Provenance of one provider call, *without* its payload (stored with every scan)."""

    source: str = Field(..., description="Provider id, e.g. 'virustotal'")
    status: ProviderStatus
    http_status: Optional[int] = Field(None, description="HTTP status if a response was received")
    reason: Optional[str] = Field(
        None,
        description="Short machine-readable code: auth | rate_limited | timeout | network | "
                    "server_error | bad_request | parse_error | bot_challenge | partial:n/m …",
    )
    fetched_at: datetime = Field(..., description="When the data was fetched (UTC; original time if cached)")
    cached: bool = Field(False, description="True if served from the local cache")
    latency_ms: Optional[float] = Field(None, description="Network latency of the call, if one was made")
    mock: bool = Field(False, description="True if produced by the mock layer, not a real provider")


class ProviderResult(BaseModel, Generic[T]):
    """What every ingestion client returns: data *plus* how we got (or failed to get) it.

    ``data`` is populated only for ``ok`` (and never as a stand-in for a failure).  Note
    that Pydantic models are always truthy, so callers must test ``status``/``ok`` — never
    ``if result:`` (the audit's ``if vt:`` counted a failed lookup as a success).
    """

    source: str
    status: ProviderStatus
    data: Optional[T] = None
    http_status: Optional[int] = None
    reason: Optional[str] = None
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cached: bool = False
    latency_ms: Optional[float] = None
    mock: bool = False

    @property
    def ok(self) -> bool:
        return self.status == ProviderStatus.OK

    def outcome(self) -> ProviderOutcome:
        """Provenance-only view (no payload) for the scan record / API response."""
        return ProviderOutcome(
            source=self.source, status=self.status, http_status=self.http_status,
            reason=self.reason, fetched_at=self.fetched_at, cached=self.cached,
            latency_ms=self.latency_ms, mock=self.mock,
        )


class FeatureCoverage(BaseModel):
    """Which providers actually contributed features (the missingness flags of A0-1).

    These are deliberately *not* part of ``FeatureVector``: the deployed XGBoost artifact
    expects exactly 19 columns in a fixed order.  They are reported next to it and are
    inputs for the retrained model (A2-1).
    """

    has_virustotal: bool = False
    has_shodan: bool = False
    has_cve: bool = False
    has_tech: bool = False


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Request body for initiating a new threat scan.

    The frontend sends this payload to ``POST /api/v1/scan``.  Validation
    is intentionally *loose* at this layer – the orchestrator will apply
    format‑specific checks (e.g. regex for IPv4) after determining the
    ``target_type``.  Keeping validation here minimal avoids rejecting
    edge‑case inputs that are actually valid (e.g. internationalised
    domain names).
    """

    target: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Domain, IP, URL, or file hash to scan",
        examples=["example.com", "8.8.8.8", "https://example.com", "d41d8cd98f00b204e9800998ecf8427e"],
    )
    target_type: TargetType = Field(
        ...,
        description="Type of target being scanned",
    )

    send_full_url: bool = Field(
        False,
        description="Privacy opt-in. By default a URL scan sends third parties (VirusTotal) and the target "
                    "only scheme://host/path — the query string, fragment and credentials are dropped. Set true "
                    "to send the URL exactly as typed.",
    )


# ---------------------------------------------------------------------------
# Per‑source result models
# ---------------------------------------------------------------------------

class VirusTotalResult(BaseModel):
    """Normalised VirusTotal analysis results.

    VirusTotal aggregates verdicts from 70+ antivirus engines.  We store
    the *counts* rather than per‑engine details to keep the payload small
    and the feature‑engineering step straightforward.

    ``reputation_score`` comes from VT's community voting system and ranges
    from −100 (unanimously malicious) to +100 (unanimously harmless).
    """

    malicious_count: int = Field(0, description="Number of engines flagging as malicious")
    harmless_count: int = Field(0, description="Number of engines flagging as harmless")
    suspicious_count: int = Field(0, description="Number of engines flagging as suspicious")
    undetected_count: int = Field(0, description="Number of engines with no detection")
    total_engines: int = Field(0, description="Total number of engines that analysed")
    reputation_score: int = Field(
        0,
        description="VT community reputation score (−100 … +100)",
    )
    last_analysis_date: Optional[datetime] = Field(
        None,
        description="Timestamp of the most recent VT analysis",
    )
    categories: dict[str, str] = Field(
        default_factory=dict,
        description="Engine‑name → category mapping (e.g. 'Fortinet': 'malware')",
    )


class ShodanResult(BaseModel):
    """Normalised Shodan / InternetDB results.

    For IPs we first hit the **free InternetDB** endpoint (no API key) to
    get open ports, CPEs, and known CVE IDs.  If the user supplies a
    Shodan API key we can upgrade to the full ``/shodan/host/{ip}``
    endpoint for richer data.

    ``vulns`` stores CVE IDs (e.g. ``CVE‑2021‑44228``) which are later
    hydrated via the NVD client.
    """

    open_ports: list[int] = Field(
        default_factory=list,
        description="TCP/UDP ports found open on the host",
    )
    hostnames: list[str] = Field(
        default_factory=list,
        description="Reverse‑DNS hostnames associated with the IP",
    )
    cpes: list[str] = Field(
        default_factory=list,
        description="Common Platform Enumeration strings for detected services",
    )
    vulns: list[str] = Field(
        default_factory=list,
        description="CVE IDs of known vulnerabilities on exposed services",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Shodan tags (e.g. 'cloud', 'vpn', 'honeypot')",
    )
    banner_data: list[dict[str, str]] = Field(
        default_factory=list,
        description="Detailed service banners (port, protocol, product, version)",
    )
    org: Optional[str] = Field(None, description="Organization name")
    isp: Optional[str] = Field(None, description="ISP name")
    asn: Optional[str] = Field(None, description="Autonomous System Number")
    country: Optional[str] = Field(None, description="Country location")
    city: Optional[str] = Field(None, description="City location")


class CVEDetail(BaseModel):
    """Details for a single CVE entry.

    Sourced from the NIST NVD API v2.  ``cvss_v3_score`` is preferred but
    may be ``None`` for very old CVEs that only have CVSS v2 data.
    ``severity`` is the qualitative label derived from the CVSS score.
    """

    cve_id: str = Field(
        ...,
        description="CVE identifier, e.g. CVE‑2021‑44228",
    )
    description: str = Field(
        "",
        description="Human‑readable vulnerability description from NVD",
    )
    cvss_v3_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=10.0,
        description="CVSS v3.x base score (0.0–10.0)",
    )
    severity: Optional[str] = Field(
        None,
        description="Qualitative severity: LOW, MEDIUM, HIGH, or CRITICAL",
    )
    published_date: Optional[datetime] = Field(
        None,
        description="Date the CVE was first published",
    )


class CVEResult(BaseModel):
    """Aggregated CVE lookup results.

    ``max_cvss_score`` is pre‑computed here so the feature‑engineering
    step does not have to iterate over the list again.
    """

    cves: list[CVEDetail] = Field(
        default_factory=list,
        description="Individual CVE records",
    )
    total_cves: int = Field(
        0,
        description="Total number of CVEs found",
    )
    max_cvss_score: float = Field(
        0.0,
        ge=0.0,
        le=10.0,
        description="Highest CVSS v3 score among all CVEs",
    )


class DetectedTechnology(BaseModel):
    """A single detected web technology.

    Modelled after the Wappalyzer / webanalyze output format.
    ``confidence`` expresses how certain the detector is – a header‑based
    match is typically 100 %, while a regex on page content may be lower.
    """

    name: str = Field(
        ...,
        description="Technology name (e.g. 'jQuery', 'Nginx')",
    )
    version: Optional[str] = Field(
        None,
        description="Detected version string, if available",
    )
    categories: list[str] = Field(
        default_factory=list,
        description="Wappalyzer category labels (e.g. 'JavaScript frameworks')",
    )
    confidence: int = Field(
        100,
        ge=0,
        le=100,
        description="Detection confidence percentage (0–100)",
    )


class TechFingerprintResult(BaseModel):
    """Web technology fingerprinting results.

    The counts ``headers_analyzed`` and ``scripts_analyzed`` are exposed so
    the UI can show the user how thorough the scan was.
    """

    technologies: list[DetectedTechnology] = Field(
        default_factory=list,
        description="List of detected technologies",
    )
    headers_analyzed: int = Field(
        0,
        description="Number of HTTP response headers inspected",
    )
    scripts_analyzed: int = Field(
        0,
        description="Number of JavaScript file references inspected",
    )


# ---------------------------------------------------------------------------
# Feature‑engineering / ML models
# ---------------------------------------------------------------------------

class FeatureVector(BaseModel):
    """Flat numeric feature vector consumed by both the baseline rule
    scorer and the gradient‑boosted fusion model.

    **Why flat floats?**  Scikit‑learn / XGBoost expect a 1‑D numeric
    array.  Keeping the vector as named fields (rather than a raw list)
    preserves human readability and makes SHAP explanations trivial to
    map back to meaningful labels.

    Each field carries a short security rationale in its ``description``.

    **``None`` means "unknown"** (the provider that would supply it did not answer, or no
    real signal exists yet) — never a neutral constant.  XGBoost receives NaN for it.
    """

    # ── VirusTotal features ──────────────────────────────────────────
    vt_malicious_ratio: Optional[float] = Field(
        0.0,
        description="Fraction of VT engines flagging as malicious (0.0–1.0)",
    )
    vt_suspicious_ratio: Optional[float] = Field(
        0.0,
        description="Fraction of VT engines flagging as suspicious (0.0–1.0)",
    )
    vt_reputation_score: Optional[float] = Field(
        0.0,
        description="Normalised VT community reputation (−100…+100 mapped to 0–1)",
    )
    vt_last_seen_days_ago: Optional[float] = Field(
        0.0,
        description="Days since last VT analysis – stale data is riskier",
    )

    # ── Shodan features ─────────────────────────────────────────────
    shodan_open_port_count: Optional[float] = Field(
        0.0,
        description="Number of open ports – larger attack surface means higher risk",
    )
    shodan_has_high_risk_port: Optional[float] = Field(
        0.0,
        description="1.0 if high‑risk ports (RDP 3389, Telnet 23, SMB 445, …) are open",
    )
    shodan_cve_count: Optional[float] = Field(
        0.0,
        description="Number of known CVEs on exposed services",
    )
    shodan_max_cvss_score: Optional[float] = Field(
        0.0,
        description="Highest CVSS score among known CVEs (0.0–10.0)",
    )
    shodan_has_iot_tag: Optional[float] = Field(
        0.0,
        description="1.0 if host is tagged as IoT",
    )
    shodan_has_compromised_tag: Optional[float] = Field(
        0.0,
        description="1.0 if host is tagged as compromised",
    )
    shodan_service_diversity_score: Optional[float] = Field(
        0.0,
        description="Count of distinct product types exposed",
    )
    shodan_high_risk_cpe_count: Optional[float] = Field(
        0.0,
        description="Number of CPEs matching high-risk software (e.g., outdated servers)",
    )

    # ── Technology fingerprint features ──────────────────────────────
    tech_count: Optional[float] = Field(
        0.0,
        description="Number of detected technologies",
    )
    tech_has_known_eol_component: Optional[float] = Field(
        0.0,
        description="1.0 if any end‑of‑life technology is detected",
    )
    tech_avg_confidence: Optional[float] = Field(
        0.0,
        description="Average detection confidence across technologies (0.0–1.0)",
    )
    tech_stack_diversity_count: Optional[float] = Field(
        0.0,
        description="Count of distinct tech categories (e.g. CMS + DB + Server = 3)",
    )
    tech_has_eol_cms_version: Optional[float] = Field(
        0.0,
        description="1.0 if an outdated/EOL CMS is specifically detected",
    )

    # ── Supplementary features ───────────────────────────────────────
    ssl_cert_valid: Optional[float] = Field(
        1.0,
        description="1.0 if the SSL/TLS certificate is valid, 0.0 otherwise",
    )
    domain_age_days: Optional[float] = Field(
        0.0,
        description="Age of the domain in days – newly registered domains are riskier",
    )


class RiskExplanation(BaseModel):
    """SHAP‑based explanation for a single feature's contribution to the
    predicted risk score.

    The frontend renders these as a waterfall chart so users can see
    *which* data source drove the score up or down.

    ``shap_value`` > 0 means the feature **increased** the predicted risk;
    ``shap_value`` < 0 means it **decreased** the risk.
    """

    feature_name: str = Field(
        ...,
        description="Machine‑readable feature name matching FeatureVector field",
    )
    feature_value: Optional[float] = Field(
        None,
        description="The actual numeric value of the feature for this scan (None = unknown)",
    )
    shap_value: float = Field(
        ...,
        description="SHAP value: positive = increases risk, negative = decreases risk",
    )
    human_readable: str = Field(
        ...,
        description="Plain‑English explanation, e.g. 'Open RDP port (+0.31 risk)'",
    )


class NeuralExplanation(BaseModel):
    """A suspicious substring surfaced by the character-level neural model.

    Produced by :class:`~app.ml.neural_fusion.NeuralFusionModel.explain_url`
    via per-character saliency. Unlike ``RiskExplanation`` (which attributes the
    score to *tabular* features), this points at the exact span of the URL
    *string* that drove the lexical phishing signal — e.g. a ``paypa1``
    look-alike token or a suspicious ``-verify-account`` chain.
    """

    substring: str = Field(
        ...,
        description="The high-attention substring of the URL",
    )
    start: int = Field(..., description="Start character index within the URL")
    end: int = Field(..., description="End character index (exclusive)")
    importance: float = Field(
        ...,
        description="Normalised saliency in [0, 1]; higher = stronger phishing signal",
    )
    human_readable: str = Field(
        ...,
        description="Plain-English explanation of the substring's contribution",
    )


# ---------------------------------------------------------------------------
# Composite / orchestrator‑level models
# ---------------------------------------------------------------------------

class ScanResult(BaseModel):
    """Complete scan result combining all data sources, engineered features,
    model scores, and SHAP explanations.

    This is the *core* data object of the entire system.  The orchestrator
    builds it incrementally:

    1. Populate ``virustotal``, ``shodan``, ``cve``, ``tech_fingerprint``.
    2. Run feature engineering → ``features``.
    3. Run baseline scorer → ``baseline_score``.
    4. Run ML fusion model → ``ml_score``, ``ml_label``.
    5. Run SHAP explainer → ``explanations``.

    If a data source fails, its field stays ``None`` and the source name is
    appended to ``data_sources_failed`` so the frontend can display a
    partial‑result warning.
    """

    scan_id: str = Field(
        ...,
        description="Unique scan identifier (UUID4 hex string)",
    )
    target: str = Field(
        ...,
        description="The original target that was scanned",
    )
    target_type: TargetType = Field(
        ...,
        description="Type of the scanned target",
    )
    timestamp: datetime = Field(
        ...,
        description="UTC timestamp when the scan was initiated",
    )

    # ── Raw data from each source ────────────────────────────────────
    virustotal: Optional[VirusTotalResult] = Field(
        None,
        description="VirusTotal analysis results (None if source failed)",
    )
    shodan: Optional[ShodanResult] = Field(
        None,
        description="Shodan / InternetDB results (None if source failed)",
    )
    cve: Optional[CVEResult] = Field(
        None,
        description="NVD CVE lookup results (None if source failed)",
    )
    tech_fingerprint: Optional[TechFingerprintResult] = Field(
        None,
        description="Technology fingerprinting results (None if source failed)",
    )

    # ── Engineered features ──────────────────────────────────────────
    features: Optional[FeatureVector] = Field(
        None,
        description="Numeric feature vector derived from raw source data",
    )

    # ── Scores ───────────────────────────────────────────────────────
    baseline_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Rule‑based heuristic score (0 = safe, 1 = critical)",
    )
    baseline_label: Optional[str] = Field(
        None,
        description="Low / Medium / High / Critical band of baseline_score; 'Unknown' if no evidence",
    )
    ml_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="ML fusion model predicted probability (0 = safe, 1 = critical)",
    )
    ml_label: Optional[str] = Field(
        None,
        description="Human‑readable risk label: low / medium / high / critical",
    )

    # ── Neural fusion model (char-CNN + tabular) ─────────────────────
    neural_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Neural fusion risk probability from URL string + tabular features",
    )
    neural_label: Optional[str] = Field(
        None,
        description="Human-readable neural risk label: Low / Medium / High / Critical",
    )
    neural_url_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="URL-string-only neural risk (no enrichment) — the zero-day signal",
    )
    neural_explanations: list[NeuralExplanation] = Field(
        default_factory=list,
        description="Suspicious URL substrings from character-level saliency",
    )

    # ── Explanations ─────────────────────────────────────────────────
    explanations: list[RiskExplanation] = Field(
        default_factory=list,
        description="SHAP‑based per‑feature risk explanations",
    )

    attack_paths: Optional[list[AttackPath]] = Field(
        None,
        description="Discovered vulnerability chains and attack paths",
    )

    # ── Metadata ─────────────────────────────────────────────────────
    data_sources_succeeded: list[str] = Field(
        default_factory=list,
        description="Names of data sources that returned successfully",
    )
    data_sources_failed: list[str] = Field(
        default_factory=list,
        description="Names of data sources that timed out or errored",
    )
    data_sources_not_found: list[str] = Field(
        default_factory=list,
        description="Sources that answered 'no record of this target' (a real answer, but no evidence)",
    )
    data_sources_skipped: list[str] = Field(
        default_factory=list,
        description="Data sources that were not called because they are not configured "
                    "(missing/placeholder credential). Distinct from failed: nothing was attempted.",
    )
    summary: Optional[str] = Field(
        None,
        description="Plain-language summary that never claims more than the evidence supports",
    )
    model_versions: dict[str, str] = Field(
        default_factory=dict,
        description="Model artifact versions (sha256[:12] from the manifest) that produced this result; "
                    "'not_loaded' for a model that was unavailable",
    )
    feature_schema_version: int = Field(
        0, description="Version of the feature semantics used (see ml.features.FEATURE_SCHEMA_VERSION)",
    )
    app_version: Optional[str] = Field(None, description="Backend version that produced this result")
    provider_results: list[ProviderOutcome] = Field(
        default_factory=list,
        description="Per-provider provenance: status, HTTP status, reason, fetched_at, cached, latency",
    )
    feature_coverage: Optional[FeatureCoverage] = Field(
        None, description="Which providers contributed features (missingness flags)",
    )
    verdict_status: str = Field(
        "ok",
        description="ok = every applicable source answered | partial = some did not | "
                    "unknown = no reputation evidence at all (never shown as 'Low')",
    )
    verdict_reason: Optional[str] = Field(None, description="Human-readable reason for partial/unknown")
    ml_status: Optional[str] = Field(
        None, description="ok | model_not_loaded | insufficient_evidence",
    )
    mock_mode: bool = Field(
        False,
        description="True when the scan used mock/synthetic data instead of live APIs",
    )


class ScanResponse(BaseModel):
    """Top‑level API response wrapper for scan results.

    Using a wrapper (rather than returning ``ScanResult`` directly) lets
    us return a uniform ``{success, result, error}`` shape for both happy
    and error paths, which simplifies frontend parsing.
    """

    success: bool = Field(True, description="Whether the scan completed without fatal errors")
    result: Optional[ScanResult] = Field(None, description="Full scan result, if successful")
    error: Optional[str] = Field(None, description="Error message, if the scan failed")


class ScanHistoryItem(BaseModel):
    """Abbreviated scan record for the history / dashboard list view.

    Intentionally excludes bulky nested data (raw source results,
    explanations) to keep the ``GET /api/v1/history`` response lightweight.
    """

    scan_id: str
    target: str
    target_type: TargetType
    timestamp: datetime
    baseline_score: Optional[float] = None
    baseline_label: Optional[str] = None
    ml_score: Optional[float] = None
    ml_label: Optional[str] = None
    neural_score: Optional[float] = None
    neural_label: Optional[str] = None


class AttackChainNode(BaseModel):
    """A single node representing a vulnerability in an attack chain."""

    cve_id: str = Field(..., description="CVE ID, e.g. CVE-2021-44228")
    cvss_score: Optional[float] = Field(None, description="CVSS base score")
    epss_score: float = Field(0.0, description="EPSS exploitation probability score")
    is_in_kev: bool = Field(False, description="Whether the CVE is in CISA KEV catalog")
    exploit_db_id: Optional[str] = Field(None, description="Exploit-DB script ID if available")
    pre_conditions: list[str] = Field(default_factory=list, description="Conditions required to exploit")
    post_conditions: list[str] = Field(default_factory=list, description="State changes after exploitation")
    description: str = Field("", description="Brief vulnerability description")


class AttackPath(BaseModel):
    """A logical path of chained vulnerabilities leading to a potential compromise."""

    path_id: str = Field(..., description="Unique identifier for the attack path")
    nodes: list[AttackChainNode] = Field(default_factory=list, description="Sequence of chained vulnerability nodes")
    total_risk_score: float = Field(0.0, description="Aggregated risk probability (0.0-1.0)")
    summary: str = Field("", description="Human-readable description of the attack sequence")


class HealthResponse(BaseModel):
    """Health‑check response for ``GET /api/v1/health``.

    Consumed by uptime monitors and the React frontend's connection
    indicator.  ``mock_mode`` tells the UI to display a banner warning
    that live API keys are not configured.
    """

    status: str = Field("healthy", description="Service status string")
    version: str = Field("0.1.0", description="Semantic version of the backend")
    mock_mode: bool = Field(
        True,
        description="True when running with mock data (no live API keys configured)",
    )


# ---------------------------------------------------------------------------
# Phase 2 — HTTP request / payload analysis (neural attack classifier)
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Request body for ``POST /analyze``.

    ``text`` may be a single parameter value, a raw query string, or a full URL.
    The endpoint classifies the value(s) with the neural HTTP attack classifier.
    This is **passive** analysis of text the caller submits — it performs no
    network requests against any target.
    """

    text: str = Field(
        ...,
        min_length=1,
        max_length=8192,
        description="A payload, query string, or URL to analyse for injection patterns",
        examples=["id=1' OR '1'='1", "q=<script>alert(1)</script>", "https://x.com/p?file=../../etc/passwd"],
    )


class PayloadFinding(BaseModel):
    """One classifier verdict for a single analysed value."""

    input: str = Field(..., description="The exact value that was classified")
    location: str = Field(
        ...,
        description="Where the value came from: 'full' or 'param:<name>'",
    )
    label: str = Field(..., description="Predicted class: benign / sqli / xss / path-traversal / cmdi")
    is_attack: bool = Field(..., description="True when the predicted class is not benign")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Softmax confidence of the predicted class")
    suspicious_span: Optional[str] = Field(
        None, description="Highest-saliency substring driving an attack verdict"
    )
    probs: dict[str, float] = Field(
        default_factory=dict, description="Full per-class probability distribution"
    )


class AnalyzeResponse(BaseModel):
    """Top-level response for ``POST /analyze``."""

    success: bool = Field(True, description="Whether analysis completed")
    model_loaded: bool = Field(
        True, description="False when the classifier checkpoint is unavailable"
    )
    findings: list[PayloadFinding] = Field(
        default_factory=list, description="Per-value classifier verdicts, most severe first"
    )
    summary: str = Field("", description="Plain-language summary of the worst finding")
    error: Optional[str] = Field(None, description="Error message, if analysis failed")


# ---------------------------------------------------------------------------
# Phase 3 — captured-traffic analysis
# ---------------------------------------------------------------------------

class CapturedRequestModel(BaseModel):
    """One captured HTTP request submitted for analysis."""

    method: str = Field("GET", description="HTTP method")
    url: str = Field(..., min_length=1, description="Full request URL")
    headers: dict[str, str] = Field(default_factory=dict, description="Request headers")
    body: Optional[str] = Field(None, description="Raw request body, if any")


class TrafficAnalyzeRequest(BaseModel):
    """Batch of captured requests, or a HAR export, to analyse.

    Supply ``requests`` (a normalised batch, e.g. from the mitmproxy addon) or
    ``har`` (a HAR document exported by Burp / DevTools / ZAP). At least one is
    required.
    """

    requests: list[CapturedRequestModel] = Field(
        default_factory=list, description="Normalised captured requests"
    )
    har: Optional[dict] = Field(
        None, description="A HAR document ({log:{entries:[...]}}) to parse"
    )


class ValueFindingModel(BaseModel):
    """Classifier verdict for one attacker-controlled value within a request."""

    location: str = Field(..., description="Where the value came from, e.g. 'query:id', 'body:user', 'path'")
    value: str = Field(..., description="The exact value classified")
    label: str = Field(..., description="benign / sqli / xss / path-traversal / cmdi")
    is_attack: bool = Field(..., description="True when not benign")
    confidence: float = Field(..., ge=0.0, le=1.0)
    suspicious_span: Optional[str] = Field(None, description="Highest-saliency substring")


class RequestFindingModel(BaseModel):
    """Aggregated verdict for a whole captured request (its worst value)."""

    method: str
    url: str
    is_attack: bool = Field(..., description="True if any value in the request is an attack")
    worst_label: str = Field(..., description="Most severe class found in the request")
    worst_location: str = Field("", description="Where the worst value was found")
    worst_confidence: float = Field(0.0, ge=0.0, le=1.0)
    suspicious_span: Optional[str] = None
    values_analyzed: int = Field(0, description="Number of values classified in this request")
    attack_values: int = Field(0, description="How many of them were attacks")
    details: list[ValueFindingModel] = Field(default_factory=list)


class TrafficAnalyzeResponse(BaseModel):
    """Top-level response for ``POST /traffic/analyze``."""

    success: bool = True
    model_loaded: bool = Field(True, description="False when the classifier is unavailable")
    analyzed: int = Field(0, description="Number of requests analysed")
    flagged: int = Field(0, description="Number of requests containing an attack")
    findings: list[RequestFindingModel] = Field(
        default_factory=list, description="Per-request verdicts, most severe first"
    )
    summary: str = Field("", description="Plain-language summary of the capture")
    error: Optional[str] = Field(None, description="Error message, if analysis failed")


# ---------------------------------------------------------------------------
# Phase 4 — active verification (scope-gated, non-destructive)
# ---------------------------------------------------------------------------

class VerifyRequest(BaseModel):
    """Request body for ``POST /verify``.

    ``target`` is the URL (with query parameters) to actively confirm. Probing is
    **default-deny**: it only runs against localhost, or a host listed in
    ``authorized_hosts`` — by which the caller attests it is authorised to test
    that host. Anything else is refused before any request is sent.
    """

    target: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Target URL (with query params) to verify — localhost/authorised only",
        examples=["http://127.0.0.1:8099/search?q=test"],
    )
    authorized_hosts: list[str] = Field(
        default_factory=list,
        description="Hosts you attest you are authorised to actively test (adds to localhost)",
    )


class ProbeResultModel(BaseModel):
    """Outcome of one non-destructive active check against one parameter."""

    param: str = Field(..., description="The parameter probed")
    technique: str = Field(..., description="reflected-xss / error-sqli / boolean-sqli")
    confirmed: bool = Field(..., description="True if the vulnerability was confirmed")
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: str = Field(..., description="Human-readable evidence for the verdict")
    payload: str = Field(..., description="The non-destructive probe value used")


class VerifyResponse(BaseModel):
    """Top-level response for ``POST /verify``."""

    success: bool = True
    authorized: bool = Field(..., description="False when the target host was out of scope")
    target: str = Field(..., description="The URL that was (or would have been) probed")
    tested_params: list[str] = Field(default_factory=list)
    confirmed_count: int = Field(0, description="Number of confirmed vulnerabilities")
    probes: list[ProbeResultModel] = Field(default_factory=list)
    summary: str = Field("", description="Plain-language summary")
    error: Optional[str] = Field(None, description="Scope refusal or other error")
    notice: Optional[str] = Field(
        None,
        description="Informational note, e.g. that `authorized_hosts` in the request was ignored",
    )


# ---------------------------------------------------------------------------
# Forward-reference resolution
# ---------------------------------------------------------------------------
# ``ScanResult`` references ``AttackPath`` / ``AttackChainNode`` and
# ``NeuralExplanation`` which are declared later in / earlier in this module.
# Combined with ``from __future__ import annotations`` (all annotations become
# strings), some pydantic/FastAPI versions fail to resolve these lazily during
# response-model schema generation ("name 'Optional' is not defined"). Rebuilding
# the affected models now — once every symbol in this module exists — resolves
# the references deterministically at import time.
ScanResult.model_rebuild()
ScanResponse.model_rebuild()
ScanHistoryItem.model_rebuild()

