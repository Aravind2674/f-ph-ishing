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

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


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
    """

    # ── VirusTotal features ──────────────────────────────────────────
    vt_malicious_ratio: float = Field(
        0.0,
        description="Fraction of VT engines flagging as malicious (0.0–1.0)",
    )
    vt_suspicious_ratio: float = Field(
        0.0,
        description="Fraction of VT engines flagging as suspicious (0.0–1.0)",
    )
    vt_reputation_score: float = Field(
        0.0,
        description="Normalised VT community reputation (−100…+100 mapped to 0–1)",
    )
    vt_last_seen_days_ago: float = Field(
        0.0,
        description="Days since last VT analysis – stale data is riskier",
    )

    # ── Shodan features ─────────────────────────────────────────────
    shodan_open_port_count: float = Field(
        0.0,
        description="Number of open ports – larger attack surface means higher risk",
    )
    shodan_has_high_risk_port: float = Field(
        0.0,
        description="1.0 if high‑risk ports (RDP 3389, Telnet 23, SMB 445, …) are open",
    )
    shodan_cve_count: float = Field(
        0.0,
        description="Number of known CVEs on exposed services",
    )
    shodan_max_cvss_score: float = Field(
        0.0,
        description="Highest CVSS score among known CVEs (0.0–10.0)",
    )
    shodan_has_iot_tag: float = Field(
        0.0,
        description="1.0 if host is tagged as IoT",
    )
    shodan_has_compromised_tag: float = Field(
        0.0,
        description="1.0 if host is tagged as compromised",
    )
    shodan_service_diversity_score: float = Field(
        0.0,
        description="Count of distinct product types exposed",
    )
    shodan_high_risk_cpe_count: float = Field(
        0.0,
        description="Number of CPEs matching high-risk software (e.g., outdated servers)",
    )

    # ── Technology fingerprint features ──────────────────────────────
    tech_count: float = Field(
        0.0,
        description="Number of detected technologies",
    )
    tech_has_known_eol_component: float = Field(
        0.0,
        description="1.0 if any end‑of‑life technology is detected",
    )
    tech_avg_confidence: float = Field(
        0.0,
        description="Average detection confidence across technologies (0.0–1.0)",
    )
    tech_stack_diversity_count: float = Field(
        0.0,
        description="Count of distinct tech categories (e.g. CMS + DB + Server = 3)",
    )
    tech_has_eol_cms_version: float = Field(
        0.0,
        description="1.0 if an outdated/EOL CMS is specifically detected",
    )

    # ── Supplementary features ───────────────────────────────────────
    ssl_cert_valid: float = Field(
        1.0,
        description="1.0 if the SSL/TLS certificate is valid, 0.0 otherwise",
    )
    domain_age_days: float = Field(
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
    feature_value: float = Field(
        ...,
        description="The actual numeric value of the feature for this scan",
    )
    shap_value: float = Field(
        ...,
        description="SHAP value: positive = increases risk, negative = decreases risk",
    )
    human_readable: str = Field(
        ...,
        description="Plain‑English explanation, e.g. 'Open RDP port (+0.31 risk)'",
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

    # ── Explanations ─────────────────────────────────────────────────
    explanations: list[RiskExplanation] = Field(
        default_factory=list,
        description="SHAP‑based per‑feature risk explanations",
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
    ml_score: Optional[float] = None
    ml_label: Optional[str] = None


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
