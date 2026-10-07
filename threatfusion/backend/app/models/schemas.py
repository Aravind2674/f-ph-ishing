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
from typing import Generic, Literal, Optional, TypeVar

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
    retry_after: Optional[float] = Field(
        None, description="Seconds until the provider's quota allows another call (rate_limited only)")


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
    retry_after: Optional[float] = Field(
        None, description="Seconds until the provider's quota allows another call (rate_limited only)")

    @property
    def ok(self) -> bool:
        return self.status == ProviderStatus.OK

    def outcome(self) -> ProviderOutcome:
        """Provenance-only view (no payload) for the scan record / API response."""
        return ProviderOutcome(
            source=self.source, status=self.status, http_status=self.http_status,
            reason=self.reason, fetched_at=self.fetched_at, cached=self.cached,
            latency_ms=self.latency_ms, mock=self.mock, retry_after=self.retry_after,
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
    # Host signals (A1-3): the TLS certificate, the RDAP/WHOIS registration record and DNS records.
    has_tls: bool = False
    has_rdap: bool = False
    has_dns: bool = False
    # Certificate-transparency history (B3): reported, not yet an input of the deployed models (retrain: A2-1).
    has_ct: bool = False


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

    scan_id: Optional[str] = Field(
        None,
        pattern=r"^[A-Za-z0-9_-]{8,64}$",
        description="Optional client-chosen id (8-64 chars of A-Z a-z 0-9 _ -), so a client can open "
                    "GET /scan/{id}/events *before* it POSTs and watch the scan live. Must be unused (409 otherwise). "
                    "Generated by the server when omitted.",
    )

    send_full_url: bool = Field(
        False,
        description="Privacy opt-in. By default a URL scan sends third parties (VirusTotal) and the target "
                    "only scheme://host/path — the query string, fragment and credentials are dropped. Set true "
                    "to send the URL exactly as typed.",
    )
    mode: Literal["sync", "async"] = Field(
        "sync",
        description="sync (default, unchanged): the response carries the full result. async (B1): the response carries the "
                    "fast-tier verdict and a scan_id immediately; the slow tier runs as a background job (follow it over "
                    "GET /scan/{id}/events, fetch it with GET /scan/{id}).",
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
    reputation_score: Optional[int] = Field(
        None,
        description="VT community reputation score (−100 … +100); None when VirusTotal did not report one",
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
    max_cvss_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=10.0,
        description="Highest CVSS v3 score among the CVEs that have one; None when none of them is scored (never 0.0)",
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
        description="Wappalyzer's own confidence (sum of the matching patterns' confidences, capped at 100); "
                    "50 for an *implied* technology (inferred, not observed)",
    )
    implied: bool = Field(False, description="Inferred from another technology (Wappalyzer 'implies'), not observed")
    # Lifecycle (A1-4, from endoflife.date). None = unknown: no version, no mapping, or the lookup failed.
    eol: Optional[bool] = Field(None, description="True = this release is end-of-life; False = supported; None = unknown")
    eol_date: Optional[str] = Field(None, description="ISO date this release cycle reaches/reached end of life")
    eol_cycle: Optional[str] = Field(None, description="The endoflife.date release cycle the version was matched to")
    latest_version: Optional[str] = Field(None, description="Latest release of that cycle, per endoflife.date")


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
    eol_assessed: int = Field(
        0,
        description="How many technologies got a lifecycle verdict (eol true/false) from endoflife.date",
    )


# ---------------------------------------------------------------------------
# Feature‑engineering / ML models
# ---------------------------------------------------------------------------

class TlsInfo(BaseModel):
    """What the host's TLS endpoint (port 443) really presents (A1-3, ``ingestion/tls.py``).

    Everything is *observed*, nothing is assumed: ``chain_valid`` is OpenSSL's verdict on the chain **and** the
    host name against the system trust store; the certificate fields are read from the certificate itself (also
    when verification failed — an expired or self-signed certificate is still parsed, which is how the UI can say
    *why* it is invalid).  Dates are stored, ``days_to_expiry`` / ``cert_age_days`` are derived at use time
    (``ingestion/tls.py``) so a cached record keeps ageing correctly.
    """

    host: str
    has_tls: bool = Field(True, description="False when nothing on :443 speaks TLS (refused / plain HTTP)")
    chain_valid: Optional[bool] = Field(None, description="Chain + host name verified against the trust store")
    verify_error: Optional[str] = Field(
        None, description="expired | self_signed | self_signed_in_chain | unknown_issuer | hostname_mismatch | verify_failed:<code>")
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    san_matches_host: Optional[bool] = Field(None, description="The certificate's names (SAN, else CN) cover the host")
    san_names: list[str] = Field(default_factory=list)
    self_signed: Optional[bool] = None
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    validation_level: Optional[str] = Field(None, description="dv | ov | ev | iv — from the CA/B certificate-policy OIDs")
    issuer_type: Optional[str] = Field(None, description="free_dv | paid_dv | ov | ev | unknown")
    tls_version: Optional[str] = None
    key_type: Optional[str] = None
    key_bits: Optional[int] = None


class RdapInfo(BaseModel):
    """Registration data for a registered domain (A1-3, ``ingestion/rdap.py``): the source of the real domain age.

    ``registered_at`` is stored (not the age) so a cached record keeps ageing; ``None`` means the registry did
    not publish a registration date — the age is then *unknown*, never 0.
    """

    domain: str
    registered_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_changed_at: Optional[datetime] = None
    registrar: Optional[str] = None
    statuses: list[str] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)
    source: str = Field("rdap", description="rdap | whois (WHOIS only where the TLD has no RDAP service)")
    server: Optional[str] = Field(None, description="The RDAP/WHOIS server that answered")


class CtCert(BaseModel):
    """One certificate from the public Certificate Transparency logs (kept small: times and issuer only)."""

    logged_at: Optional[datetime] = None
    not_before: Optional[datetime] = None
    issuer: Optional[str] = None


class CtInfo(BaseModel):
    """Certificate-transparency history of a host (B3, ``ingestion/ct.py``, via crt.sh).

    A phishing site almost always gets a certificate *just before* it goes live, and kits often put several brand-like names
    on one certificate; an established site has years of them.  ``first_seen`` is stored (not the age) so a cached record
    keeps ageing; the ``cert_*`` fields are re-derived on every read (``ct.derive``).  First-seen-in-CT is *not* the
    registration date: a domain can exist for years without a certificate (RDAP gives the registration).
    """

    host: str
    certs_total: int = Field(0, description="Distinct certificates crt.sh returned for the host")
    certs: list[CtCert] = Field(default_factory=list, description="Newest first, capped")
    san_names: list[str] = Field(default_factory=list, description="Distinct names across those certificates, capped")
    first_seen: Optional[datetime] = None
    truncated: bool = Field(False, description="More certificates exist than are kept: counts are lower bounds")
    # ── derived on read (never trusted from a cache) ──
    cert_first_seen_days: Optional[float] = Field(None, description="Days since the earliest certificate was logged")
    cert_count_30d: Optional[int] = Field(None, description="Certificates logged in the last 30 days")
    latest_issuer: Optional[str] = None
    issuer_is_free_dv: Optional[bool] = Field(
        None, description="The newest certificate comes from a free / automated DV issuer (common on legitimate sites too)")
    san_brand_hits: list[str] = Field(default_factory=list, description="'name -> Brand' for SAN names that imitate a protected brand")
    san_brand_keyword_hits: int = 0


class DnsInfo(BaseModel):
    """DNS facts about the host (A1-3, ``ingestion/dns_records.py``).

    Each record family is **three-state**: a list when the lookup answered (``[]`` = the zone has none), ``None``
    when the lookup *failed* (listed in ``failed_types``).  ``spf`` / ``dmarc`` follow the same rule.
    """

    host: str
    lookup_domain: str = Field(..., description="The registered domain MX/NS/TXT/CAA/DMARC were read from")
    a: Optional[list[str]] = None
    aaaa: Optional[list[str]] = None
    mx: Optional[list[str]] = None
    ns: Optional[list[str]] = None
    txt: Optional[list[str]] = None
    caa: Optional[list[str]] = None
    spf: Optional[bool] = None
    spf_record: Optional[str] = None
    dmarc: Optional[bool] = None
    dmarc_policy: Optional[str] = None
    asn: Optional[int] = Field(None, description="Hosting autonomous system of the first public address")
    asn_org: Optional[str] = None
    asn_prefix: Optional[str] = None
    asn_country: Optional[str] = None
    failed_types: list[str] = Field(default_factory=list)


# ── Exploit-informed exposure (B11) ─────────────────────────────────────────
class EpssRow(BaseModel):
    """One EPSS answer (FIRST.org): the 30-day exploitation probability and its percentile."""

    epss: float = Field(..., ge=0.0, le=1.0)
    percentile: float = Field(..., ge=0.0, le=1.0)
    date: Optional[str] = Field(None, description="The EPSS model date this score is from (ISO date)")


class KevRow(BaseModel):
    """One CISA Known Exploited Vulnerabilities entry."""

    date_added: Optional[str] = None
    due_date: Optional[str] = None
    ransomware: bool = Field(False, description="knownRansomwareCampaignUse == 'Known'")
    vendor: Optional[str] = None
    product: Optional[str] = None
    name: Optional[str] = None


class SsvcRow(BaseModel):
    """CISA Vulnrichment's SSVC decision points for one CVE (CISA-ADP container of the CVE JSON 5 record)."""

    exploitation: Optional[str] = Field(None, description="none | poc | active")
    automatable: Optional[str] = Field(None, description="yes | no")
    technical_impact: Optional[str] = Field(None, description="partial | total")
    timestamp: Optional[str] = None


class ExposureCve(BaseModel):
    """The exploitation evidence for one CVE listed on the host (``None`` = unknown, never 0)."""

    cve_id: str
    cvss: Optional[float] = Field(None, description="Severity — shown for context, not folded into exposure")
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: Optional[str] = None
    in_kev: Optional[bool] = Field(None, description="None = the KEV feed was unavailable")
    kev_ransomware: Optional[bool] = None
    kev_date_added: Optional[str] = None
    ssvc_exploitation: Optional[str] = None
    ssvc_automatable: Optional[str] = None
    ssvc_technical_impact: Optional[str] = None
    category: Optional[str] = Field(None, description="SSVC-style: Track | Track* | Attend | Act (None = not assessable)")
    probability: Optional[float] = Field(None, description="Estimated probability of exploitation: KEV 0.95/0.99, else EPSS")
    basis: list[str] = Field(default_factory=list)


class ExposureAssessment(BaseModel):
    """How exposed the host is to *likely-to-be-exploited* vulnerabilities — separate from maliciousness (B11)."""

    score: Optional[float] = Field(None, description="0-100: probability that at least one listed CVE is exploited "
                                                      "(noisy-OR); None = could not be assessed")
    category: Optional[str] = Field(None, description="Worst SSVC-style category among the CVEs")
    cves_total: int = 0
    cves_assessed: int = Field(0, description="CVEs for which an exploitation probability could be computed")
    complete: bool = False
    kev_count: int = 0
    max_epss: Optional[float] = None
    cves: list[ExposureCve] = Field(default_factory=list, description="Worst first")
    notes: list[str] = Field(default_factory=list)
    method: str = ""
    feed_ages: dict[str, Optional[float]] = Field(default_factory=dict, description="Age in days of the local feeds used")


# ── Independent reputation channels (B2) ────────────────────────────────────
class ReputationVerdict(BaseModel):
    """What one independent reputation source says about the target (``ingestion/reputation.py`` / ``blocklists.py``).

    ``listed`` is only ever ``True`` when the source *positively* says the target is bad (a blocklist hit, an abuse score at
    or above the threshold, a malicious rating). A source with no record is a ``not_found`` outcome: "not listed" is the
    absence of evidence, never a clean bill of health. Popularity (Tranco) and scanner context (GreyNoise) are carried in
    ``category`` / ``extra`` and never set ``listed``.
    """

    source: str
    listed: bool = False
    category: Optional[str] = Field(None, description="phishing | malware | social_engineering | botnet_c2 | abuse | "
                                                      "threat_intel | scanner | benign | popular")
    match: Optional[str] = Field(None, description="exact_url | host | ip | ioc: how the record matched the target")
    score: Optional[float] = Field(None, description="The source's own 0-100 score where it gives one (e.g. AbuseIPDB)")
    detail: Optional[str] = None
    reference: Optional[str] = Field(None, description="Public report / pulse / scan page for the record")
    last_seen: Optional[str] = None
    feed_age_days: Optional[float] = Field(None, description="Age of the local feed this answer came from")
    stale: bool = False
    extra: dict[str, Optional[str | int | float | bool]] = Field(default_factory=dict)


class ReputationSummary(BaseModel):
    """All independent reputation answers for the scan, side by side (B2): kept apart from the maliciousness scores."""

    channels_applicable: int = 0
    channels_answered: int = Field(0, description="Channels that gave an answer (listed or not found); the rest are gaps")
    listed_by: list[str] = Field(default_factory=list)
    verdicts: list[ReputationVerdict] = Field(default_factory=list)
    popularity_rank: Optional[int] = Field(None, description="Tranco rank of the registered domain (a popularity prior)")
    feed_ages: dict[str, Optional[float]] = Field(default_factory=dict, description="Days since each local feed was fetched")
    notes: list[str] = Field(default_factory=list)


# ── Brand impersonation (B4) ────────────────────────────────────────────────
LookalikeKind = Literal["homoglyph", "leetspeak", "typo", "separator", "brand_keyword", "brand_in_subdomain",
                        "same_name_other_tld", "contains_brand"]


class LookalikeMatch(BaseModel):
    """One protected brand this domain resembles, and the evidence for it."""

    brand: str
    brand_domain: str = Field(..., description="The brand's primary official domain")
    sector: str
    country: Optional[str] = None
    source: Literal["curated", "popular"] = "curated"
    kind: LookalikeKind
    similarity: float = Field(..., ge=0.0, le=1.0,
                              description="Rule score for the *kind* of resemblance — a heuristic, not a probability")
    distance: Optional[int] = Field(None, description="Edit distance, for typo matches")
    matched: str = Field("", description="The part of the host that resembles the brand (label, token or subdomain)")
    evidence: list[str] = Field(default_factory=list)
    mixed_script: bool = Field(False, description="A label mixes scripts (e.g. Latin + Cyrillic) — the homograph signature")


class BrandCheck(BaseModel):
    """Is this host impersonating a protected brand? (B4) — ``lookalike_of`` is ``match`` when ``status == 'lookalike'``."""

    status: Literal["lookalike", "official", "no_match"]
    match: Optional[LookalikeMatch] = None
    official_of: Optional[str] = Field(None, description="Set when the host is one of the brand's own domains")
    candidates: list[LookalikeMatch] = Field(default_factory=list,
                                             description="Weaker resemblances below the flagging threshold")
    brands_checked: int = Field(0, description="Curated brands compared")
    popular_checked: int = Field(0, description="Popular (Tranco) domains compared in addition")
    threshold: float = 0.8
    notes: list[str] = Field(default_factory=list)


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
        description="1.0 if any detected technology release is end-of-life per endoflife.date; 0.0 if none is "
                    "(or nothing was detected); null when technologies were detected but none could be assessed",
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
        description="1.0 if a detected CMS release is end-of-life; 0.0 if the CMS (if any) is supported; null when "
                    "a CMS was detected but could not be assessed",
    )

    # ── Supplementary features ───────────────────────────────────────
    ssl_cert_valid: Optional[float] = Field(
        None,
        description="1.0 if the host presents a currently valid, name-matching certificate, 0.0 if it presents an "
                    "invalid one or no TLS at all; null when TLS was not probed (A1-3)",
    )
    domain_age_days: Optional[float] = Field(
        None,
        description="Age of the registered domain in days from its RDAP/WHOIS registration date; null when unknown "
                    "(never 0) — newly registered domains are riskier",
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
    # Additive (A2-5): the unit is stated, and a what-if in probability terms is given alongside.
    unit: str = Field("log-odds", description="Unit of shap_value: a log-odds contribution to the raw model margin "
                                              "(base value + sum of contributions = margin)")
    probability_delta: Optional[float] = Field(
        None, description="How much the calibrated probability would change if this feature's contribution were removed "
                          "(a what-if, not an additive share)")
    group: Optional[str] = Field(None, description="Feature group: surface | host | path | risk | brand")


class UrlRiskTerm(BaseModel):
    """One fired rule of the transparent lexical baseline."""

    text: str
    weight: float


class UrlRiskAssessment(BaseModel):
    """The URL-level maliciousness assessment (A2): calibrated model scores for the URL *string* (``ml/url_risk``)."""

    applicable: bool = True
    score: Optional[float] = Field(None, description="Calibrated probability from the tree model (URL features)")
    raw_score: Optional[float] = Field(None, description="The tree model's uncalibrated score (a ranking, not a probability)")
    cnn_score: Optional[float] = Field(None, description="Calibrated probability from the character CNN (None = not loaded)")
    baseline_score: Optional[float] = Field(None, description="The a-priori lexical baseline, calibrated the same way")
    fused_score: Optional[float] = Field(None, description="Stacked fusion of the channels that answered (B7)")
    fusion_contributions: dict[str, float] = Field(default_factory=dict, description="Per-channel log-odds in the fused score")
    headline_score: Optional[float] = Field(None, description="The fused score if available, else the tree model's")
    flagged: bool = Field(False, description="headline_score >= threshold")
    threshold: Optional[float] = None
    threshold_basis: Optional[str] = None
    at_prevalence: dict[str, float] = Field(default_factory=dict,
                                            description="What the headline score means if only 1 in 100 / 1 in 1000 URLs are phishing")
    baseline_terms: list[UrlRiskTerm] = Field(default_factory=list)
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


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

class CanonicalTarget(BaseModel):
    """What the scanner actually looked up, after ``core/targets.canonicalize`` (A1-6).

    The *user-visible* proof that "BÜCHER.example." and "https://bücher.example/x?t=1" were treated as
    ``xn--bcher-kva.example``. ``url`` is the **public** form (no query, fragment or credentials) — the secrets
    in the typed string are deliberately not echoed back.
    """

    kind: TargetType
    host: Optional[str] = Field(None, description="ASCII/punycode lowercase hostname, or the IP literal")
    registered_domain: Optional[str] = Field(
        None, description="eTLD+1 from the Public Suffix List; null when the suffix is not a public one")
    subdomain: str = ""
    ip: Optional[str] = None
    port: Optional[int] = Field(None, description="Explicit non-default port, if any")
    scheme: Optional[str] = None
    url: Optional[str] = Field(None, description="Canonical URL without query/fragment/credentials (URL targets)")
    has_userinfo: bool = Field(False, description="The typed target contained user:password@ credentials")
    hash: Optional[str] = None
    hash_type: Optional[str] = None


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
    canonical: Optional[CanonicalTarget] = Field(
        None,
        description="The canonical form of the target that providers were queried with (A1-6); "
                    "null on scans stored before it existed",
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
    tls: Optional[TlsInfo] = Field(None, description="TLS certificate facts (None if unavailable; A1-3)")
    rdap: Optional[RdapInfo] = Field(None, description="Registration record incl. the real domain age (A1-3)")
    dns: Optional[DnsInfo] = Field(None, description="DNS records, SPF/DMARC and hosting ASN (A1-3)")
    ct: Optional[CtInfo] = Field(None, description="Certificate-transparency history: first certificate, recent issuance, issuer (B3)")
    exposure: Optional[ExposureAssessment] = Field(
        None,
        description="Exploit-informed exposure of the host (EPSS / KEV / SSVC) — deliberately separate from the "
                    "maliciousness scores and never blended into them (B11). None when it could not be assessed at all.",
    )
    url_risk: Optional[UrlRiskAssessment] = Field(
        None,
        description="Calibrated URL-string maliciousness models and the transparent baseline (A2). None for IP / hash "
                    "targets or when the model is not loaded (see ml_status).",
    )
    reputation: Optional[ReputationSummary] = Field(
        None,
        description="Independent reputation channels (blocklists, abuse.ch, Safe Browsing, AbuseIPDB, urlscan, OTX, GreyNoise, "
                    "Tranco) side by side (B2), separate from the maliciousness scores. None when no channel applied.",
    )
    brand_check: Optional[BrandCheck] = Field(
        None,
        description="Local brand-impersonation check of the host (B4): status, evidence and what was compared. "
                    "None for IP / file-hash targets or when the check is switched off.",
    )
    lookalike_of: Optional[LookalikeMatch] = Field(
        None, description="The brand this host impersonates (``brand_check.match``), when it scored at or above the threshold",
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
        description="Provider-evidence score (rule-based weighted sum over VirusTotal / ports / CVEs / TLS / age; 0 = nothing found, "
                    "1 = critical). None when no provider answered. Never adjusted after it is computed.",
    )
    baseline_label: Optional[str] = Field(
        None,
        description="Low / Medium / High / Critical band of baseline_score; 'Unknown' if no evidence",
    )
    ml_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="URL model: calibrated probability that the URL text looks like phishing (the stacked tree + character-CNN "
                    "fusion). None for IP / hash targets or when the model is not loaded. Never adjusted after it is computed.",
    )
    ml_label: Optional[str] = Field(
        None,
        description="Low / Medium / High / Critical band of ml_score (the URL model's operating points); 'Unknown' without a score",
    )
    headline_band: Optional[str] = Field(
        None,
        description="The higher-risk band of the two channels (URL model, provider evidence); None when neither produced one",
    )
    driven_by: Optional[Literal["url_model", "provider_evidence", "both"]] = Field(
        None, description="Which channel produced headline_band (both = the same band)",
    )
    agreement: Optional[bool] = Field(
        None, description="|ml_score - baseline_score| <= 15 points; None when either score is missing",
    )
    baseline_terms: list[UrlRiskTerm] = Field(
        default_factory=list,
        description="What baseline_score is made of: each term's plain-English reason and its points on the 0..1 scale",
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


class FastRequest(BaseModel):
    """Body of ``POST /scan/fast``: just what the local checks need."""

    target: str = Field(..., min_length=1, max_length=2048)
    target_type: Optional[TargetType] = Field(None, description="Optional; inferred from the target when omitted")
    send_full_url: bool = Field(False, description="Match the full URL (with query) against the local lists instead of the trimmed form")


class FastVerdict(BaseModel):
    """The fast tier's answer (B1): local data only — nothing about the target left the machine."""

    status: Literal["listed", "suspicious", "official", "info", "nothing_found", "invalid", "not_applicable", "not_assessable"]
    level: Literal["block", "warn", "info", "none"] = Field(
        ..., description="block = the exact page is on a local phishing list; warn = look-alike / flagged text / listed host; "
                         "info = a brand's own domain; none = nothing found (NOT a clean bill of health)")
    reasons: list[str] = Field(default_factory=list)
    target_type: Optional[TargetType] = None
    canonical_host: Optional[str] = None
    registered_domain: Optional[str] = None
    listed_by: list[str] = Field(default_factory=list, description="Local lists that name this URL / host")
    popularity_rank: Optional[int] = Field(None, description="Tranco rank (a prior, not a verdict)")
    brand_check: Optional[BrandCheck] = None
    url_risk_score: Optional[float] = Field(None, description="Calibrated URL-text headline probability")
    url_risk_flagged: Optional[bool] = None
    list_gaps: list[str] = Field(default_factory=list, description="Local lists that could not be read (unknown, not clean)")
    cached_scan: Optional[dict] = Field(None, description="A recent full scan of the same target: its id and headline")
    latency_ms: float = 0.0
    tier: Literal["fast"] = "fast"


class ScanResponse(BaseModel):
    """Top‑level API response wrapper for scan results.

    Using a wrapper (rather than returning ``ScanResult`` directly) lets
    us return a uniform ``{success, result, error}`` shape for both happy
    and error paths, which simplifies frontend parsing.
    """

    success: bool = Field(True, description="Whether the scan completed without fatal errors")
    result: Optional[ScanResult] = Field(None, description="Full scan result, if successful")
    error: Optional[str] = Field(None, description="Error message, if the scan failed")
    # Two-tier pipeline (B1), additive: present for ``mode: "async"`` requests and ``GET /scan/{id}`` of a running scan.
    scan_id: Optional[str] = Field(None, description="Id to follow the slow tier (SSE events / GET /scan/{id})")
    status: Optional[Literal["running", "done", "error"]] = Field(None, description="Slow-tier state; None = a synchronous scan")
    fast: Optional[FastVerdict] = Field(None, description="The fast-tier verdict returned immediately in async mode")


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
    headline_band: Optional[str] = None
    driven_by: Optional[str] = None


class AttackChainNode(BaseModel):
    """A single node representing a vulnerability in an attack chain."""

    cve_id: str = Field(..., description="CVE ID, e.g. CVE-2021-44228")
    cvss_score: Optional[float] = Field(None, description="CVSS base score")
    epss_score: Optional[float] = Field(None, description="EPSS exploitation probability; None = unknown (never an invented 0.0)")
    is_in_kev: bool = Field(False, description="Whether the CVE is in CISA KEV catalog")
    exploit_db_id: Optional[str] = Field(None, description="Exploit-DB script ID if available")
    pre_conditions: list[str] = Field(default_factory=list, description="Conditions required to exploit")
    post_conditions: list[str] = Field(default_factory=list, description="State changes after exploitation")
    description: str = Field("", description="Brief vulnerability description")


class AttackPath(BaseModel):
    """A logical path of chained vulnerabilities leading to a potential compromise."""

    path_id: str = Field(..., description="Unique identifier for the attack path")
    nodes: list[AttackChainNode] = Field(default_factory=list, description="Sequence of chained vulnerability nodes")
    total_risk_score: Optional[float] = Field(
        None,
        description="Probability (0.0-1.0) that at least one rated CVE on the path is exploited; None when no CVE on the path has "
                    "a CVSS score, an EPSS score or a KEV listing",
    )
    unrated_cves: list[str] = Field(
        default_factory=list,
        description="CVEs on the path with no CVSS, EPSS or KEV data: left out of the risk figure, not given a made-up value",
    )
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

