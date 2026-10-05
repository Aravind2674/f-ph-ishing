"""
ThreatFusion – Network Layer Data Contracts
============================================

Single source of truth for every shape that flows through the network
monitoring pipeline: raw sensor events → enrichment → fused alerts.

The models deliberately mirror the conventions in ``app.models.schemas``
(Pydantic v2, ``Field(default_factory=…)`` for mutable defaults, a short
rationale in every ``description``) so the two layers read as one codebase.

**Honesty contract:** every optional enrichment block carries an
``available`` flag and a ``reason`` string.  When a signal cannot be
obtained (no WiGLE key, VirusTotal offline, monitor mode unsupported) the
block is marked unavailable with the real reason — it is *never* filled
with a fabricated value.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Qualitative severity band for a network alert."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AlertType(str, Enum):
    """The kind of suspicious activity an alert represents."""

    DEAUTH_FLOOD = "deauth_flood"
    ROGUE_AP = "rogue_ap"
    EVIL_TWIN = "evil_twin"
    NEW_DEVICE = "new_device"
    CROSS_LAYER_HIT = "cross_layer_hit"
    BEHAVIORAL_DEVIATION = "behavioral_deviation"
    ARP_SPOOF = "arp_spoof"
    TLS_FINGERPRINT = "tls_fingerprint"        # B13: a client TLS fingerprint listed for malware
    DGA_SUSPECT = "dga_suspect"                # B13: machine-generated-looking domain names / NXDOMAIN bursts
    BEACONING = "beaconing"                    # B13: periodic connections to one destination
    DNS_ANOMALY = "dns_anomaly"                # B13: very long / high-entropy names, TXT volume


class EventType(str, Enum):
    """Raw sensor event kinds, before correlation decides on an alert."""

    ARP_OBSERVED = "arp_observed"
    ARP_CONFLICT = "arp_conflict"
    NEW_DEVICE = "new_device"
    DNS_QUERY = "dns_query"
    DNS_RESPONSE = "dns_response"              # A3-3: rcode + answers (domain → IPs, TTL)
    TLS_CLIENT_HELLO = "tls_client_hello"      # A3-3: SNI + JA3/JA4 from the unencrypted ClientHello
    AP_OBSERVED = "ap_observed"                # B14: an access point seen in a Wi-Fi scan (the correlator decides what it means)
    WIFI_AP = "wifi_ap"
    EVIL_TWIN = "evil_twin"
    ROGUE_AP = "rogue_ap"
    DEAUTH = "deauth"
    DEAUTH_FLOOD = "deauth_flood"


# ---------------------------------------------------------------------------
# Raw sensor event
# ---------------------------------------------------------------------------

class SensorEvent(BaseModel):
    """A single observation emitted by a capture sensor.

    Sensors are intentionally *dumb*: they report exactly what they saw on
    the wire/air and nothing more.  All interpretation, enrichment and
    scoring happens later in the correlation engine.  This keeps the
    provenance of every value auditable back to a concrete capture.
    """

    event_type: EventType = Field(..., description="Kind of raw observation")
    timestamp: datetime = Field(..., description="UTC time the sensor observed it")
    sensor: str = Field(..., description="Which sensor produced this (arp/dns/wifi/dot11)")

    # ── Device identity (populated for L2/L3 events) ─────────────────────
    mac: Optional[str] = Field(None, description="Source device MAC address")
    ip: Optional[str] = Field(None, description="Source device IPv4 address")

    # ── DNS / cross-layer ───────────────────────────────────────────────
    domain: Optional[str] = Field(None, description="Queried domain (DNS events)")

    # ── WiFi / AP events ────────────────────────────────────────────────
    bssid: Optional[str] = Field(None, description="Access-point BSSID (MAC)")
    ssid: Optional[str] = Field(None, description="Access-point SSID (network name)")
    channel: Optional[int] = Field(None, description="WiFi channel")
    signal: Optional[int] = Field(None, description="Signal strength (% or dBm)")

    # ── ARP conflict details ────────────────────────────────────────────
    old_mac: Optional[str] = Field(None, description="Previously seen MAC for this IP")
    new_mac: Optional[str] = Field(None, description="Newly claimed MAC for this IP")

    # ── Arbitrary real evidence captured with the event ─────────────────
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Sensor-specific raw fields (frame counts, rates, packet meta)",
    )


# ---------------------------------------------------------------------------
# Enrichment blocks
# ---------------------------------------------------------------------------

class SignalContribution(BaseModel):
    """One real signal's contribution to the fused alert score.

    Making every contribution explicit is what lets Screen B answer
    "why is the score what it is" without hand-waving.  ``points`` are the
    signed number of points this signal added to (or removed from) the
    0–100 fused score.
    """

    name: str = Field(..., description="Machine name of the signal, e.g. 'app_layer'")
    label: str = Field(..., description="Human-readable signal label")
    available: bool = Field(True, description="False when this signal could not be obtained")
    points: float = Field(0.0, description="Signed points contributed to the fused score")
    detail: str = Field("", description="Plain-language explanation of what fired")
    reason: Optional[str] = Field(
        None, description="If unavailable, the real reason it degraded"
    )


class AppLayerSubScore(BaseModel):
    """Result of routing an observed domain/IP through the App-Layer pipeline.

    This is produced by the *existing* scoring modules
    (``extract_features`` → ``baseline_score`` + ``FusionModel``), not a
    re-implementation.  It is the concrete realisation of cross-layer
    correlation (differentiator #1).
    """

    available: bool = Field(True, description="False if the App-Layer lookup could not run")
    reason: Optional[str] = Field(None, description="Why the sub-score is unavailable, if so")
    target: Optional[str] = Field(None, description="Domain/IP that was scored")
    target_type: Optional[str] = Field(None, description="'domain' or 'ip'")
    baseline_score: Optional[float] = Field(None, description="App-Layer heuristic score 0–1")
    ml_score: Optional[float] = Field(None, description="App-Layer ML fusion score 0–1")
    ml_label: Optional[str] = Field(None, description="App-Layer risk label")
    vt_malicious_count: Optional[int] = Field(
        None, description="VirusTotal engines flagging malicious"
    )
    vt_total_engines: Optional[int] = Field(None, description="VirusTotal engines queried")
    flagged: bool = Field(
        False, description="True if the App-Layer considers the target malicious/suspicious"
    )
    top_explanations: list[str] = Field(
        default_factory=list, description="Top human-readable SHAP drivers"
    )
    live: bool = Field(
        False, description="True if the VirusTotal lookup used live data (not mock)"
    )
    # ── Additive (A3-4): where the answer came from, and whether it is corroborated ──
    source: Optional[str] = Field(
        None, description="virustotal | local_blocklist | popular_domain | url_model_only | budget_exhausted | cache — what produced this sub-score")
    corroborated: bool = Field(
        False, description="True only when the evidence is a blocklist hit or at least two VirusTotal engines; "
                           "a URL-text model score alone never raises a cross-layer alert")
    blocklists: list[str] = Field(default_factory=list, description="Local lists that name this domain")
    popularity_rank: Optional[int] = Field(None, description="Tranco rank (a prior, not a verdict)")


class WigleResult(BaseModel):
    """Real WiGLE public-history lookup for an access-point BSSID.

    Zero prior observations (a BSSID never publicly seen) raises suspicion;
    years of sightings lower it (differentiator #2).
    """

    available: bool = Field(True, description="False if WiGLE could not be queried")
    reason: Optional[str] = Field(None, description="Why unavailable (no key, rate-limited, error)")
    bssid: Optional[str] = Field(None, description="BSSID that was queried")
    found: bool = Field(False, description="Whether WiGLE has any public record of this BSSID")
    total_observations: int = Field(0, description="Number of public WiGLE observations")
    first_seen: Optional[str] = Field(None, description="First public sighting (WiGLE 'firsttime')")
    last_seen: Optional[str] = Field(None, description="Most recent public sighting")
    known_ssids: list[str] = Field(
        default_factory=list, description="SSIDs WiGLE has associated with this BSSID"
    )


class BaselineComparison(BaseModel):
    """Learned profile vs. the freshly observed behaviour for a device.

    Built from real captured DNS/port activity (differentiator #3).
    """

    device_known: bool = Field(..., description="Whether the device has an established profile")
    observations: int = Field(0, description="Total DNS observations learned for this device")
    established: bool = Field(
        False, description="True once enough traffic has been observed to trust the baseline"
    )
    known_domains_sample: list[str] = Field(
        default_factory=list, description="A sample of domains the device normally contacts"
    )
    known_domain_count: int = Field(0, description="Distinct domains in the learned profile")
    observed_domain: Optional[str] = Field(None, description="The domain observed in this event")
    is_new_domain: bool = Field(
        False, description="True if the observed domain is absent from the learned profile"
    )
    deviation_detail: str = Field("", description="Plain-language description of the deviation")


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class AlertEvidence(BaseModel):
    """Everything that justified an alert and its score.

    Screen B renders this verbatim, so it must be complete and honest —
    including which signals *failed* to contribute and why.
    """

    signals: list[SignalContribution] = Field(
        default_factory=list, description="Every signal that fed the fused score"
    )
    app_layer: Optional[AppLayerSubScore] = Field(
        None, description="Cross-layer App-Layer sub-score, if a domain/IP was involved"
    )
    wigle: Optional[WigleResult] = Field(
        None, description="WiGLE public-history result, if an AP was involved"
    )
    baseline: Optional[BaselineComparison] = Field(
        None, description="Device baseline vs. observed behaviour, if applicable"
    )
    raw: dict[str, Any] = Field(
        default_factory=dict, description="Raw sensor evidence (frame counts, packet meta, etc.)"
    )


class NetworkAlert(BaseModel):
    """A scored, human-facing network alert.

    Carries severity, a fused 0–100 risk score, timestamp, involved
    device(s), the trigger type, and the full underlying evidence.
    """

    alert_id: str = Field(..., description="Unique alert identifier (UUID4 hex)")
    timestamp: datetime = Field(..., description="UTC time the alert was raised")
    alert_type: AlertType = Field(..., description="Category of suspicious activity")
    severity: Severity = Field(..., description="Low / Medium / High / Critical")
    fused_score: float = Field(
        ..., ge=0.0, le=100.0, description="Unified 0–100 risk score across all signals"
    )
    title: str = Field(..., description="Short human-readable alert title")

    # ── Involved device(s) ──────────────────────────────────────────────
    device_mac: Optional[str] = Field(None, description="Primary involved device MAC")
    device_name: Optional[str] = Field(None, description="Friendly/derived device name")
    device_ip: Optional[str] = Field(None, description="Primary involved device IP")
    involved: list[str] = Field(
        default_factory=list, description="All involved identifiers (MACs/IPs/BSSIDs/domains)"
    )

    trigger_type: str = Field(..., description="What concretely triggered the alert")
    evidence: AlertEvidence = Field(..., description="Full scoring evidence breakdown")
    recommended_actions: list[str] = Field(
        default_factory=list, description="Suggested defensive responses"
    )


class DeviceProfile(BaseModel):
    """Persisted rolling behaviour profile for a single device."""

    mac: str = Field(..., description="Device MAC address (primary key)")
    ip: Optional[str] = Field(None, description="Most recent observed IPv4")
    hostname: Optional[str] = Field(None, description="Resolved/observed hostname, if any")
    vendor: Optional[str] = Field(None, description="OUI vendor, if resolvable")
    first_seen: datetime = Field(..., description="When the device was first observed")
    last_seen: datetime = Field(..., description="Most recent observation")
    dns_observations: int = Field(0, description="Total DNS queries observed from this device")
    distinct_domains: int = Field(0, description="Distinct domains contacted")
    top_domains: list[str] = Field(
        default_factory=list, description="Most frequently contacted domains"
    )
    ports: list[int] = Field(default_factory=list, description="Destination ports observed")


class MonitorStatus(BaseModel):
    """Honest, real-time health of the capture layer.

    Surfaces exactly which sensors are running and — critically — which
    are degraded and why (e.g. monitor mode unavailable, scapy missing).
    """

    running: bool = Field(..., description="Whether the monitor service is active")
    sensors: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Per-sensor {available, running, reason} status",
    )
    alert_count: int = Field(0, description="Total alerts raised this session")
    device_count: int = Field(0, description="Distinct devices profiled")
    started_at: Optional[datetime] = Field(None, description="When monitoring started")
    # ── Additive (A3): why capture can or cannot work, and what it can see ──
    capture: Optional[dict[str, Any]] = Field(
        None, description="Capture preflight + live state: {state, ok, reason, fix, selected_interface, interfaces, details, packets_seen}. "
                          "state is one of no_scapy | no_npcap | not_elevated | no_interface | ready | running | no_packets_seen | error")
    scope_note: str = Field(
        "A sensor on one computer sees that computer's own traffic plus broadcast / multicast traffic on its network segment — not the "
        "traffic of other devices. Watching other devices needs a sensor at the gateway or on a mirror port, or Zeek / Suricata logs.",
        description="What the sensor can and cannot see (A3-6)")
    dropped_events: int = Field(0, description="Sensor events discarded because the processing queue was full (never silent)")
