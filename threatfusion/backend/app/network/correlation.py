"""
ThreatFusion – Correlation & Fusion Scoring Engine
====================================================

Turns raw :class:`SensorEvent` observations into scored :class:`NetworkAlert` objects.

1. **Cross-layer correlation** — an observed name (a DNS query, a TLS SNI, or the name an IP was resolved from) goes through the
   reputation gate (``reputation_gate.py``): local lists and the URL model first, VirusTotal only for a flagged name inside the
   network's own budget.  A cross-layer alert needs *corroboration* (a list hit, or at least two VirusTotal engines).
2. **Wi-Fi** (``aps.py``) — access points are remembered; only a *watched* network is judged: unfamiliar hardware (vendor prefix) or a new
   security mode under its name, or a new channel.  A candidate evil twin's BSSID is also looked up against WiGLE's public history.
3. **Behavioural baselining** — a name a *device* has never contacted, once its profile is established, and only if the name is not a
   popular one (a new popular site is normal behaviour, not a deviation).
4. **TLS fingerprints** — a ClientHello whose JA3 hash is on abuse.ch's SSLBL list.  Capped at Medium: abuse.ch says these listings are
   not false-positive tested, and a JA3 identifies a TLS *library*, not a host.
5. **Measurable heuristics** (``heuristics.py``) — NXDOMAIN bursts, machine-generated-looking names, beaconing.  Every alert carries the
   evidence that triggered it.
6. **ARP** — gateway MAC change, gratuitous-ARP flood, one MAC claiming many IPs (``sensor/arp_sensor.py`` decides; this scores).

Every alert's ``fused_score`` (0–100) is the clamped sum of explicit :class:`SignalContribution` points, so the score is fully
reconstructable from the evidence.  When a signal is unavailable it contributes 0 points and records the real reason.  The weights are
transparent expert priors.

Noise control: the same alert (type + device + subject) is raised once per ``NETWORK_ALERT_DEDUP_SECONDS``; a fresh install only
*learns* during ``NETWORK_WARMUP_SECONDS`` instead of announcing every device already on the network; the DNS query and the TLS SNI of
one visit are one observation.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import Any, Callable, Optional
from uuid import uuid4

from app.core.config import get_settings
from app.network.baseline_store import BaselineStore
from app.network.enrichment.app_layer import AppLayerScorer
from app.network.enrichment.wigle import WigleClient, to_evidence
from app.network.heuristics import BeaconDetector, NxdomainBurst, name_anomaly
from app.network.models import (
    AlertEvidence,
    AlertType,
    AppLayerSubScore,
    BaselineComparison,
    EventType,
    NetworkAlert,
    SensorEvent,
    Severity,
    SignalContribution,
    WigleResult,
)
from app.network.reputation_gate import registered_domain_of
from app.network.resolution import ResolutionMap

logger = logging.getLogger(__name__)


# ── Fusion weights (transparent expert priors) ──────────────────────────
ARP_SPOOF_BASE = 60.0
ARP_SPOOF_GATEWAY_BONUS = 25.0
ARP_FLOOD_BASE = 45.0
ARP_FLOOD_GATEWAY_BONUS = 20.0
ARP_MULTI_IP_BASE = 40.0
NEW_DEVICE_BASE = 30.0
CROSS_LAYER_BASE = 20.0          # a known device reaching a flagged name
BLOCKLIST_POINTS = 50.0          # a local blocklist names the host
VT_BASE_POINTS = 30.0            # at least two VirusTotal engines flag it ...
VT_PER_ENGINE_POINTS = 5.0       # ... plus this per malicious engine
VT_MAX_ENGINES = 8
BEHAVIORAL_DEVIATION_POINTS = 30.0
TLS_FINGERPRINT_POINTS = 40.0    # Medium at most: SSLBL JA3 listings are not false-positive tested
DGA_BURST_BASE = 45.0
NAME_ANOMALY_BASE = 20.0
BEACON_BASE = 45.0
EVIL_TWIN_BASE = 50.0
SECURITY_MISMATCH_POINTS = 45.0
OPEN_TWIN_BONUS = 20.0
ROGUE_AP_BASE = 20.0
WIGLE_UNSEEN_BONUS = 32.0        # BSSID with zero public history → suspicious
WIGLE_ESTABLISHED_PENALTY = -18.0  # long public history → reassuring
WIGLE_ESTABLISHED_MIN_OBS = 5

_SAME_VISIT_SECONDS = 5.0
_MAX_TRACKED = 8192


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


def severity_from_score(score: float) -> Severity:
    """Map a 0–100 fused score to a severity band (the same bands the URL model's labels use, scaled ×100)."""
    if score >= 75.0:
        return Severity.CRITICAL
    if score >= 50.0:
        return Severity.HIGH
    if score >= 25.0:
        return Severity.MEDIUM
    return Severity.LOW


def _sum_points(signals: list[SignalContribution]) -> float:
    return _clamp(sum(s.points for s in signals))


class CorrelationEngine:
    """Enriches sensor events and emits scored alerts.

    Parameters
    ----------
    store : BaselineStore
        Persisted per-device behaviour profiles.
    app_scorer : AppLayerScorer
        Adapter over the reputation gate.
    wigle : WigleClient
        Real WiGLE public-history client.
    clock : callable
        Wall-clock seconds (warm-up and alert de-duplication); event windows use the events' own timestamps.
    """

    def __init__(self, store: BaselineStore, app_scorer: AppLayerScorer, wigle: WigleClient, *, settings: Any = None,
                 clock: Callable[[], float] = time.time, ap_store: Any = None) -> None:
        s = settings or get_settings()
        self._store = store
        self._aps = ap_store
        self._app = app_scorer
        self._wigle = wigle
        self._settings = s
        self._clock = clock
        # Dedup guard so a device's "new device" alert fires at most once.
        self._alerted_new_devices: set[str] = set()
        # Session cache of MACs already persisted, to avoid a DB round-trip on every repeat ARP presence observation.
        self._active_macs: set[str] = set()
        self.resolutions = ResolutionMap(max_entries=50_000, clock=clock)
        self._nx = NxdomainBurst(s.NXDOMAIN_BURST_THRESHOLD, s.NXDOMAIN_BURST_WINDOW_SECONDS)
        self._beacon = BeaconDetector(s.BEACON_MIN_EVENTS, s.BEACON_MIN_SPAN_SECONDS, s.BEACON_MAX_JITTER)
        self._recent_names: "OrderedDict[tuple[str, str], float]" = OrderedDict()
        self._alert_seen: "OrderedDict[tuple, float]" = OrderedDict()
        self._warmup_until = 0.0
        self._connected_ssid: Optional[str] = None

    def reset(self) -> None:
        """Reset state tracking when the user clears data."""
        self._alerted_new_devices.clear()
        self._active_macs.clear()
        self.resolutions = ResolutionMap(max_entries=50_000, clock=self._clock)
        self._nx = NxdomainBurst(self._settings.NXDOMAIN_BURST_THRESHOLD, self._settings.NXDOMAIN_BURST_WINDOW_SECONDS)
        self._beacon = BeaconDetector(self._settings.BEACON_MIN_EVENTS, self._settings.BEACON_MIN_SPAN_SECONDS, self._settings.BEACON_MAX_JITTER)
        self._recent_names.clear()
        self._alert_seen.clear()

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------

    def begin_session(self, *, fresh: bool) -> None:
        """Called when monitoring starts. ``fresh`` = no device has ever been profiled: learn quietly for the warm-up period."""
        seconds = float(self._settings.NETWORK_WARMUP_SECONDS)
        self._warmup_until = self._clock() + seconds if fresh and seconds > 0 else 0.0

    def watched_ssids(self) -> set[str]:
        """Lower-cased SSIDs whose access points are judged: those in NETWORK_MONITORED_SSIDS plus the network this machine is connected to."""
        watched = {x.strip().lower() for x in self._settings.NETWORK_MONITORED_SSIDS.split(",") if x.strip()}
        if self._connected_ssid:
            watched.add(self._connected_ssid.lower())
        return watched

    @property
    def warming_up(self) -> bool:
        return self._clock() < self._warmup_until

    def _once(self, *key: Any) -> bool:
        """True the first time ``key`` is seen in the de-duplication window (and records it)."""
        now = self._clock()
        window = float(self._settings.NETWORK_ALERT_DEDUP_SECONDS)
        last = self._alert_seen.get(key)
        if last is not None and now - last < window:
            return False
        self._alert_seen[key] = now
        self._alert_seen.move_to_end(key)
        while len(self._alert_seen) > _MAX_TRACKED:
            self._alert_seen.popitem(last=False)
        return True

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def correlate(self, event: SensorEvent) -> list[NetworkAlert]:
        """Produce zero or more scored alerts from one raw event."""
        try:
            t = event.event_type
            if t == EventType.ARP_CONFLICT:
                return await self._handle_arp_conflict(event)
            if t == EventType.ARP_OBSERVED:
                return await self._handle_arp_observed(event)
            if t == EventType.ARP_FLOOD:
                return self._handle_arp_flood(event)
            if t == EventType.ARP_MULTI_IP:
                return self._handle_arp_multi_ip(event)
            if t == EventType.DNS_QUERY:
                return await self._handle_name(event, event.domain, "dns")
            if t == EventType.DNS_RESPONSE:
                return self._handle_dns_response(event)
            if t == EventType.TLS_CLIENT_HELLO:
                return await self._handle_tls(event)
            if t == EventType.WIFI_SCAN:
                return await self._handle_wifi_scan(event)
        except Exception:
            logger.exception("Correlation failed for event %s", event.event_type)
        return []

    # ------------------------------------------------------------------
    # ARP
    # ------------------------------------------------------------------

    async def _handle_arp_observed(self, event: SensorEvent) -> list[NetworkAlert]:
        if not event.mac:
            return []
        if event.mac in self._active_macs:
            return []  # already persisted this session — nothing new to do
        is_new = await self._store.observe_device(event.mac, event.ip)
        self._active_macs.add(event.mac)
        if not is_new or event.mac in self._alerted_new_devices:
            return []
        self._alerted_new_devices.add(event.mac)
        if self.warming_up:
            return []                                                  # learning the network as it is: not an arrival
        return [self._new_device_alert(event)]

    async def _handle_arp_conflict(self, event: SensorEvent) -> list[NetworkAlert]:
        # Record the newly-claiming MAC as a device too.
        if event.new_mac:
            await self._store.observe_device(event.new_mac, event.ip)

        is_gateway = bool(event.raw.get("is_gateway"))
        signals = [
            SignalContribution(
                name="arp_conflict",
                label="ARP binding changed",
                points=ARP_SPOOF_BASE,
                detail=(
                    f"IP {event.ip} was bound to {event.old_mac} but is now claimed by {event.new_mac} "
                    f"(the old address spoke {event.raw.get('old_mac_last_heard_seconds_ago', '?')} s earlier) — "
                    f"a MITM / ARP-spoofing indicator."
                ),
            )
        ]
        if is_gateway:
            signals.append(SignalContribution(
                name="gateway_targeted",
                label="Gateway targeted",
                points=ARP_SPOOF_GATEWAY_BONUS,
                detail=f"The IP {event.ip} is the default gateway — whole-network interception is possible.",
            ))
        if not self._once("arp_conflict", event.ip, event.new_mac):
            return []
        score = _sum_points(signals)
        return [NetworkAlert(
            alert_id=uuid4().hex,
            timestamp=event.timestamp,
            alert_type=AlertType.ARP_SPOOF,
            severity=severity_from_score(score),
            fused_score=score,
            title=f"{'Gateway ' if is_gateway else ''}ARP binding changed on {event.ip}",
            device_mac=event.new_mac,
            device_ip=event.ip,
            involved=[x for x in [event.ip, event.old_mac, event.new_mac] if x],
            trigger_type="ARP (IP→MAC) binding conflict",
            evidence=AlertEvidence(signals=signals, raw=event.raw),
            recommended_actions=[
                f"Isolate the device advertising {event.new_mac} from the network",
                f"Verify the true MAC of {event.ip} (especially if it is the gateway)",
                "Enable Dynamic ARP Inspection / DHCP snooping on the switch",
            ],
        )]

    def _handle_arp_flood(self, event: SensorEvent) -> list[NetworkAlert]:
        raw = event.raw
        signals = [SignalContribution(
            name="arp_flood", label="Gratuitous-ARP flood", points=ARP_FLOOD_BASE,
            detail=f"{event.mac} announced itself {raw.get('count')} times in {raw.get('window_seconds')} s "
                   f"(threshold {raw.get('threshold')}); cache-poisoning tools re-announce continuously to keep the poison fresh.")]
        if raw.get("is_gateway"):
            signals.append(SignalContribution(name="gateway_targeted", label="From the gateway's MAC", points=ARP_FLOOD_GATEWAY_BONUS,
                                              detail="The flood comes from the MAC that currently holds the gateway address."))
        if not self._once("arp_flood", event.mac):
            return []
        score = _sum_points(signals)
        return [NetworkAlert(
            alert_id=uuid4().hex, timestamp=event.timestamp, alert_type=AlertType.ARP_FLOOD, severity=severity_from_score(score), fused_score=score,
            title=f"ARP flood from {event.mac}", device_mac=event.mac, device_ip=event.ip,
            involved=[x for x in [event.mac, event.ip] if x], trigger_type="Burst of gratuitous ARP announcements",
            evidence=AlertEvidence(signals=signals, raw=raw),
            recommended_actions=[f"Find the device with MAC {event.mac} and check what is running on it",
                                 "Enable Dynamic ARP Inspection / port security on the switch"])]

    def _handle_arp_multi_ip(self, event: SensorEvent) -> list[NetworkAlert]:
        raw = event.raw
        signals = [SignalContribution(
            name="arp_multi_ip", label="One MAC, many IPs", points=ARP_MULTI_IP_BASE,
            detail=f"{event.mac} claimed {raw.get('ip_count')} different IP addresses in {raw.get('window_seconds')} s "
                   f"(threshold {raw.get('threshold')}): {', '.join((raw.get('ips') or [])[:6])}. A host running virtual machines or "
                   f"containers can do this legitimately; an attacker impersonating several hosts does it too.")]
        if not self._once("arp_multi_ip", event.mac):
            return []
        score = _sum_points(signals)
        return [NetworkAlert(
            alert_id=uuid4().hex, timestamp=event.timestamp, alert_type=AlertType.ARP_MULTI_IP, severity=severity_from_score(score), fused_score=score,
            title=f"{event.mac} claims {raw.get('ip_count')} IP addresses", device_mac=event.mac, device_ip=event.ip,
            involved=[event.mac, *(raw.get("ips") or [])[:6]], trigger_type="One MAC answering for many IP addresses",
            evidence=AlertEvidence(signals=signals, raw=raw),
            recommended_actions=["Confirm whether this device hosts virtual machines or containers",
                                 "If not, isolate it and inspect it"])]

    # ------------------------------------------------------------------
    # DNS responses, TLS hellos and the names they carry
    # ------------------------------------------------------------------

    def _handle_dns_response(self, event: SensorEvent) -> list[NetworkAlert]:
        raw = event.raw
        name = (event.domain or "").lower()
        answers = raw.get("answers") or []
        for ttl in {int(a.get("ttl", 0)) for a in answers if a.get("type") in ("A", "AAAA")}:
            ips = [a["data"] for a in answers if a.get("type") in ("A", "AAAA") and int(a.get("ttl", 0)) == ttl and a.get("data")]
            also = [a["name"] for a in answers if a.get("type") in ("A", "AAAA") and a.get("name") and a["name"] != name]
            self.resolutions.add(name, ips, ttl, also=also)
        if raw.get("rcode_name") != "NXDOMAIN" or not event.mac or not name:
            return []
        burst = self._nx.observe(event.mac, name, event.timestamp.timestamp())
        if burst is None or not self._once("dga", event.mac):
            return []
        signals = [SignalContribution(
            name="nxdomain_burst", label="Burst of “no such domain” answers", points=DGA_BURST_BASE,
            detail=f"{burst.count} NXDOMAIN answers to {event.mac} in {int(burst.window_seconds)} s "
                   f"(threshold {self._nx.threshold}), e.g. {', '.join(burst.names[:5])}. A domain-generation algorithm looks like this "
                   f"from the resolver's side — so does a broken configuration; this is evidence of a pattern, not proof of malware.")]
        score = _sum_points(signals)
        return [NetworkAlert(
            alert_id=uuid4().hex, timestamp=event.timestamp, alert_type=AlertType.DGA_SUSPECT, severity=severity_from_score(score), fused_score=score,
            title=f"{burst.count} unresolvable names in {int(burst.window_seconds)} s for {event.mac}", device_mac=event.mac, device_ip=event.ip,
            involved=[x for x in [event.mac, event.ip, *burst.names[:5]] if x], trigger_type="NXDOMAIN burst (possible domain-generation algorithm)",
            evidence=AlertEvidence(signals=signals, raw={"names": burst.names, "count": burst.count, "window_seconds": burst.window_seconds}),
            recommended_actions=[f"Check what is running on device {event.mac}", "Look at the names above: random-looking ones suggest malware",
                                 "If a misconfigured service is the cause, fix its host names"])]

    async def _handle_tls(self, event: SensorEvent) -> list[NetworkAlert]:
        raw = event.raw
        alerts: list[NetworkAlert] = []
        ja3 = raw.get("ja3")
        if ja3 and event.mac:
            alert = await self._ja3_alert(event, str(ja3))
            if alert is not None:
                alerts.append(alert)
        sni = (event.domain or "").lower() or None
        name, how = (sni, "tls_sni") if sni else (self.resolutions.name_for(raw.get("dst_ip")), "resolved_ip")
        if name and event.mac:
            alerts.extend(await self._handle_name(event, name, how))
        return alerts

    async def _ja3_alert(self, event: SensorEvent, ja3: str) -> Optional[NetworkAlert]:
        from app.core.hub import hub

        if not self._settings.SSLBL_JA3_ENABLED:
            return None
        status, row = await hub.ja3().match(ja3)
        if status != "listed" or not self._once("ja3", event.mac, ja3):
            return None
        row = row or {}
        signals = [SignalContribution(
            name="tls_fingerprint", label="TLS client fingerprint on a malware list", points=TLS_FINGERPRINT_POINTS,
            detail=(f"JA3 {ja3} is listed by abuse.ch SSLBL" + (f" ({row['reason']})" if row.get("reason") else "")
                    + (f", first seen {row['first']}" if row.get("first") else "") + (f", last seen {row['last']}" if row.get("last") else "")
                    + ". abuse.ch states these listings are not false-positive tested, and a JA3 identifies a TLS library, not a host: "
                      "a legitimate program built on the same library can match."))]
        score = _sum_points(signals)
        dest = event.domain or event.raw.get("dst_ip")
        return NetworkAlert(
            alert_id=uuid4().hex, timestamp=event.timestamp, alert_type=AlertType.TLS_FINGERPRINT, severity=severity_from_score(score), fused_score=score,
            title=f"TLS client fingerprint on a malware list ({row.get('reason') or 'SSLBL'})", device_mac=event.mac, device_ip=event.ip,
            involved=[x for x in [event.mac, event.ip, dest, ja3] if x], trigger_type="JA3 fingerprint listed by abuse.ch SSLBL",
            evidence=AlertEvidence(signals=signals, raw={"ja3": ja3, "ja4": event.raw.get("ja4"), "sni": event.domain, "dst_ip": event.raw.get("dst_ip"),
                                                         "listing": row}),
            recommended_actions=[f"Find which program on {event.mac} opened this connection", "Check it against the SSLBL listing before acting"])

    # ── one observed name, however it was seen ───────────────────────────
    def _seen_this_visit(self, mac: str, name: str, at: float) -> bool:
        key = (mac, name)
        last = self._recent_names.get(key)
        self._recent_names[key] = at
        self._recent_names.move_to_end(key)
        while len(self._recent_names) > _MAX_TRACKED:
            self._recent_names.popitem(last=False)
        return last is not None and 0 <= at - last < _SAME_VISIT_SECONDS

    async def _handle_name(self, event: SensorEvent, domain: Optional[str], source: str) -> list[NetworkAlert]:
        name = (domain or "").strip().lower().rstrip(".")
        if not event.mac or not name:
            return []
        at = event.timestamp.timestamp()
        alerts: list[NetworkAlert] = []

        beacon = self._beacon.observe(event.mac, name, at)               # every visit counts, however it was observed
        if self._seen_this_visit(event.mac, name, at):
            return []                                                    # the DNS query and the TLS SNI of one visit are one observation

        # 1) Device newness (covers ARP-less deployments), deduped. During the warm-up it is learned, not announced.
        was_known = await self._store.is_known_device(event.mac)
        if not was_known and event.mac not in self._alerted_new_devices:
            await self._store.observe_device(event.mac, event.ip)
            self._alerted_new_devices.add(event.mac)
            if not self.warming_up:
                alerts.append(self._new_device_alert(event))

        # 2) Learn from this observation, then compare against the profile.
        await self._store.record_dns(event.mac, name, event.ip)
        comparison = await self._store.compare_dns(event.mac, name)

        # 3) Cross-layer: the reputation gate.
        app = await self._app.score(name, "domain")
        popular = app.popularity_rank is not None
        cross_layer = bool(app.available and app.flagged and app.corroborated)
        deviation = bool(comparison.established and comparison.is_new_domain and not popular)

        signals = [self._app_layer_signal(app)]
        signals.append(SignalContribution(
            name="behavioral_deviation", label="Behavioural deviation",
            points=BEHAVIORAL_DEVIATION_POINTS if deviation else 0.0, detail=comparison.deviation_detail))

        if cross_layer or deviation:
            if cross_layer:
                signals.insert(0, SignalContribution(
                    name="cross_layer_contact", label="Known device → flagged domain", points=CROSS_LAYER_BASE,
                    detail=f"Device {event.mac} contacted '{name}' ({'DNS query' if source == 'dns' else 'TLS connection'}), which the "
                           f"reputation check flags."))
                alert_type, title = AlertType.CROSS_LAYER_HIT, f"Device contacted flagged domain {name}"
                trigger = "Connection to a name that a blocklist or VirusTotal flags"
                actions = [f"Block domain {name} at the resolver/firewall", f"Isolate device {event.mac} ({event.ip}) and inspect it",
                           "Review the device's recent DNS history for related indicators"]
                dedupe_key: tuple = ("cross", event.mac, registered_domain_of(name))
            else:
                alert_type, title = AlertType.BEHAVIORAL_DEVIATION, f"Behavioural deviation: {name}"
                trigger = "Contact with a name outside the device's learned baseline"
                actions = [f"Confirm whether {name} is expected for this device", f"Watch device {event.mac} for further anomalous contacts",
                           "If unexpected, isolate the device and block the domain"]
                dedupe_key = ("deviation", event.mac, registered_domain_of(name))
            if self._once(*dedupe_key):
                score = _sum_points(signals)
                alerts.append(NetworkAlert(
                    alert_id=uuid4().hex, timestamp=event.timestamp, alert_type=alert_type, severity=severity_from_score(score), fused_score=score,
                    title=title, device_mac=event.mac, device_ip=event.ip, involved=[x for x in [event.mac, event.ip, name] if x],
                    trigger_type=trigger,
                    evidence=AlertEvidence(signals=signals, app_layer=app, baseline=comparison,
                                           raw={"domain": name, "observed_via": source, "qtype": event.raw.get("qtype")}),
                    recommended_actions=actions))

        # 4) Names that look machine-generated (never for a popular or private name)
        if not popular and app.source != "private":
            finding = name_anomaly(name, registered_domain_of(name).split(".")[0], long_label=self._settings.NAME_LABEL_LONG,
                                   min_len=self._settings.NAME_LABEL_MIN_LENGTH, min_entropy=self._settings.NAME_LABEL_MIN_ENTROPY)
            if finding is not None and self._once("name_anomaly", event.mac, registered_domain_of(name)):
                sig = [SignalContribution(name="name_anomaly", label="Name looks machine-generated", points=NAME_ANOMALY_BASE,
                                          detail="; ".join(finding.reasons) + ". An unsupervised measure of how random the name looks — CDN and "
                                                 "hash-named hosts can look like this too.")]
                score = _sum_points(sig)
                alerts.append(NetworkAlert(
                    alert_id=uuid4().hex, timestamp=event.timestamp, alert_type=AlertType.DNS_ANOMALY, severity=severity_from_score(score),
                    fused_score=score, title=f"Unusual-looking name: {name[:60]}", device_mac=event.mac, device_ip=event.ip,
                    involved=[x for x in [event.mac, event.ip, name] if x], trigger_type="Long or high-entropy DNS label",
                    evidence=AlertEvidence(signals=sig, app_layer=app, raw={"domain": name, "label": finding.label,
                                                                            "entropy_bits_per_char": round(finding.entropy, 2), "observed_via": source}),
                    recommended_actions=[f"Check whether {name} is a service you use", "If it is not, find the program on the device that asked for it"]))

        # 5) Beaconing: this destination contacted at near-regular intervals
        if beacon is not None and not popular and app.source != "private" and self._once("beacon", event.mac, name):
            sig = [SignalContribution(
                name="beaconing", label="Regular contact with one destination", points=BEACON_BASE,
                detail=f"{beacon.count} contacts with '{name}' over {int(beacon.span_seconds)} s, one every {beacon.period_seconds:g} s on average "
                       f"(jitter {beacon.jitter:.0%}). Malware check-ins are periodic; so are mail clients, NTP and telemetry.")]
            score = _sum_points(sig)
            alerts.append(NetworkAlert(
                alert_id=uuid4().hex, timestamp=event.timestamp, alert_type=AlertType.BEACONING, severity=severity_from_score(score), fused_score=score,
                title=f"{event.mac} contacts {name} every {beacon.period_seconds:g} s", device_mac=event.mac, device_ip=event.ip,
                involved=[x for x in [event.mac, event.ip, name] if x], trigger_type="Periodic connections to one destination",
                evidence=AlertEvidence(signals=sig, app_layer=app, raw={"domain": name, "count": beacon.count, "period_seconds": beacon.period_seconds,
                                                                        "jitter": beacon.jitter, "span_seconds": beacon.span_seconds}),
                recommended_actions=[f"Identify the program on {event.mac} that contacts {name}", "If it is not one you recognise, isolate the device"]))
        return alerts

    def _app_layer_signal(self, app: AppLayerSubScore) -> SignalContribution:
        """What the reputation gate found, as explicit points (0 when it found nothing corroborated)."""
        label = "Domain reputation"
        if not app.available:
            return SignalContribution(name="app_layer", label=label, available=False, points=0.0,
                                      detail="Reputation check unavailable — degraded to other signals.", reason=app.reason)
        source = app.cached_from if app.source == "cache" else app.source
        if source == "local_blocklist":
            return SignalContribution(name="app_layer", label=label, points=BLOCKLIST_POINTS,
                                      detail=f"'{app.target}' is listed by {', '.join(app.blocklists)} (a local blocklist; no third-party call was made).")
        if source == "virustotal" and app.corroborated:
            engines = min(VT_MAX_ENGINES, app.vt_malicious_count or 0)
            return SignalContribution(
                name="app_layer", label=label, points=VT_BASE_POINTS + VT_PER_ENGINE_POINTS * engines,
                detail=f"VirusTotal: {app.vt_malicious_count}/{app.vt_total_engines} engines flag '{app.target}' as malicious (the URL model had "
                       f"scored it {app.ml_score:.0%} first; that is why VirusTotal was asked).")
        score_text = "n/a" if app.ml_score is None else f"{app.ml_score:.0%}"
        why = {"popular_domain": f"'{app.target}' is in the Tranco popularity list (#{app.popularity_rank}); not checked further.",
               "url_model_only": f"URL model score {score_text}" + (" — flagged, but a URL-text score alone is not corroboration."
                                                                    if app.reason else " — below the flag threshold, so nothing was sent anywhere."),
               "budget_exhausted": f"URL model flagged it ({score_text}) but the network's VirusTotal budget is used up."
               }.get(source or "", app.reason or "nothing flagged")
        return SignalContribution(name="app_layer", label=label, points=0.0, detail=why)

    # ------------------------------------------------------------------
    # Wi-Fi
    # ------------------------------------------------------------------

    async def _handle_wifi_scan(self, event: SensorEvent) -> list[NetworkAlert]:
        """One Wi-Fi scan: remember every access point, and judge the ones that carry a *watched* network's name.

        Watched = the SSIDs in NETWORK_MONITORED_SSIDS plus the network this machine is connected to.  See ``aps.py`` for the rules.
        """
        if self._aps is None:
            return []
        raw = event.raw
        self._connected_ssid = raw.get("connected_ssid") or None
        findings = await self._aps.observe(raw.get("aps") or [], self.watched_ssids())
        alerts: list[NetworkAlert] = []
        for f in findings:
            if self._once("ap", f.bssid, f.kind):
                alerts.append(await self._ap_alert(event, f))
        return alerts

    async def _ap_alert(self, event: SensorEvent, f: Any) -> NetworkAlert:
        ev, ap = f.evidence, f.ap
        if f.kind == "unexpected_oui":
            signals = [SignalContribution(
                name="evil_twin", label="Your network's name on different hardware", points=EVIL_TWIN_BASE,
                detail=(f"SSID '{f.ssid}' is advertised by BSSID {f.bssid} whose vendor prefix is {ev['observed_oui']}, but the {ev['known_bssids']} "
                        f"access point(s) you know for this network all use {', '.join(ev['known_ouis'])}. A real second access point of the same "
                        f"system normally shares the prefix."))]
            alert_type, title = AlertType.EVIL_TWIN, f"Possible evil-twin for '{f.ssid}' (unfamiliar hardware)"
        elif f.kind == "security_mismatch":
            observed = ev["observed_security"]
            signals = [SignalContribution(
                name="security_mismatch", label="Different security mode", points=SECURITY_MISMATCH_POINTS,
                detail=f"'{f.ssid}' is being advertised by {f.bssid} with {observed}; it has only ever been seen with "
                       f"{', '.join(ev['known_security']) or 'another mode'}.")]
            if str(observed).lower().startswith("open"):
                signals.append(SignalContribution(name="open_twin", label="Open network under a secured name", points=OPEN_TWIN_BONUS,
                                                  detail="An open copy of a secured network lets anyone who joins it be intercepted."))
            alert_type, title = AlertType.EVIL_TWIN, f"'{f.ssid}' advertised with a different security mode"
        else:
            signals = [SignalContribution(
                name="unexpected_channel", label="Access point on a new channel", points=ROGUE_AP_BASE,
                detail=f"{f.bssid} ('{f.ssid}') appeared on channel {ev['observed_channel']}; in {ev['sightings']} earlier sightings it used "
                       f"{', '.join(str(c) for c in ev['channels_used_before'])}. Access points do change channel — this is the weakest signal.")]
            alert_type, title = AlertType.ROGUE_AP, f"Access point {f.bssid} changed channel"
        wigle = None
        if f.kind != "unexpected_channel":
            wigle = await self._wigle_evidence(f.bssid)
            self._apply_wigle(signals, wigle)
        score = _sum_points(signals)
        return NetworkAlert(
            alert_id=uuid4().hex, timestamp=event.timestamp, alert_type=alert_type, severity=severity_from_score(score), fused_score=score, title=title,
            involved=[x for x in [f.bssid, f.ssid] if x], trigger_type=f"Watched network: {f.kind.replace('_', ' ')}",
            evidence=AlertEvidence(signals=signals, wigle=wigle, raw={**ev, "bssid": f.bssid, "ssid": f.ssid, "channel": ap.get("channel"),
                                                                      "signal_percent": ap.get("signal_percent"), "security": ap.get("security"),
                                                                      "oui": ap.get("oui")}),
            recommended_actions=[
                "If this is your own access point, confirm it (Network → Access points → Mark known) and this alert will not repeat",
                f"Otherwise verify the legitimate hardware for '{f.ssid}' before connecting to {f.bssid}",
                "Locate the transmitter (signal strength, channel)"])

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _wigle_evidence(self, bssid: Optional[str]) -> Optional[WigleResult]:
        """Look the BSSID up and return the alert-evidence view (None if there is no BSSID)."""
        if not bssid:
            return None
        return to_evidence(await self._wigle.lookup_bssid(bssid), bssid)

    def _apply_wigle(self, signals: list[SignalContribution], wigle: Optional[WigleResult]) -> None:
        """Fold a real WiGLE result into an AP alert's signals."""
        if wigle is None:
            return
        if not wigle.available:
            signals.append(SignalContribution(
                name="wigle",
                label="WiGLE public history",
                available=False,
                points=0.0,
                detail="WiGLE history could not be consulted — AP scored on other signals only.",
                reason=wigle.reason,
            ))
            return
        if not wigle.found:
            signals.append(SignalContribution(
                name="wigle",
                label="WiGLE public history",
                points=WIGLE_UNSEEN_BONUS,
                detail="WiGLE has NO public record of this BSSID — consistent with a "
                       "brand-new / never-before-seen transmitter.",
            ))
        elif wigle.total_observations >= WIGLE_ESTABLISHED_MIN_OBS:
            signals.append(SignalContribution(
                name="wigle",
                label="WiGLE public history",
                points=WIGLE_ESTABLISHED_PENALTY,
                detail=(
                    f"WiGLE has {wigle.total_observations} public observations "
                    f"(first seen {wigle.first_seen}) — an established, mapped AP."
                ),
            ))
        else:
            signals.append(SignalContribution(
                name="wigle",
                label="WiGLE public history",
                points=WIGLE_UNSEEN_BONUS / 2,
                detail=(
                    f"WiGLE has only {wigle.total_observations} observation(s) — "
                    f"a sparsely-seen AP."
                ),
            ))

    def _new_device_alert(self, event: SensorEvent) -> NetworkAlert:
        signals = [SignalContribution(
            name="new_device",
            label="New device on network",
            points=NEW_DEVICE_BASE,
            detail=f"Device {event.mac} ({event.ip or 'ip unknown'}) has not been observed before.",
        )]
        score = _sum_points(signals)
        return NetworkAlert(
            alert_id=uuid4().hex,
            timestamp=event.timestamp,
            alert_type=AlertType.NEW_DEVICE,
            severity=severity_from_score(score),
            fused_score=score,
            title=f"New device joined: {event.mac}",
            device_mac=event.mac,
            device_ip=event.ip,
            involved=[x for x in [event.mac, event.ip] if x],
            trigger_type="First observation of this MAC on the monitored network",
            evidence=AlertEvidence(signals=signals, raw=event.raw),
            recommended_actions=[
                "Confirm this device is authorised on your network",
                f"If unknown, isolate {event.mac} and investigate",
            ],
        )
