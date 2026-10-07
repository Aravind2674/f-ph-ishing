"""
ThreatFusion – Correlation & Fusion Scoring Engine
====================================================

Turns raw :class:`SensorEvent` observations into scored
:class:`NetworkAlert` objects. This is where the three differentiators
become one number:

1. **Cross-layer correlation** — an observed domain/IP is scored by the real
   App-Layer pipeline (:class:`AppLayerScorer`) and folded in.
2. **WiGLE as a signal** — a candidate rogue/evil-twin AP's BSSID is looked
   up against WiGLE's real public history and folded in.
3. **Behavioural baselining** — the observed behaviour is compared against
   the device's learned profile (:class:`BaselineStore`) and folded in.

Every alert's ``fused_score`` (0–100) is the clamped sum of explicit
:class:`SignalContribution` points, so the score is fully reconstructable
from the evidence — nothing is opaque or invented. When a signal is
unavailable it contributes 0 points and records the real reason.

The fusion weights below are transparent expert priors (mirroring the
philosophy of the App-Layer ``baseline`` scorer), chosen so that:
* a confirmed malicious-domain contact by a known device lands High/Critical,
* an evil-twin whose BSSID has *zero* WiGLE history lands High,
* a brand-new device or a novel-but-benign domain lands Low/Medium.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from app.network.baseline_store import BaselineStore
from app.network.enrichment.app_layer import AppLayerScorer
from app.network.enrichment.wigle import WigleClient, to_evidence
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

logger = logging.getLogger(__name__)


# ── Fusion weights (transparent expert priors) ──────────────────────────
ARP_SPOOF_BASE = 60.0
ARP_SPOOF_GATEWAY_BONUS = 25.0
NEW_DEVICE_BASE = 30.0
CROSS_LAYER_BASE = 20.0          # known device reaching a flagged domain
APP_LAYER_WEIGHT = 70.0          # multiplied by App-Layer ml_score [0,1]
BEHAVIORAL_DEVIATION_POINTS = 30.0
EVIL_TWIN_BASE = 50.0
ROGUE_AP_BASE = 20.0
WIGLE_UNSEEN_BONUS = 32.0        # BSSID with zero public history → suspicious
WIGLE_ESTABLISHED_PENALTY = -18.0  # long public history → reassuring
WIGLE_ESTABLISHED_MIN_OBS = 5


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


def severity_from_score(score: float) -> Severity:
    """Map a 0–100 fused score to a severity band.

    Bands mirror the App-Layer's ``_get_ml_label`` thresholds (scaled ×100)
    so severity means the same thing across both layers.
    """
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
        Adapter that reuses the App-Layer scoring pipeline.
    wigle : WigleClient
        Real WiGLE public-history client.
    """

    def __init__(
        self,
        store: BaselineStore,
        app_scorer: AppLayerScorer,
        wigle: WigleClient,
    ) -> None:
        self._store = store
        self._app = app_scorer
        self._wigle = wigle
        # Dedup guard so a device's "new device" alert fires at most once.
        self._alerted_new_devices: set[str] = set()
        # Session cache of MACs already persisted, to avoid a DB round-trip on
        # every repeat ARP presence observation for an already-known device.
        self._active_macs: set[str] = set()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def correlate(self, event: SensorEvent) -> list[NetworkAlert]:
        """Produce zero or more scored alerts from one raw event."""
        try:
            if event.event_type == EventType.ARP_CONFLICT:
                return await self._handle_arp_conflict(event)
            if event.event_type == EventType.ARP_OBSERVED:
                return await self._handle_arp_observed(event)
            if event.event_type == EventType.DNS_QUERY:
                return await self._handle_dns(event)
            if event.event_type == EventType.EVIL_TWIN:
                return await self._handle_evil_twin(event)
            if event.event_type == EventType.ROGUE_AP:
                return await self._handle_rogue_ap(event)
        except Exception:
            logger.exception("Correlation failed for event %s", event.event_type)
        return []

    # ------------------------------------------------------------------
    # Handlers
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
        return [self._new_device_alert(event)]

    async def _handle_arp_conflict(self, event: SensorEvent) -> list[NetworkAlert]:
        # Record the newly-claiming MAC as a device too.
        if event.new_mac:
            await self._store.observe_device(event.new_mac, event.ip)

        is_gateway = bool(event.raw.get("is_gateway"))
        signals = [
            SignalContribution(
                name="arp_conflict",
                label="ARP cache poisoning",
                points=ARP_SPOOF_BASE,
                detail=(
                    f"IP {event.ip} was bound to {event.old_mac} but is now "
                    f"claimed by {event.new_mac} — a MITM / ARP-spoofing indicator."
                ),
            )
        ]
        if is_gateway:
            signals.append(SignalContribution(
                name="gateway_targeted",
                label="Gateway targeted",
                points=ARP_SPOOF_GATEWAY_BONUS,
                detail=f"The spoofed IP {event.ip} is the configured gateway — "
                       f"whole-network interception is possible.",
            ))

        score = _sum_points(signals)
        return [NetworkAlert(
            alert_id=uuid4().hex,
            timestamp=event.timestamp,
            alert_type=AlertType.ARP_SPOOF,
            severity=severity_from_score(score),
            fused_score=score,
            title=f"ARP spoofing on {event.ip}",
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

    async def _handle_dns(self, event: SensorEvent) -> list[NetworkAlert]:
        if not event.mac or not event.domain:
            return []

        alerts: list[NetworkAlert] = []

        # 1) Device newness (covers ARP-less deployments), deduped.
        was_known = await self._store.is_known_device(event.mac)
        if not was_known and event.mac not in self._alerted_new_devices:
            await self._store.observe_device(event.mac, event.ip)
            self._alerted_new_devices.add(event.mac)
            alerts.append(self._new_device_alert(event))

        # 2) Learn from this observation, then compare against the profile.
        await self._store.record_dns(event.mac, event.domain, event.ip)
        comparison = await self._store.compare_dns(event.mac, event.domain)

        # 3) Cross-layer: score the observed domain via the App-Layer pipeline.
        app = await self._app.score(event.domain, "domain")

        signals: list[SignalContribution] = []

        # App-Layer contribution
        if app.available:
            pts = round((app.ml_score or 0.0) * APP_LAYER_WEIGHT, 1)
            liveness = "live" if app.live else "mock"
            signals.append(SignalContribution(
                name="app_layer",
                label="App-Layer domain intelligence",
                points=pts,
                detail=(
                    f"App-Layer scored '{event.domain}' as {app.ml_label} "
                    f"(ml={app.ml_score:.2f}, VT {app.vt_malicious_count}/"
                    f"{app.vt_total_engines} engines malicious, {liveness})."
                ),
            ))
        else:
            signals.append(SignalContribution(
                name="app_layer",
                label="App-Layer domain intelligence",
                available=False,
                points=0.0,
                detail="App-Layer sub-score unavailable — degraded to other signals.",
                reason=app.reason,
            ))

        # Behavioural deviation contribution
        if comparison.established and comparison.is_new_domain:
            signals.append(SignalContribution(
                name="behavioral_deviation",
                label="Behavioural deviation",
                points=BEHAVIORAL_DEVIATION_POINTS,
                detail=comparison.deviation_detail,
            ))
        else:
            signals.append(SignalContribution(
                name="behavioral_deviation",
                label="Behavioural deviation",
                points=0.0,
                detail=comparison.deviation_detail,
            ))

        # Decide whether this rises to an alert, and of what type.
        cross_layer = app.available and app.flagged
        deviation = comparison.established and comparison.is_new_domain

        if not cross_layer and not deviation:
            return alerts  # normal traffic (only possibly a new-device alert)

        if cross_layer:
            signals.insert(0, SignalContribution(
                name="cross_layer_contact",
                label="Known device → flagged domain",
                points=CROSS_LAYER_BASE,
                detail=(
                    f"Device {event.mac} contacted '{event.domain}', which the "
                    f"App-Layer flags as malicious/suspicious."
                ),
            ))
            alert_type = AlertType.CROSS_LAYER_HIT
            title = f"Device contacted flagged domain {event.domain}"
            trigger = "DNS query to an App-Layer-flagged domain"
            actions = [
                f"Block domain {event.domain} at the resolver/firewall",
                f"Isolate device {event.mac} ({event.ip}) and inspect it",
                "Review the device's recent DNS history for related indicators",
            ]
        else:
            alert_type = AlertType.BEHAVIORAL_DEVIATION
            title = f"Behavioural deviation: {event.domain}"
            trigger = "DNS query to a domain outside the device's learned baseline"
            actions = [
                f"Confirm whether {event.domain} is expected for this device",
                f"Watch device {event.mac} for further anomalous contacts",
                "If unexpected, isolate the device and block the domain",
            ]

        score = _sum_points(signals)
        alerts.append(NetworkAlert(
            alert_id=uuid4().hex,
            timestamp=event.timestamp,
            alert_type=alert_type,
            severity=severity_from_score(score),
            fused_score=score,
            title=title,
            device_mac=event.mac,
            device_ip=event.ip,
            involved=[x for x in [event.mac, event.ip, event.domain] if x],
            trigger_type=trigger,
            evidence=AlertEvidence(
                signals=signals,
                app_layer=app,
                baseline=comparison,
                raw={"domain": event.domain, "qtype": event.raw.get("qtype")},
            ),
            recommended_actions=actions,
        ))
        return alerts

    async def _handle_evil_twin(self, event: SensorEvent) -> list[NetworkAlert]:
        signals = [SignalContribution(
            name="evil_twin",
            label="Monitored SSID on unknown BSSID",
            points=EVIL_TWIN_BASE,
            detail=(
                f"SSID '{event.ssid}' is being advertised by BSSID {event.bssid}, "
                f"which has never carried that network name before."
            ),
        )]
        wigle = await self._wigle_evidence(event.bssid)
        self._apply_wigle(signals, wigle)

        score = _sum_points(signals)
        return [NetworkAlert(
            alert_id=uuid4().hex,
            timestamp=event.timestamp,
            alert_type=AlertType.EVIL_TWIN,
            severity=severity_from_score(score),
            fused_score=score,
            title=f"Possible evil-twin for '{event.ssid}'",
            involved=[x for x in [event.bssid, event.ssid] if x],
            trigger_type="Monitored SSID advertised by an unrecognised BSSID",
            evidence=AlertEvidence(
                signals=signals, wigle=wigle,
                raw={"channel": event.channel, "signal": event.signal, **event.raw},
            ),
            recommended_actions=[
                f"Verify the legitimate BSSID for SSID '{event.ssid}'",
                "Warn users not to connect until confirmed",
                "Locate the rogue transmitter (signal strength / channel triangulation)",
            ],
        )]

    async def _handle_rogue_ap(self, event: SensorEvent) -> list[NetworkAlert]:
        signals = [SignalContribution(
            name="rogue_ap",
            label="New access point in RF environment",
            points=ROGUE_AP_BASE,
            detail=f"BSSID {event.bssid} (SSID '{event.ssid}') appeared after the RF baseline was learned.",
        )]
        wigle = await self._wigle_evidence(event.bssid)
        self._apply_wigle(signals, wigle)

        score = _sum_points(signals)

        # Suppress low-value noise: an established, long-history neighbour AP
        # (real WiGLE record) that scores below Medium is not worth an alert.
        if (
            wigle is not None and wigle.available and wigle.found
            and wigle.total_observations >= WIGLE_ESTABLISHED_MIN_OBS
            and score < 25.0
        ):
            return []

        return [NetworkAlert(
            alert_id=uuid4().hex,
            timestamp=event.timestamp,
            alert_type=AlertType.ROGUE_AP,
            severity=severity_from_score(score),
            fused_score=score,
            title=f"New access point: {event.ssid or event.bssid}",
            involved=[x for x in [event.bssid, event.ssid] if x],
            trigger_type="Previously-unseen BSSID in the monitored RF environment",
            evidence=AlertEvidence(
                signals=signals, wigle=wigle,
                raw={"channel": event.channel, "signal": event.signal, **event.raw},
            ),
            recommended_actions=[
                "Confirm whether this AP is authorised in your environment",
                "If unknown, investigate its location and purpose",
                "Consider it hostile until its WiGLE/physical provenance is verified",
            ],
        )]

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
