"""
ThreatFusion – ARP Sensor
==========================

Passively sniffs ARP traffic on the monitored LAN (scapy + Npcap) to
surface two real signals:

1. **Device presence** — every ARP reply/announcement reveals a real
   (IP, MAC) binding. Emitted as ``ARP_OBSERVED`` so the service can decide,
   against the persisted baseline, whether a device is genuinely new.

2. **ARP spoofing / MITM** — when an IP that was bound to one MAC is
   suddenly claimed by a *different* MAC, that is a classic ARP
   cache-poisoning indicator. Emitted as ``ARP_CONFLICT`` with both the
   previously-observed and newly-claimed MAC as raw evidence.

The IP→MAC table is built purely from observed frames; there are no seeded
bindings. If a gateway IP is configured, conflicts involving it are tagged
so the correlation engine can weight them more heavily.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from app.network.models import EventType, SensorEvent
from app.network.sensor.base import BaseSensor, EmitFn, load_scapy

logger = logging.getLogger(__name__)


class ArpSensor(BaseSensor):
    name = "arp"

    def __init__(self, emit: EmitFn, interface: str = "", gateway_ip: str = "") -> None:
        super().__init__(emit)
        self._interface = interface or None
        self._gateway_ip = gateway_ip or None
        # Real, observation-built binding table: ip -> mac
        self._ip_mac: dict[str, str] = {}
        # MACs already reported this session — keeps the presence signal to one
        # event per device rather than one per ARP frame (correlation and the
        # persisted baseline decide genuine newness).
        self._seen_macs: set[str] = set()

    def _run(self) -> None:
        scapy = load_scapy()
        ARP = scapy.ARP

        def handle(pkt) -> None:
            if not pkt.haslayer(ARP):
                return
            arp = pkt[ARP]
            # op 1 = who-has (request), 2 = is-at (reply). Both carry a real
            # source binding in psrc/hwsrc.
            ip = arp.psrc
            mac = (arp.hwsrc or "").lower()
            if not ip or not mac or ip == "0.0.0.0":
                return

            prior = self._ip_mac.get(ip)
            if prior and prior != mac:
                # Same IP, different MAC → cache-poisoning indicator.
                is_gateway = self._gateway_ip is not None and ip == self._gateway_ip
                self._emit(SensorEvent(
                    event_type=EventType.ARP_CONFLICT,
                    timestamp=datetime.now(timezone.utc),
                    sensor=self.name,
                    ip=ip,
                    mac=mac,
                    old_mac=prior,
                    new_mac=mac,
                    raw={
                        "arp_op": int(arp.op),
                        "is_gateway": is_gateway,
                        "gateway_ip": self._gateway_ip,
                    },
                ))
            self._ip_mac[ip] = mac

            # Report presence once per newly-seen MAC (not per frame).
            if mac not in self._seen_macs:
                self._seen_macs.add(mac)
                self._emit(SensorEvent(
                    event_type=EventType.ARP_OBSERVED,
                    timestamp=datetime.now(timezone.utc),
                    sensor=self.name,
                    ip=ip,
                    mac=mac,
                    raw={"arp_op": int(arp.op)},
                ))

        logger.info("ARP sensor sniffing (iface=%s)", self._interface or "default")
        scapy.sniff(
            filter="arp",
            prn=handle,
            store=False,
            iface=self._interface,
            stop_filter=self._should_stop,
        )
