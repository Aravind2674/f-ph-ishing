"""
ThreatFusion – DNS Sensor
==========================

Passively sniffs DNS *queries* on the monitored network (scapy + Npcap,
UDP/53). Every observed query is a real record of "device X wanted to reach
domain Y" — the raw material for both:

* **Cross-layer correlation** (differentiator #1): the observed domain is
  routed through the App-Layer pipeline downstream.
* **Behavioural baselining** (differentiator #3): the (device, domain) pair
  is folded into the device's learned profile.

The sensor only reports what it saw: source MAC (from the Ethernet frame),
source IP, and the queried name. It does not decide whether anything is
malicious — that is the correlation engine's job.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.network.models import EventType, SensorEvent
from app.network.sensor.base import BaseSensor, EmitFn, load_scapy

logger = logging.getLogger(__name__)


class DnsSensor(BaseSensor):
    name = "dns"

    def __init__(self, emit: EmitFn, interface: str = "") -> None:
        super().__init__(emit)
        self._interface = interface or None

    def _run(self) -> None:
        scapy = load_scapy()
        DNS = scapy.DNS
        DNSQR = scapy.DNSQR
        IP = scapy.IP
        Ether = scapy.Ether

        def handle(pkt) -> None:
            if not pkt.haslayer(DNS):
                return
            dns = pkt[DNS]
            # qr == 0 → this is a query (not a response). We only learn from
            # what the device *asked for*.
            if dns.qr != 0 or dns.qdcount < 1 or not pkt.haslayer(DNSQR):
                return

            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            domain = qname.rstrip(".").lower()
            if not domain:
                return

            src_ip = pkt[IP].src if pkt.haslayer(IP) else None
            src_mac = pkt[Ether].src.lower() if pkt.haslayer(Ether) else None

            self._emit(SensorEvent(
                event_type=EventType.DNS_QUERY,
                timestamp=datetime.now(timezone.utc),
                sensor=self.name,
                mac=src_mac,
                ip=src_ip,
                domain=domain,
                raw={"qtype": int(pkt[DNSQR].qtype)},
            ))

        logger.info("DNS sensor sniffing (iface=%s)", self._interface or "default")
        scapy.sniff(
            filter="udp port 53",
            prn=handle,
            store=False,
            iface=self._interface,
            stop_filter=self._should_stop,
        )
