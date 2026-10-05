"""
ThreatFusion – DNS Sensor
==========================

Passively captures DNS (UDP/TCP 53, IPv4 and IPv6) — both what a device **asked** for and what it was **told** (A3-3):

* ``DNS_QUERY``    — device X wanted domain Y (query type recorded);
* ``DNS_RESPONSE`` — the rcode (NOERROR / NXDOMAIN / SERVFAIL …) and the A / AAAA / CNAME answers with their TTLs, so a domain
  can be tied to the IPs it resolved to (a later connection to a bare IP is then explainable) and NXDOMAIN bursts — the
  signature of a domain-generation algorithm — can be counted (B13).

mDNS / LLMNR, PTR reverse lookups, ``.local`` / ``.lan`` hosts, single-label names and DNS-SD service names are dropped and counted
by reason (``status().filtered``): they are noise for reputation checks and private hostnames must not leave the machine.

Scope (stated, not hidden): a sensor on a laptop sees *its own* DNS plus broadcast traffic.  DNS from other devices is only visible
at a gateway / mirror port, or through Zeek / Suricata logs (``log_sensor.py``).  Encrypted DNS (DoH / DoT) is invisible to this
sensor by design; the TLS sensor still sees the SNI of those connections.

The sensor only reports what it saw; deciding whether anything is malicious is the correlation engine's job.
"""

from __future__ import annotations

from typing import Any, Iterable

from app.network.models import EventType, SensorEvent
from app.network.sensor.capture import CaptureSensor, packet_time
from app.network.sensor.packets import parse_dns


class DnsSensor(CaptureSensor):
    name = "dns"
    bpf = "port 53"                 # udp + tcp, v4 + v6 (an answer too large for UDP arrives over TCP)

    def handle(self, pkt: Any) -> Iterable[SensorEvent]:
        obs, reason = parse_dns(pkt)
        if obs is None:
            if reason:
                self.note_filtered(reason)
            return ()
        ts = packet_time(pkt)
        if not obs.response:
            return (SensorEvent(
                event_type=EventType.DNS_QUERY, timestamp=ts, sensor=self.name,
                mac=obs.client_mac, ip=obs.client_ip, domain=obs.qname,
                raw={"qtype": obs.qtype, "qtype_name": obs.qtype_name, "server": obs.server_ip, "transport": obs.transport},
            ),)
        return (SensorEvent(
            event_type=EventType.DNS_RESPONSE, timestamp=ts, sensor=self.name,
            mac=obs.client_mac, ip=obs.client_ip, domain=obs.qname,
            raw={
                "qtype": obs.qtype, "qtype_name": obs.qtype_name, "rcode": obs.rcode, "rcode_name": obs.rcode_name,
                "answer_count": obs.answer_count, "server": obs.server_ip, "transport": obs.transport,
                "answers": [{"name": a.name, "type": a.type, "data": a.data, "ttl": a.ttl} for a in obs.answers],
            },
        ),)
