"""
ThreatFusion – TLS ClientHello sensor (A3-3, B13)
===================================================

The first client→server bytes of a TLS connection are unencrypted.  This sensor reads them to learn two things DNS cannot tell:

* the **SNI** — which server name the client asked for, even when the lookup bypassed the local resolver (DNS-over-HTTPS, a hard-coded
  resolver, a cached answer) — and
* the **JA3 / JA4 client fingerprint** — which TLS software is talking (``tls_hello.py``).

Only the ClientHello is read: nothing past the handshake is parsed, no payload is stored, and the connection is never touched.
Hellos larger than one TCP segment are reassembled (bounded, ``HelloAssembler``).  QUIC / HTTP-3 (UDP 443) is not covered.

Scope is the same as for DNS: a laptop sees its own connections.
"""

from __future__ import annotations

from typing import Any, Iterable

from app.network.models import EventType, SensorEvent
from app.network.sensor.capture import CaptureSensor, packet_time
from app.network.sensor.packets import l3_of, mac_of
from app.network.tls_hello import HelloAssembler, ja3, ja4


class TlsSensor(CaptureSensor):
    name = "tls"
    bpf = "tcp dst port 443"

    def __init__(self, emit, interface: str = "", **kw) -> None:
        super().__init__(emit, interface, **kw)
        self._assembler = HelloAssembler()

    def wants(self, pkt: Any) -> bool:
        return bool(pkt.haslayer("TCP") and pkt.haslayer("Raw") and int(pkt["TCP"].dport) == 443)

    def handle(self, pkt: Any) -> Iterable[SensorEvent]:
        if not pkt.haslayer("TCP") or not pkt.haslayer("Raw"):
            return ()
        tcp = pkt["TCP"]
        payload = bytes(pkt["Raw"].load)
        l3 = l3_of(pkt)
        flow = (l3.src, int(tcp.sport), l3.dst, int(tcp.dport))
        hello = self._assembler.feed(flow, payload)
        if hello is None:
            return ()
        _, ja3_hash = ja3(hello)
        src_mac, _ = mac_of(pkt)
        return (SensorEvent(
            event_type=EventType.TLS_CLIENT_HELLO, timestamp=packet_time(pkt), sensor=self.name,
            mac=src_mac, ip=l3.src, domain=hello.sni,
            raw={"dst_ip": l3.dst, "dst_port": int(tcp.dport), "ja3": ja3_hash, "ja4": ja4(hello),
                 "alpn": [a.decode("ascii", "replace") for a in hello.alpn[:4]], "tls_version": hello.client_version,
                 "has_sni": hello.sni is not None},
        ),)
