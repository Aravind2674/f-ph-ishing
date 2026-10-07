"""
One sniffer per interface, many parsers (revamp T2b)
====================================================

The sensors used to open one ``AsyncSniffer`` each (ARP, DNS, TLS): three capture handles on one interface, three copies of every
packet, three threads to stop.  :class:`SharedCapture` opens **one** sniffer with one BPF filter and hands each packet to the parsers
that want it (``CaptureSensor.wants``), so every packet is read from the driver once.

The filter keeps only what the parsers use::

    arp  or  port 53  or  (tcp dst port 443 and (ip6 or tcp[((tcp[12]&0xf0)>>2)]=0x16))

* ``arp`` — address-resolution traffic;
* ``port 53`` — DNS over UDP *and* TCP, IPv4 and IPv6;
* TLS: a TCP segment to port 443 whose payload starts with byte ``0x16`` (a TLS *handshake* record).  Classic BPF cannot index into an
  IPv6 payload, so IPv6 segments to 443 are let through and the TLS parser discards the non-handshake ones.

If the capture library rejects that expression, the sensor retries once with the plain ``arp or port 53 or tcp dst port 443`` (the
parsers then do the payload test) and says so in its status (``filter_fallback``).  Nothing about a failure is hidden: an interface that
cannot be opened is reported with the library's own message, exactly as for a single sensor.

Lifecycle is inherited from :class:`~app.network.sensor.capture.CaptureSensor` (idempotent start / stop, no leaked thread, verbatim open
errors).  The parsers are never started on their own: they are plain objects with a ``handle`` method and their own counters.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Sequence

from app.network.models import SensorEvent
from app.network.sensor.capture import CaptureSensor

logger = logging.getLogger(__name__)

BPF_FULL = "arp or port 53 or (tcp dst port 443 and (ip6 or tcp[((tcp[12]&0xf0)>>2)]=0x16))"
BPF_SAFE = "arp or port 53 or tcp dst port 443"
_FILTER_ERRORS = ("filter", "syntax error", "pcap_compile", "bpf", "expression")


class SharedCapture(CaptureSensor):
    name = "capture"

    def __init__(self, emit, interface: str = "", parsers: Sequence[CaptureSensor] = (), **kw) -> None:
        super().__init__(emit, interface, **kw)
        self.parsers: list[CaptureSensor] = list(parsers)
        self.bpf = BPF_FULL
        self.filter_fallback = False

    def start(self) -> None:
        for parser in self.parsers:
            parser.reset_counters()
        super().start()
        failed_on_filter = (not self.available and bool(self.reason) and not self._offline
                            and any(word in (self.reason or "").lower() for word in _FILTER_ERRORS))
        if failed_on_filter and self.bpf != BPF_SAFE:
            logger.warning("Capture filter rejected (%s); retrying with the plain filter", self.reason)
            self.bpf, self.filter_fallback = BPF_SAFE, True
            super().start()

    def handle(self, pkt: Any) -> Iterable[SensorEvent]:
        for parser in self.parsers:
            if parser.wants(pkt):
                parser._on_packet(pkt)                 # counts, parses, emits through its own (counting) emit
        return ()

    def parser_status(self, parser: CaptureSensor) -> dict[str, Any]:
        """One parser's health, in the shape every sensor reports: availability follows the shared capture."""
        from app.network.sensor.base import _iso

        return {
            "available": self.available,
            "running": bool(self.running and self._alive()),
            "reason": self.reason,
            "packets": parser.packets_seen,
            "events": parser.events_emitted,
            "last_event_at": _iso(parser.last_event_at),
            "handler_errors": parser.handler_errors,
            "filtered": dict(parser.filtered),
        }

    def status(self) -> dict[str, Any]:
        d = super().status()
        d.update({"filter": self.bpf, "filter_fallback": self.filter_fallback})
        return d
