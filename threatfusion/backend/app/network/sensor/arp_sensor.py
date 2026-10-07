"""
ThreatFusion – ARP Sensor
==========================

Passively reads ARP traffic on the monitored LAN (scapy + Npcap).  It reports what it saw and four things derived from counting it:

1. **Device presence** — every ARP packet reveals a real (IP, MAC) binding.  Emitted once per MAC as ``ARP_OBSERVED`` so the service can
   decide, against the persisted baseline, whether a device is genuinely new.
2. **Binding change** (``ARP_CONFLICT``) — an IP that was bound to one MAC is now claimed by another.  The semantics follow arpwatch:
   *the gateway's MAC changing is always reported* (that is what a man-in-the-middle looks like to every client); any other IP is
   reported only if the **old MAC spoke within ``conflict_window`` seconds** — an address handed to a new device after a DHCP lease
   ran out is a re-bind, not an attack, and is applied silently.
3. **Gratuitous-ARP flood** (``ARP_FLOOD``) — one MAC announcing itself ``flood_threshold`` or more times inside ``flood_window``
   seconds (cache-poisoning tools re-announce continuously to keep the poison fresh).
4. **One MAC claiming many IPs** (``ARP_MULTI_IP``) — ``multi_ip_threshold`` or more different source IPs from one MAC inside
   ``multi_ip_window`` seconds.  The gateway's MAC is exempt (proxy ARP is normal for a router); a VM host with several virtual
   addresses will also trip it, which the alert says.

The table is built purely from observed frames — nothing is seeded — and is bounded (``MAX_BINDINGS``).  All windows run on the
packets' own capture times, so a PCAP replay behaves like the live capture.  ARP is IPv4 only: Neighbor-Discovery spoofing on IPv6
is **not** detected (stated, not implied).
"""

from __future__ import annotations

from collections import OrderedDict, deque
from typing import Any, Iterable, Optional

from app.network.models import EventType, SensorEvent
from app.network.sensor.capture import CaptureSensor, packet_time

MAX_BINDINGS = 8192


class ArpSensor(CaptureSensor):
    name = "arp"
    bpf = "arp"

    def __init__(self, emit, interface: str = "", gateway_ip: str = "", *, conflict_window: float = 300.0, flood_threshold: int = 30,
                 flood_window: float = 10.0, multi_ip_threshold: int = 8, multi_ip_window: float = 60.0, **kw) -> None:
        super().__init__(emit, interface, **kw)
        self._gateway_ip = gateway_ip or None
        self._conflict_window = float(conflict_window)
        self._flood_threshold, self._flood_window = max(2, flood_threshold), float(flood_window)
        self._multi_threshold, self._multi_window = max(2, multi_ip_threshold), float(multi_ip_window)
        # Real, observation-built binding table: ip -> (mac, epoch seconds it was last heard)
        self._ip_mac: "OrderedDict[str, tuple[str, float]]" = OrderedDict()
        # MACs already reported this session — keeps the presence signal to one event per device rather than one per ARP frame.
        self._seen_macs: set[str] = set()
        self._gratuitous: dict[str, deque[float]] = {}
        self._claims: dict[str, deque[tuple[float, str]]] = {}
        self._last_flood: dict[str, float] = {}
        self._last_multi: dict[str, float] = {}

    def reset_counters(self) -> None:
        super().reset_counters()
        self._ip_mac = OrderedDict()
        self._seen_macs = set()
        self._gratuitous, self._claims = {}, {}
        self._last_flood, self._last_multi = {}, {}

    def wants(self, pkt: Any) -> bool:
        return bool(pkt.haslayer("ARP"))

    def _gateway_mac(self) -> Optional[str]:
        entry = self._ip_mac.get(self._gateway_ip) if self._gateway_ip else None
        return entry[0] if entry else None

    def handle(self, pkt: Any) -> Iterable[SensorEvent]:
        if not pkt.haslayer("ARP"):
            return ()
        arp = pkt["ARP"]
        # op 1 = who-has (request), 2 = is-at (reply). Both carry a real source binding in psrc/hwsrc.
        ip = str(arp.psrc)
        mac = (arp.hwsrc or "").lower()
        if not ip or not mac or ip == "0.0.0.0":
            return ()
        ts = packet_time(pkt)
        now = ts.timestamp()
        out: list[SensorEvent] = []

        prior = self._ip_mac.get(ip)
        if prior is not None and prior[0] != mac:
            old_mac, heard = prior
            is_gateway = self._gateway_ip is not None and ip == self._gateway_ip
            if is_gateway or now - heard <= self._conflict_window:
                out.append(SensorEvent(
                    event_type=EventType.ARP_CONFLICT, timestamp=ts, sensor=self.name,
                    ip=ip, mac=mac, old_mac=old_mac, new_mac=mac,
                    raw={"arp_op": int(arp.op), "is_gateway": is_gateway, "gateway_ip": self._gateway_ip,
                         "old_mac_last_heard_seconds_ago": round(now - heard, 1)},
                ))
        if len(self._ip_mac) < MAX_BINDINGS or ip in self._ip_mac:
            self._ip_mac[ip] = (mac, now)
            self._ip_mac.move_to_end(ip)

        out.extend(self._flood_events(arp, ip, mac, ts, now))
        out.extend(self._multi_ip_events(ip, mac, ts, now))

        # Report presence once per newly-seen MAC (not per frame).
        if mac not in self._seen_macs and len(self._seen_macs) < MAX_BINDINGS:
            self._seen_macs.add(mac)
            out.append(SensorEvent(
                event_type=EventType.ARP_OBSERVED, timestamp=ts, sensor=self.name,
                ip=ip, mac=mac, raw={"arp_op": int(arp.op)},
            ))
        return out

    # ── derived signals ──────────────────────────────────────────────────
    def _flood_events(self, arp: Any, ip: str, mac: str, ts, now: float) -> list[SensorEvent]:
        if str(arp.pdst) != ip:                                    # gratuitous = announcing its own address (psrc == pdst)
            return []
        dq = self._gratuitous.setdefault(mac, deque())
        dq.append(now)
        while dq and dq[0] < now - self._flood_window:
            dq.popleft()
        if len(dq) < self._flood_threshold or now - self._last_flood.get(mac, float("-inf")) < self._flood_window:
            return []
        if len(self._gratuitous) > MAX_BINDINGS:
            self._gratuitous.pop(next(iter(self._gratuitous)))
        self._last_flood[mac] = now
        return [SensorEvent(event_type=EventType.ARP_FLOOD, timestamp=ts, sensor=self.name, ip=ip, mac=mac,
                            raw={"count": len(dq), "window_seconds": self._flood_window, "threshold": self._flood_threshold,
                                 "is_gateway": mac == self._gateway_mac()})]

    def _multi_ip_events(self, ip: str, mac: str, ts, now: float) -> list[SensorEvent]:
        gateway_mac = self._gateway_mac()
        if gateway_mac is not None and mac == gateway_mac:
            return []                                              # a router answering for many addresses is normal (proxy ARP)
        dq = self._claims.setdefault(mac, deque())
        dq.append((now, ip))
        while dq and dq[0][0] < now - self._multi_window:
            dq.popleft()
        distinct = sorted({i for _, i in dq})
        if len(distinct) < self._multi_threshold or now - self._last_multi.get(mac, float("-inf")) < self._multi_window:
            return []
        if len(self._claims) > MAX_BINDINGS:
            self._claims.pop(next(iter(self._claims)))
        self._last_multi[mac] = now
        return [SensorEvent(event_type=EventType.ARP_MULTI_IP, timestamp=ts, sensor=self.name, ip=ip, mac=mac,
                            raw={"ips": distinct[:20], "ip_count": len(distinct), "window_seconds": self._multi_window,
                                 "threshold": self._multi_threshold})]
