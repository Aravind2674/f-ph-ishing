"""
Packet → observation helpers (A3-3)
===================================

Pure functions over scapy packets (IPv4 *and* IPv6), kept apart from the sensors so they can be tested by replaying a PCAP
fixture.  They report what the packet says and nothing more.

DNS
---
* **queries** (``qr == 0``): who asked for which name, with the query type;
* **responses** (``qr == 1``): the *answer* — rcode (NOERROR / NXDOMAIN / SERVFAIL …), and the A / AAAA / CNAME records with their
  TTLs.  A response is addressed *to* the client, so the device is the packet's destination, not its source.  Knowing which IPs a
  name resolved to is what lets a later connection to a bare IP be tied back to a domain, and NXDOMAIN bursts are the signature of
  a domain-generation algorithm (B13).
* **names that are not about the internet are dropped** and counted by reason: mDNS / LLMNR (multicast, ports 5353 / 5355), PTR
  reverse lookups and ``*.arpa``, ``.local`` / ``.lan`` / ``.home`` / ``.internal`` hosts, single-label hostnames, DNS-SD service
  names (``_tcp`` / ``_udp``) and malformed names.  They are noise for reputation lookups and — worse — a private hostname is
  something the user does not want sent to a third party (A0-10).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Optional

_MAX_ANSWERS = 16
_LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".localdomain", ".localhost", ".intranet", ".corp", ".private", ".home.arpa")
_QTYPE_PTR = 12
_QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
_RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass
class L3:
    src: Optional[str]
    dst: Optional[str]
    version: int                     # 4 | 6 | 0 (no IP layer)


@dataclass
class DnsAnswer:
    name: str
    type: str
    data: str
    ttl: int


@dataclass
class DnsObservation:
    response: bool
    qname: str
    qtype: int
    qtype_name: str
    rcode: int
    rcode_name: str
    client_mac: Optional[str]
    client_ip: Optional[str]
    server_ip: Optional[str]
    answers: list[DnsAnswer] = field(default_factory=list)
    answer_count: int = 0
    transport: str = "udp"


def l3_of(pkt: Any) -> L3:
    try:
        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            return L3(str(ip.src), str(ip.dst), 4)
        if pkt.haslayer("IPv6"):
            ip = pkt["IPv6"]
            return L3(str(ip.src), str(ip.dst), 6)
    except Exception:
        pass
    return L3(None, None, 0)


def mac_of(pkt: Any) -> tuple[Optional[str], Optional[str]]:
    try:
        if pkt.haslayer("Ether"):
            e = pkt["Ether"]
            return str(e.src).lower(), str(e.dst).lower()
    except Exception:
        pass
    return None, None


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def clean_name(raw: Any) -> str:
    return _text(raw).rstrip(".").lower()


def is_multicast_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


def name_filter_reason(qname: str, qtype: int) -> Optional[str]:
    """Why a DNS name should not be analysed (``None`` = analyse it)."""
    if not qname:
        return "empty"
    if len(qname) > 253 or any(len(label) > 63 for label in qname.split(".")) or "\x00" in qname:
        return "malformed"
    if qtype == _QTYPE_PTR or qname.endswith(".arpa"):
        return "ptr"
    if "." not in qname:
        return "single_label"
    if qname.endswith(_LOCAL_SUFFIXES):
        return "local_name"
    if qname.startswith("_") or "._tcp." in qname or "._udp." in qname:
        return "service_discovery"
    return None


def _rr_data(rr: Any, rtype: int) -> str:
    data = getattr(rr, "rdata", "")
    if rtype in (1, 28):
        return _text(data)
    if rtype in (5, 2, 12):
        return clean_name(data)
    if isinstance(data, list):                      # TXT: a list of byte strings
        return " ".join(_text(x) for x in data)[:200]
    return _text(data)[:200]


def parse_dns(pkt: Any) -> tuple[Optional[DnsObservation], Optional[str]]:
    """``(observation, None)`` for a DNS packet worth analysing, ``(None, reason)`` for one that is deliberately ignored,
    ``(None, None)`` when the packet is not DNS at all."""
    if not pkt.haslayer("DNS"):
        return None, None
    dns = pkt["DNS"]
    l3 = l3_of(pkt)
    src_mac, dst_mac = mac_of(pkt)
    transport = "tcp" if pkt.haslayer("TCP") else "udp"
    l4 = pkt["UDP"] if pkt.haslayer("UDP") else (pkt["TCP"] if pkt.haslayer("TCP") else None)
    if l4 is not None and 5353 in (int(l4.sport), int(l4.dport)):
        return None, "mdns"
    if l4 is not None and 5355 in (int(l4.sport), int(l4.dport)):
        return None, "llmnr"
    if is_multicast_ip(l3.dst):
        return None, "multicast"
    if not pkt.haslayer("DNSQR"):
        return None, "no_question"
    qr = pkt["DNSQR"]
    qname = clean_name(qr.qname)
    qtype = int(qr.qtype)
    reason = name_filter_reason(qname, qtype)
    if reason:
        return None, reason
    is_response = int(dns.qr or 0) == 1
    obs = DnsObservation(
        response=is_response, qname=qname, qtype=qtype, qtype_name=_QTYPE_NAMES.get(qtype, str(qtype)),
        rcode=int(dns.rcode or 0), rcode_name=_RCODE_NAMES.get(int(dns.rcode or 0), str(int(dns.rcode or 0))),
        # a query comes FROM the client; a response goes TO it
        client_mac=dst_mac if is_response else src_mac,
        client_ip=l3.dst if is_response else l3.src,
        server_ip=l3.src if is_response else l3.dst,
        transport=transport,
    )
    if is_response:
        count = int(dns.ancount or 0)
        obs.answer_count = count
        for i in range(min(count, _MAX_ANSWERS)):
            try:
                rr = dns.an[i]
                rtype = int(rr.type)
                obs.answers.append(DnsAnswer(clean_name(rr.rrname), _QTYPE_NAMES.get(rtype, str(rtype)), _rr_data(rr, rtype), int(rr.ttl)))
            except Exception:                        # a malformed record must not discard the rest of the packet
                break
    return obs, None
