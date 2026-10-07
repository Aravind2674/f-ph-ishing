"""A3-2 / A3-3: sensor lifecycle on AsyncSniffer, and PCAP-fixture replay of the DNS / TLS / ARP parsers.

The capture here is **synthetic** (built with scapy in the fixture below, with fixed packet timestamps) — there is no Npcap on the
development machine and a real capture would contain someone's traffic.  AsyncSniffer's offline reader needs neither, and runs the
same handlers as a live capture, so what is verified is the parsing and the lifecycle, not a particular network."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, IPv6, Raw, TCP, UDP, wrpcap

from app.network.models import EventType
from app.network.sensor.arp_sensor import ArpSensor
from app.network.sensor.capture import CaptureSensor
from app.network.sensor.dns_sensor import DnsSensor
from app.network.sensor.packets import name_filter_reason, parse_dns
from app.network.sensor.tls_sensor import TlsSensor
from tests.test_a3_tls_hello import build_hello

T0 = 1_760_000_000.0                       # fixed capture epoch: 2025-10-09 08:53:20 UTC
CLIENT_MAC, ROUTER_MAC = "aa:bb:cc:00:00:50", "aa:bb:cc:00:00:01"
CLIENT_IP, ROUTER_IP = "192.168.0.50", "192.168.0.1"


def _stamp(pkts):
    for i, p in enumerate(pkts):
        p.time = T0 + i * 0.25
    return pkts


def _udp53(src_mac, dst_mac, src, dst, sport, dport, dns, v6=False):
    ip = IPv6(src=src, dst=dst) if v6 else IP(src=src, dst=dst)
    return Ether(src=src_mac, dst=dst_mac) / ip / UDP(sport=sport, dport=dport) / dns


@pytest.fixture()
def pcap(tmp_path: Path) -> Path:
    pkts = [
        # 0: a query for www.example.com
        _udp53(CLIENT_MAC, ROUTER_MAC, CLIENT_IP, ROUTER_IP, 51000, 53, DNS(rd=1, qd=DNSQR(qname="www.example.com", qtype="A"))),
        # 1: the answer — CNAME + A + AAAA with TTLs
        _udp53(ROUTER_MAC, CLIENT_MAC, ROUTER_IP, CLIENT_IP, 53, 51000, DNS(
            qr=1, rd=1, ra=1, rcode=0, qd=DNSQR(qname="www.example.com"), ancount=3,
            an=DNSRR(rrname="www.example.com", type="CNAME", ttl=300, rdata="edge.example.net")
            / DNSRR(rrname="edge.example.net", type="A", ttl=60, rdata="93.184.216.34")
            / DNSRR(rrname="edge.example.net", type="AAAA", ttl=60, rdata="2606:2800:220:1:248:1893:25c8:1946"))),
        # 2: NXDOMAIN over IPv6
        _udp53(ROUTER_MAC, CLIENT_MAC, "fe80::1", "fe80::50", 53, 51001, DNS(qr=1, rcode=3, qd=DNSQR(qname="xjqkzplwv.example"), ancount=0), v6=True),
        # 3: an IPv6 query
        _udp53(CLIENT_MAC, ROUTER_MAC, "fe80::50", "fe80::1", 51002, 53, DNS(rd=1, qd=DNSQR(qname="ipv6.example.org", qtype="AAAA")), v6=True),
        # 4: mDNS (multicast, port 5353) — must be ignored
        _udp53(CLIENT_MAC, "01:00:5e:00:00:fb", CLIENT_IP, "224.0.0.251", 5353, 5353, DNS(qd=DNSQR(qname="printer.local"))),
        # 5: a PTR lookup — must be ignored
        _udp53(CLIENT_MAC, ROUTER_MAC, CLIENT_IP, ROUTER_IP, 51003, 53, DNS(rd=1, qd=DNSQR(qname="1.0.168.192.in-addr.arpa", qtype="PTR"))),
        # 6: a private hostname — must be ignored
        _udp53(CLIENT_MAC, ROUTER_MAC, CLIENT_IP, ROUTER_IP, 51004, 53, DNS(rd=1, qd=DNSQR(qname="nas.lan"))),
        # 7: TXT query (type recorded)
        _udp53(CLIENT_MAC, ROUTER_MAC, CLIENT_IP, ROUTER_IP, 51005, 53, DNS(rd=1, qd=DNSQR(qname="c2.example.net", qtype="TXT"))),
        # 8: a TLS ClientHello in one segment
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst="93.184.216.34") / TCP(sport=50100, dport=443, flags="PA") / Raw(build_hello(sni="Secure.Example.com")),
        # 9/10: a ClientHello split across two segments, with no SNI marker in the first
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst="203.0.113.7") / TCP(sport=50101, dport=443, flags="PA") / Raw(build_hello(sni="split.example.org", pad_to=1700)[:1400]),
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst="203.0.113.7") / TCP(sport=50101, dport=443, flags="PA") / Raw(build_hello(sni="split.example.org", pad_to=1700)[1400:]),
        # 11: not TLS on 443
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst="203.0.113.9") / TCP(sport=50102, dport=443, flags="PA") / Raw(b"GET / HTTP/1.1\r\n\r\n"),
        # 12: a hello over IPv6
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IPv6(src="2406:7400::50", dst="2606:2800:220:1::1") / TCP(sport=50103, dport=443, flags="PA") / Raw(build_hello(sni="v6.example.com")),
        # 13/14: ARP — one device claims .1, then a different MAC claims it
        Ether(src=ROUTER_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=ROUTER_MAC, psrc=ROUTER_IP, hwdst="ff:ff:ff:ff:ff:ff", pdst=ROUTER_IP),
        Ether(src="de:ad:be:ef:00:66", dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc="de:ad:be:ef:00:66", psrc=ROUTER_IP, hwdst="ff:ff:ff:ff:ff:ff", pdst=ROUTER_IP),
    ]
    path = tmp_path / "fixture.pcap"
    wrpcap(str(path), _stamp(pkts))
    return path


def replay(sensor_cls, pcap_path: Path, *args, **kw):
    events: list = []
    sensor = sensor_cls(events.append, *args, offline=str(pcap_path), **kw)
    sensor.start()
    deadline = time.monotonic() + 5
    while sensor._alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    sensor.stop()
    return sensor, events


# ── A3-3: DNS ───────────────────────────────────────────────────────────────
def test_dns_replay_gives_the_expected_fields(pcap: Path) -> None:
    sensor, events = replay(DnsSensor, pcap)
    by_type = lambda t: [e for e in events if e.event_type == t]
    queries, responses = by_type(EventType.DNS_QUERY), by_type(EventType.DNS_RESPONSE)
    assert [q.domain for q in queries] == ["www.example.com", "ipv6.example.org", "c2.example.net"]
    q0 = queries[0]
    assert (q0.mac, q0.ip) == (CLIENT_MAC, CLIENT_IP) and q0.raw["qtype_name"] == "A" and q0.raw["server"] == ROUTER_IP
    assert queries[1].ip == "fe80::50", "IPv6 queries are captured"
    assert queries[2].raw["qtype_name"] == "TXT"

    r0 = responses[0]
    assert r0.domain == "www.example.com" and r0.raw["rcode_name"] == "NOERROR" and r0.raw["answer_count"] == 3
    # the device in a response is the packet's DESTINATION
    assert (r0.mac, r0.ip, r0.raw["server"]) == (CLIENT_MAC, CLIENT_IP, ROUTER_IP)
    assert r0.raw["answers"] == [
        {"name": "www.example.com", "type": "CNAME", "data": "edge.example.net", "ttl": 300},
        {"name": "edge.example.net", "type": "A", "data": "93.184.216.34", "ttl": 60},
        {"name": "edge.example.net", "type": "AAAA", "data": "2606:2800:220:1:248:1893:25c8:1946", "ttl": 60},
    ]
    nx = responses[1]
    assert nx.raw["rcode_name"] == "NXDOMAIN" and nx.raw["answers"] == [] and nx.ip == "fe80::50"


def test_dns_noise_is_filtered_and_counted_by_reason(pcap: Path) -> None:
    sensor, events = replay(DnsSensor, pcap)
    domains = {e.domain for e in events}
    assert not domains & {"printer.local", "nas.lan", "1.0.168.192.in-addr.arpa"}
    assert sensor.filtered == {"mdns": 1, "ptr": 1, "local_name": 1}


@pytest.mark.parametrize("name,qtype,reason", [
    ("example.com", 1, None), ("a.b.example.co.uk", 28, None),
    ("1.0.168.192.in-addr.arpa", 12, "ptr"), ("x.ip6.arpa", 1, "ptr"), ("example.com", 12, "ptr"),
    ("localhost", 1, "single_label"), ("printer", 1, "single_label"), ("nas.local", 1, "local_name"), ("router.home.arpa", 1, "ptr"),
    ("_ipp._tcp.example.com", 33, "service_discovery"), ("", 1, "empty"), ("a" * 64 + ".com", 1, "malformed"),
])
def test_name_filter_reasons(name, qtype, reason) -> None:
    assert name_filter_reason(name, qtype) == reason


def test_packet_timestamps_are_the_capture_times(pcap: Path) -> None:
    _, events = replay(DnsSensor, pcap)
    q0, r0 = events[0], events[1]
    assert q0.timestamp == datetime.fromtimestamp(T0, tz=timezone.utc)
    assert (r0.timestamp - q0.timestamp).total_seconds() == pytest.approx(0.25), "an event is dated when the packet was seen, not when it was handled"


def test_a_dns_packet_that_is_not_dns_or_is_truncated_is_ignored(pcap: Path) -> None:
    pkt = Ether() / IP() / TCP() / Raw(b"hello")
    assert parse_dns(pkt) == (None, None)
    broken = _udp53(CLIENT_MAC, ROUTER_MAC, CLIENT_IP, ROUTER_IP, 1, 53, DNS(qr=1, qd=DNSQR(qname="ok.example.com"), ancount=5))
    obs, reason = parse_dns(broken)
    assert obs is not None and obs.answers == [] and obs.answer_count == 5, "a lying ancount does not crash the parser"


# ── A3-3: TLS SNI ───────────────────────────────────────────────────────────
def test_tls_replay_reads_sni_and_fingerprints_including_a_split_hello_and_ipv6(pcap: Path) -> None:
    sensor, events = replay(TlsSensor, pcap)
    assert [e.domain for e in events] == ["secure.example.com", "split.example.org", "v6.example.com"]
    first = events[0]
    assert first.event_type == EventType.TLS_CLIENT_HELLO and first.mac == CLIENT_MAC and first.ip == CLIENT_IP
    assert first.raw["dst_ip"] == "93.184.216.34" and first.raw["dst_port"] == 443
    assert len(first.raw["ja3"]) == 32 and first.raw["ja4"].startswith("t13d") and first.raw["alpn"] == ["h2", "http/1.1"]
    assert events[1].raw["dst_ip"] == "203.0.113.7", "the reassembled hello is attributed to its flow"
    assert events[2].ip == "2606:2800:220:1::1" or events[2].ip == "2406:7400::50"
    assert sensor.packets_seen == 15 and sensor.handler_errors == 0


# ── ARP ─────────────────────────────────────────────────────────────────────
def test_arp_replay_reports_presence_once_and_the_conflict(pcap: Path) -> None:
    sensor, events = replay(ArpSensor, pcap, "", ROUTER_IP)
    kinds = [e.event_type for e in events]
    assert kinds.count(EventType.ARP_OBSERVED) == 2 and kinds.count(EventType.ARP_CONFLICT) == 1
    conflict = next(e for e in events if e.event_type == EventType.ARP_CONFLICT)
    assert (conflict.old_mac, conflict.new_mac, conflict.ip) == (ROUTER_MAC, "de:ad:be:ef:00:66", ROUTER_IP)
    assert conflict.raw["is_gateway"] is True


# ── A3-2: lifecycle ─────────────────────────────────────────────────────────
class FakeSniffer:
    """Mimics AsyncSniffer: a thread that runs until stopped; ``fail`` makes it die at once with an exception."""

    instances: list = []

    def __init__(self, fail: str | None = None, feed: list | None = None, **kwargs) -> None:
        self.kwargs, self.fail, self.feed = kwargs, fail, feed or []
        self._stop = threading.Event()
        self.thread = None
        self.running = False
        self.exception = None
        FakeSniffer.instances.append(self)

    def _run(self) -> None:
        if self.fail:
            self.exception = ValueError(self.fail)
            return
        self.kwargs["started_callback"]()
        for pkt in self.feed:
            self.kwargs["prn"](pkt)
        self._stop.wait()                                   # a quiet link: no packet ever arrives to wake a stop_filter

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._run, name="fake-sniffer", daemon=True)
        self.thread.start()

    def stop(self, join: bool = True) -> None:
        if not self.running:
            raise RuntimeError("Not running ! (check .running attr)")
        self._stop.set()
        if join:
            self.thread.join()


class QuietSensor(CaptureSensor):
    name = "quiet"
    bpf = "udp"

    def handle(self, pkt):
        return ()


def fake_factory(**preset):
    return lambda **kw: FakeSniffer(**preset, **kw)


def leaked() -> list[str]:
    return [t.name for t in threading.enumerate() if t.name == "fake-sniffer" or t.name.startswith("sensor-")]


def test_start_stop_ten_times_leaves_no_thread_behind() -> None:
    s = QuietSensor(lambda e: None, "eth0", sniffer_factory=fake_factory())
    for _ in range(10):
        s.start()
        assert s.running and s.available
        s.stop()
        assert not s.running
    assert leaked() == []


def test_start_and_stop_are_idempotent() -> None:
    FakeSniffer.instances.clear()
    s = QuietSensor(lambda e: None, "eth0", sniffer_factory=fake_factory())
    s.stop()                                               # before start: harmless
    s.start()
    s.start()
    s.start()
    assert len(FakeSniffer.instances) == 1, "starting a running sensor must not create a second sniffer"
    s.stop()
    s.stop()
    assert leaked() == []
    s.start()                                              # a restart after a stop works
    assert s.running and len(FakeSniffer.instances) == 2
    s.stop()


def test_stop_returns_promptly_on_a_quiet_link() -> None:
    s = QuietSensor(lambda e: None, "eth0", sniffer_factory=fake_factory())
    s.start()
    t0 = time.monotonic()
    s.stop()
    assert time.monotonic() - t0 < 1.0


def test_a_sniffer_that_cannot_open_reports_the_verbatim_reason() -> None:
    s = QuietSensor(lambda e: None, "no-such-iface", sniffer_factory=fake_factory(fail="Interface 'no-such-iface' not found !"))
    s.start()
    assert not s.available and not s.running
    assert "not found" in s.reason and "ValueError" in s.reason
    assert leaked() == []


def test_a_sniffer_that_raises_in_its_constructor_is_reported_not_raised() -> None:
    def boom(**kw):
        raise OSError("bad BPF filter")

    s = QuietSensor(lambda e: None, "eth0", sniffer_factory=boom)
    s.start()
    assert not s.available and "bad BPF filter" in s.reason


def test_packets_are_counted_and_a_failing_handler_never_kills_the_capture() -> None:
    class Flaky(CaptureSensor):
        name = "flaky"

        def handle(self, pkt):
            if pkt.time == 2:
                raise RuntimeError("parser bug")
            return []

    class P:
        def __init__(self, t):
            self.time = t

    events: list = []
    s = Flaky(events.append, "eth0", sniffer_factory=fake_factory(feed=[P(1), P(2), P(3)]))
    s.start()
    time.sleep(0.2)
    st = s.status()
    s.stop()
    assert st["packets_seen"] == 3 and st["handler_errors"] == 1 and st["last_packet_at"].startswith("1970-01-01T00:00:03")


def test_missing_scapy_is_a_clear_reason(monkeypatch) -> None:
    import app.network.sensor.capture as cap

    def nope():
        raise RuntimeError("scapy/Npcap not available: boom")

    monkeypatch.setattr(cap, "load_scapy", nope)
    s = QuietSensor(lambda e: None, "eth0")
    s.start()
    assert not s.available and "scapy/Npcap not available" in s.reason


def test_the_real_asyncsniffer_replays_and_start_stop_x10_leaks_nothing(pcap: Path) -> None:
    before = {t.ident for t in threading.enumerate()}
    for _ in range(10):
        events: list = []
        s = DnsSensor(events.append, offline=str(pcap))
        s.start()
        deadline = time.monotonic() + 5
        while s._alive() and time.monotonic() < deadline:
            time.sleep(0.005)
        s.stop()
        assert len(events) == 5 and s.available, s.reason
    time.sleep(0.1)
    assert {t.ident for t in threading.enumerate()} - before == set(), "no sniffer thread may outlive its sensor"


def test_the_real_asyncsniffer_with_a_missing_interface_fails_loudly(monkeypatch) -> None:
    """With the real AsyncSniffer a wrong interface name is discovered when the thread starts: it must surface as the reason."""
    s = DnsSensor(lambda e: None, "definitely-not-an-interface")
    s.start()
    assert not s.available and not s.running
    assert s.reason, "whatever the platform says (interface not found, no Npcap, no privileges) is reported verbatim"
    s.stop()
    assert leaked() == []
