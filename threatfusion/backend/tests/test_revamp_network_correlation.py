"""Revamp T2c — correlation that produces real alerts, and the reputation gate that keeps monitoring from burning quota.

Everything here is deterministic: injected clocks, a fake URL model that flags or clears every name, synthetic scapy packets, respx for
the one remote lookup (VirusTotal).  Nothing reaches a real provider.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
import pytest
import respx
from scapy.all import ARP, Ether

from app.core.config import get_settings
from app.core.feeds import FeedStore
from app.core.hub import hub
from app.ingestion.blocklists import Ja3BlacklistFeed
from app.network.baseline_store import BaselineStore
from app.network.correlation import BLOCKLIST_POINTS, TLS_FINGERPRINT_POINTS, CorrelationEngine
from app.network.enrichment.app_layer import AppLayerScorer
from app.network.enrichment.wigle import WigleClient
from app.network.heuristics import BeaconDetector, NxdomainBurst, name_anomaly, shannon_entropy
from app.network.models import AlertType, EventType, SensorEvent, Severity
from app.network.reputation_gate import ReputationGate, VtBudget
from app.network.resolution import ResolutionMap
from app.network.sensor.arp_sensor import ArpSensor
from tests.netfakes import url_model

T0 = 1_760_000_000.0
MAC, IP = "aa:bb:cc:00:00:50", "192.168.0.50"


class Clock:
    def __init__(self, t: float = T0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def ev(kind: EventType, at: float = T0, **kw) -> SensorEvent:
    return SensorEvent(event_type=kind, timestamp=datetime.fromtimestamp(at, tz=timezone.utc), sensor=kw.pop("sensor", "dns"), **kw)


def query(name: str, at: float = T0, mac: str = MAC) -> SensorEvent:
    return ev(EventType.DNS_QUERY, at, mac=mac, ip=IP, domain=name, raw={"qtype": 1})


def response(name: str, at: float = T0, *, rcode: str = "NOERROR", answers=(), mac: str = MAC) -> SensorEvent:
    return ev(EventType.DNS_RESPONSE, at, mac=mac, ip=IP, domain=name, raw={"rcode_name": rcode, "answers": list(answers), "answer_count": len(answers)})


def hello(sni: str | None, dst: str = "203.0.113.7", ja3: str = "a" * 32, at: float = T0, mac: str = MAC) -> SensorEvent:
    return ev(EventType.TLS_CLIENT_HELLO, at, sensor="tls", mac=mac, ip=IP, domain=sni, raw={"dst_ip": dst, "dst_port": 443, "ja3": ja3, "ja4": "t13d"})


@pytest.fixture(autouse=True)
def _tmp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'net.db').as_posix()}")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def make_engine(tmp_path, clock: Clock | None = None, **env) -> CorrelationEngine:
    store = BaselineStore(str(tmp_path / "base.db"), min_observations=3)
    await store.init()
    return CorrelationEngine(store, AppLayerScorer(), WigleClient("", ""), clock=clock or Clock())


# ── name <-> IP map ─────────────────────────────────────────────────────────
def test_resolutions_respect_ttl_and_are_bounded() -> None:
    clock = Clock(100.0)
    m = ResolutionMap(max_entries=3, clock=clock)
    m.add("www.example.com", ["93.184.216.34"], 60, also=["edge.example.net"])
    assert m.names_for("93.184.216.34") == ["www.example.com", "edge.example.net"] or set(m.names_for("93.184.216.34")) == {"www.example.com", "edge.example.net"}
    clock.t += 59
    assert m.name_for("93.184.216.34") is not None
    clock.t += 2
    assert m.name_for("93.184.216.34") is None and len(m) == 0, "an answer is forgotten when its TTL runs out"
    for i in range(5):
        m.add(f"h{i}.example", [f"10.0.0.{i}"], 600)
    assert len(m) == 3 and m.name_for("10.0.0.0") is None and m.name_for("10.0.0.4") == "h4.example", "least recently used goes first"
    m.add("zero.example", ["10.9.9.9"], 0)
    assert m.name_for("10.9.9.9") == "zero.example", "TTL 0 is kept for a second so the connection that follows can be explained"


# ── heuristics ──────────────────────────────────────────────────────────────
def test_nxdomain_burst_fires_once_per_window_at_the_threshold() -> None:
    b = NxdomainBurst(threshold=5, window_seconds=60)
    hits = [b.observe("dev", f"xk{i}q.example", T0 + i) for i in range(12)]
    assert [h is not None for h in hits] == [False, False, False, False, True] + [False] * 7
    first = hits[4]
    assert first.count == 5 and first.names[0] == "xk0q.example"
    assert b.observe("dev", "later.example", T0 + 200) is None, "the old answers slid out of the window"
    assert b.observe("other", "x.example", T0) is None, "counted per device"


def test_name_anomaly_flags_random_and_long_labels_not_ordinary_ones() -> None:
    assert name_anomaly("www.example.com", "example") is None
    assert name_anomaly("mail.wikipedia.org", "wikipedia") is None
    random = name_anomaly("xjqkzplwvmnbtrfs.example", "xjqkzplwvmnbtrfs")
    assert random is not None and "bits of entropy" in random.reasons[0] and random.entropy >= 3.8
    assert name_anomaly("internationalization.example", "internationalization") is None, "long, but ordinary letters repeat: low entropy"
    assert name_anomaly("xjqkzplwvmnb.example", "xjqkzplwvmnb") is None, "12 distinct characters is at most log2(12) = 3.58 bits"
    assert name_anomaly("xjqkzplwvmnb.example", "xjqkzplwvmnb", min_len=12, min_entropy=3.5) is not None, "...but a looser setting catches it"
    assert name_anomaly("a" * 45 + ".example", "a" * 45).reasons[0].startswith("a 45-character label")
    assert name_anomaly("sub." + "b" * 30 + "." + "c" * 30 + "." + "d" * 40 + ".com", "d").reasons, "a very long whole name is flagged"
    assert shannon_entropy("aaaa") == 0.0 and shannon_entropy("") == 0.0


def test_beaconing_needs_many_regular_long_lived_contacts() -> None:
    d = BeaconDetector(min_events=8, min_span=300, max_jitter=0.15, cooldown=3600)
    found = [d.observe("dev", "c2.example.net", T0 + i * 60) for i in range(10)]            # one a minute, perfectly regular
    assert found[:7] == [None] * 7, "fewer than 8 contacts is not a series"
    assert found[7] is not None and found[7].period_seconds == 60.0 and found[7].jitter == 0.0 and found[7].count == 8
    assert all(f is None for f in found[8:]), "reported once per cooldown"

    jittery = BeaconDetector()
    times = [0, 40, 130, 150, 290, 330, 480, 500, 700, 710]
    assert all(jittery.observe("dev", "web.example", T0 + t) is None for t in times), "irregular contacts (a person browsing) are not beacons"

    fast = BeaconDetector()
    assert all(fast.observe("dev", "chatty.example", T0 + i * 1.0) is None for i in range(100)), "contacts <2 s apart are one visit"
    short = BeaconDetector()
    assert all(short.observe("dev", "burst.example", T0 + i * 20) is None for i in range(12)), "a series must last at least 300 s"


# ── the reputation gate ─────────────────────────────────────────────────────
VT_BODY = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 60, "suspicious": 1, "undetected": 4},
                                   "reputation": -10, "last_analysis_date": 1_700_000_000}}}
VT_ANY = r"https://www\.virustotal\.com/api/v3/.*"


@pytest.fixture
def live(monkeypatch):
    monkeypatch.setenv("USE_MOCK_DATA", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key-for-tests-123456")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_a_thousand_flagged_names_cause_no_more_virustotal_calls_than_the_budget(live, monkeypatch) -> None:
    monkeypatch.setenv("NETWORK_VT_PER_MINUTE", "1")
    get_settings.cache_clear()
    gate = ReputationGate()
    with url_model(flagged=True), respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=VT_ANY).respond(200, json=VT_BODY)
        results = [await gate.assess(f"host{i}.com") for i in range(1000)]
        assert route.call_count == 1, "the network's VirusTotal budget is 1 per minute"
    assert results[0].source == "virustotal" and results[0].corroborated is True and results[0].vt_malicious_count == 5
    assert all(r.source == "budget_exhausted" and r.corroborated is False and r.flagged is False and "budget" in r.reason for r in results[1:])
    assert gate.stats["vt_calls"] == 1 and gate.stats["budget_exhausted"] == 999


@pytest.mark.asyncio
async def test_the_cache_answers_repeats_by_registered_domain_without_asking_again(live, monkeypatch) -> None:
    monkeypatch.setenv("NETWORK_VT_PER_MINUTE", "100")
    get_settings.cache_clear()
    gate = ReputationGate()
    with url_model(flagged=True) as model, respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=VT_ANY).respond(200, json=VT_BODY)
        for i in range(1000):
            await gate.assess(f"cdn{i % 7}.shared{i % 10}.com")          # 1000 queries, 10 registered domains
        assert route.call_count == 10
    assert gate.stats["cache_hits"] == 990 and model.calls == 20          # flagged names are scored twice (once more for the evidence)
    r = await gate.assess("anything.shared3.com")
    assert r.source == "cache" and r.cached_from == "virustotal" and r.target == "anything.shared3.com"


@pytest.mark.asyncio
async def test_concurrent_queries_for_one_domain_share_one_evaluation(live, monkeypatch) -> None:
    monkeypatch.setenv("NETWORK_VT_PER_MINUTE", "100")
    get_settings.cache_clear()
    gate = ReputationGate()
    with url_model(flagged=True) as model, respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=VT_ANY).respond(200, json=VT_BODY)
        out = await asyncio.gather(*(gate.assess(f"a{i}.same-domain.com") for i in range(50)))
        assert route.call_count == 1
    assert gate.stats["dedup_joins"] == 49 and model.calls == 2
    assert len({r.vt_malicious_count for r in out}) == 1


@pytest.mark.asyncio
async def test_private_names_and_ip_literals_cost_nothing(live) -> None:
    gate = ReputationGate()
    with url_model(flagged=True) as model, respx.mock(assert_all_called=False) as router:
        out = [await gate.assess(n) for n in ("printer.local", "nas", "1.0.168.192.in-addr.arpa", "93.184.216.34", "a/b?c=d.com")]
        assert len(router.calls) == 0 and model.calls == 0
    assert all(r.available is False and r.source == "private" for r in out)
    assert "third-party" in out[0].reason and "not looked up passively" in out[3].reason


@pytest.mark.asyncio
async def test_a_model_that_finds_nothing_ends_the_check_before_any_provider(live) -> None:
    gate = ReputationGate()
    with url_model(score=0.01, flagged=False) as model, respx.mock(assert_all_called=False) as router:
        r = await gate.assess("ordinary-shop.com")
        assert len(router.calls) == 0 and model.calls == 1, "no explanation is computed for a name that is not flagged"
    assert r.source == "url_model_only" and r.flagged is False and r.corroborated is False and r.ml_score == 0.01


@pytest.mark.asyncio
async def test_an_unloaded_model_spends_nothing_and_says_so(live) -> None:
    gate = ReputationGate()
    with url_model() as model, respx.mock(assert_all_called=False) as router:
        model.loaded = False
        r = await gate.assess("whatever.com")
        assert len(router.calls) == 0
    assert r.available is False and "not loaded" in r.reason


@pytest.mark.asyncio
async def test_one_engine_is_not_corroboration(live, monkeypatch) -> None:
    monkeypatch.setenv("NETWORK_VT_PER_MINUTE", "5")
    get_settings.cache_clear()
    one = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 60, "suspicious": 0, "undetected": 9}, "reputation": 0}}}
    with url_model(flagged=True), respx.mock(assert_all_called=False) as router:
        router.get(url__regex=VT_ANY).respond(200, json=one)
        r = await ReputationGate().assess("lonely-flag.com")
    assert r.source == "virustotal" and r.vt_malicious_count == 1 and r.flagged is False and r.corroborated is False


def test_the_virustotal_budget_is_a_rolling_minute_and_cache_hits_give_the_slot_back() -> None:
    clock = Clock(0.0)
    b = VtBudget(2, clock)
    assert b.try_acquire() and b.try_acquire() and not b.try_acquire()
    clock.t = 30
    assert not b.try_acquire()
    clock.t = 61
    assert b.try_acquire() and b.try_acquire(), "both slots, used at t=0, have expired"
    assert not b.try_acquire()
    b.refund()
    assert b.try_acquire() and not b.try_acquire()
    assert not VtBudget(0, clock).try_acquire(), "0 = the network never calls VirusTotal"


@pytest.mark.asyncio
async def test_the_gate_reports_what_each_stage_saved(live, monkeypatch) -> None:
    gate = ReputationGate()
    with url_model(score=0.01, flagged=False):
        await gate.assess("a.com"), await gate.assess("a.com"), await gate.assess("printer.local")
    s = gate.summary()
    assert s["names"] == 3 and s["cache_hits"] == 1 and s["private"] == 1 and s["model_clear"] == 1 and s["vt_budget_per_minute"] == 1


# ── JA3 blacklist feed ──────────────────────────────────────────────────────
# Fixture in the layout abuse.ch documents for ja3_fingerprints.csv. The hashes are made up for this test; the layout itself was NOT
# verified against the live file (see docs/REVAMP.md).
SSLBL_SAMPLE = b"""################################################################
# abuse.ch SSLBL JA3 Fingerprint Blacklist                     #
################################################################
# ja3_md5,Firstseen,Lastseen,Listingreason
0123456789abcdef0123456789abcdef,2019-01-01 10:00:00,2020-02-02 11:00:00,Dridex
fedcba9876543210fedcba9876543210,2018-05-05 00:00:00,2018-06-06 00:00:00,Tofsee
not-a-hash,2020-01-01,2020-01-01,junk
"""


def test_ja3_feed_parses_the_documented_layout_and_ignores_comments_and_junk() -> None:
    feed = Ja3BlacklistFeed(False, store=FeedStore())
    rows = feed.parse(SSLBL_SAMPLE)
    assert set(rows) == {"0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"}
    assert rows["0123456789abcdef0123456789abcdef"] == {"first": "2019-01-01 10:00:00", "last": "2020-02-02 11:00:00", "reason": "Dridex"}


@pytest.mark.asyncio
async def test_ja3_match_distinguishes_listed_not_listed_and_never_downloaded() -> None:
    store = FeedStore()
    feed = Ja3BlacklistFeed(False, store=store)
    assert (await feed.match("0123456789abcdef0123456789abcdef"))[0] == "unavailable", "never downloaded is UNKNOWN, not 'not listed'"
    await store.replace("sslbl_ja3", feed.parse(SSLBL_SAMPLE), source_url="sslbl_ja3")
    status, row = await feed.match("0123456789ABCDEF0123456789abcdef")
    assert status == "listed" and row["reason"] == "Dridex"
    assert await feed.match("f" * 32) == ("not_listed", None)


# ── correlation: TLS, DNS answers, heuristics ───────────────────────────────
@pytest.mark.asyncio
async def test_a_listed_ja3_raises_a_tls_fingerprint_alert_capped_at_medium(tmp_path) -> None:
    store = hub.feeds
    await store.replace("sslbl_ja3", Ja3BlacklistFeed(False, store=store).parse(SSLBL_SAMPLE), source_url="sslbl_ja3")
    engine = await make_engine(tmp_path)
    with url_model(score=0.01, flagged=False):
        alerts = await engine.correlate(hello("update.example.org", ja3="0123456789abcdef0123456789abcdef"))
    a = next(x for x in alerts if x.alert_type == AlertType.TLS_FINGERPRINT)
    assert a.severity == Severity.MEDIUM and a.fused_score == TLS_FINGERPRINT_POINTS < 50, "abuse.ch does not false-positive test SSLBL JA3 entries"
    detail = a.evidence.signals[0].detail
    assert "Dridex" in detail and "not false-positive tested" in detail and a.evidence.raw["ja4"] == "t13d"
    again = await engine.correlate(hello("update.example.org", ja3="0123456789abcdef0123456789abcdef", at=T0 + 100))
    assert [x for x in again if x.alert_type == AlertType.TLS_FINGERPRINT] == [], "the same device + fingerprint is reported once per window"
    with url_model(score=0.01, flagged=False):
        other = await engine.correlate(hello("update.example.org", ja3="f" * 32, mac="aa:bb:cc:00:00:99", at=T0 + 200))
    assert [x for x in other if x.alert_type == AlertType.TLS_FINGERPRINT] == []


@pytest.mark.asyncio
async def test_without_the_feed_no_fingerprint_alert_is_invented(tmp_path) -> None:
    engine = await make_engine(tmp_path)
    with url_model(score=0.01, flagged=False):
        alerts = await engine.correlate(hello("x.example.org", ja3="0123456789abcdef0123456789abcdef"))
    assert [a for a in alerts if a.alert_type == AlertType.TLS_FINGERPRINT] == []


@pytest.mark.asyncio
async def test_a_hello_without_sni_is_explained_by_the_dns_answer_that_preceded_it(live, tmp_path) -> None:
    clock = Clock()
    engine = await make_engine(tmp_path, clock)
    answers = [{"name": "sneaky-site.com", "type": "A", "data": "203.0.113.7", "ttl": 300}]
    await engine.correlate(response("sneaky-site.com", answers=answers))
    assert engine.resolutions.name_for("203.0.113.7") == "sneaky-site.com"
    two = {"data": {"attributes": {"last_analysis_stats": {"malicious": 4, "harmless": 60, "suspicious": 0, "undetected": 6}, "reputation": 0}}}
    with url_model(flagged=True), respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=VT_ANY).respond(200, json=two)
        alerts = await engine.correlate(hello(None, dst="203.0.113.7", ja3="b" * 32, at=T0 + 1))
        assert route.call_count == 1, "the name found through the DNS answer was assessed (and VirusTotal asked: the model flagged it)"
    cross = [a for a in alerts if a.alert_type == AlertType.CROSS_LAYER_HIT]
    assert len(cross) == 1 and cross[0].evidence.app_layer.target == "sneaky-site.com" and cross[0].evidence.raw["observed_via"] == "resolved_ip"
    unknown = await engine.correlate(hello(None, dst="198.51.100.1", at=T0 + 2))
    assert unknown == [], "an address nothing resolved to has no name to assess"
    clock.t += 400
    assert engine.resolutions.name_for("203.0.113.7") is None, "the TTL ran out"


@pytest.mark.asyncio
async def test_a_url_score_alone_never_raises_a_cross_layer_alert(live, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETWORK_VT_PER_MINUTE", "0")                 # the network may not call VirusTotal at all
    get_settings.cache_clear()
    engine = await make_engine(tmp_path)
    with url_model(score=0.99, flagged=True), respx.mock(assert_all_called=False) as router:
        alerts = await engine.correlate(query("looks-bad-but-unverified.com"))
        assert len(router.calls) == 0
    assert [a for a in alerts if a.alert_type == AlertType.CROSS_LAYER_HIT] == []
    # (a first sighting on an unestablished profile raises nothing else either)


@pytest.mark.asyncio
async def test_the_dns_query_and_the_sni_of_one_visit_are_one_observation(tmp_path, monkeypatch) -> None:
    engine = await make_engine(tmp_path)
    for _ in range(4):
        await engine._store.record_dns(MAC, "google.com", IP)
    with url_model(score=0.01, flagged=False):
        first = await engine.correlate(query("quiet-novel.example.org", T0))
        second = await engine.correlate(hello("quiet-novel.example.org", at=T0 + 0.3))
    assert [a.alert_type for a in first] == [AlertType.BEHAVIORAL_DEVIATION]
    assert second == [], "the SNI of the same visit is not a second observation"
    profile = await engine._store.get_profile(MAC)
    assert profile.dns_observations == 5, "the baseline counted the visit once"


@pytest.mark.asyncio
async def test_an_nxdomain_burst_raises_one_evidence_carrying_alert(tmp_path) -> None:
    engine = await make_engine(tmp_path)
    alerts = []
    for i in range(25):
        alerts += await engine.correlate(response(f"qzx{i}kvw.example", T0 + i, rcode="NXDOMAIN"))
    burst = [a for a in alerts if a.alert_type == AlertType.DGA_SUSPECT]
    assert len(burst) == 1 and burst[0].severity == Severity.MEDIUM
    assert burst[0].evidence.raw["count"] == 20 and "qzx0kvw.example" in burst[0].evidence.raw["names"]
    assert "not proof of malware" in burst[0].evidence.signals[0].detail
    quiet = await make_engine(tmp_path)
    assert [a for i in range(10) for a in await quiet.correlate(response(f"typo{i}.example", T0 + i, rcode="NXDOMAIN"))] == []


@pytest.mark.asyncio
async def test_a_random_looking_name_is_flagged_with_its_evidence_but_a_popular_one_is_not(tmp_path) -> None:
    engine = await make_engine(tmp_path)
    with url_model(score=0.01, flagged=False):
        odd = await engine.correlate(query("xjqkzplwvmnbtrfs.example.org"))
        popular = await engine.correlate(query("d3x9a7b2c1f0e8q9z4.google.com", T0 + 10))
    a = next(x for x in odd if x.alert_type == AlertType.DNS_ANOMALY)
    assert a.severity == Severity.LOW and a.evidence.raw["label"] == "xjqkzplwvmnbtrfs" and a.evidence.raw["entropy_bits_per_char"] >= 3.5
    assert [x for x in popular if x.alert_type == AlertType.DNS_ANOMALY] == [], "a popular registered domain is skipped (mock Tranco ranks google.com)"


@pytest.mark.asyncio
async def test_regular_check_ins_are_reported_as_beaconing_with_period_and_jitter(tmp_path) -> None:
    engine = await make_engine(tmp_path)
    alerts = []
    with url_model(score=0.01, flagged=False):
        for i in range(10):
            alerts += await engine.correlate(query("updates-check.example.org", T0 + i * 60))
    beacon = [a for a in alerts if a.alert_type == AlertType.BEACONING]
    assert len(beacon) == 1 and beacon[0].evidence.raw["period_seconds"] == 60.0 and beacon[0].evidence.raw["count"] == 8
    assert "every 60 s" in beacon[0].title


# ── ARP ─────────────────────────────────────────────────────────────────────
GW_IP, GW_MAC, ATT_MAC = "192.168.0.1", "aa:bb:cc:00:00:01", "de:ad:be:ef:00:66"


def arp(op: int, mac: str, ip: str, at: float, *, pdst: str | None = None):
    p = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=op, hwsrc=mac, psrc=ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=pdst or ip)
    p.time = at
    return p


def run_arp(sensor: ArpSensor, packets) -> list[SensorEvent]:
    out: list[SensorEvent] = []
    for p in packets:
        out += list(sensor.handle(p))
    return out


def sensor(**kw) -> ArpSensor:
    return ArpSensor(lambda e: None, "eth0", GW_IP, conflict_window=300, flood_threshold=5, flood_window=10, multi_ip_threshold=4,
                     multi_ip_window=60, **kw)


def test_a_gateway_mac_change_is_always_reported_even_after_a_long_silence() -> None:
    events = run_arp(sensor(), [arp(2, GW_MAC, GW_IP, T0), arp(2, ATT_MAC, GW_IP, T0 + 86_400)])
    conflict = next(e for e in events if e.event_type == EventType.ARP_CONFLICT)
    assert conflict.raw["is_gateway"] is True and (conflict.old_mac, conflict.new_mac) == (GW_MAC, ATT_MAC)


def test_a_dhcp_rebind_of_an_ordinary_address_is_not_a_conflict_but_a_live_clash_is() -> None:
    events = run_arp(sensor(), [arp(2, "aa:aa:aa:00:00:01", "192.168.0.77", T0), arp(2, "bb:bb:bb:00:00:02", "192.168.0.77", T0 + 3600)])
    assert [e for e in events if e.event_type == EventType.ARP_CONFLICT] == [], "the old holder had been silent for an hour: the lease moved"
    clash = run_arp(sensor(), [arp(2, "aa:aa:aa:00:00:01", "192.168.0.77", T0), arp(2, "bb:bb:bb:00:00:02", "192.168.0.77", T0 + 20)])
    assert len([e for e in clash if e.event_type == EventType.ARP_CONFLICT]) == 1


def test_a_gratuitous_arp_flood_is_counted_over_the_packets_own_time() -> None:
    packets = [arp(1, ATT_MAC, "192.168.0.99", T0 + i * 0.5) for i in range(8)]                 # psrc == pdst: gratuitous
    flood = [e for e in run_arp(sensor(), packets) if e.event_type == EventType.ARP_FLOOD]
    assert len(flood) == 1 and flood[0].raw["count"] == 5 and flood[0].raw["threshold"] == 5
    slow = [arp(1, ATT_MAC, "192.168.0.99", T0 + i * 30) for i in range(8)]
    assert [e for e in run_arp(sensor(), slow) if e.event_type == EventType.ARP_FLOOD] == []
    ordinary = [arp(1, ATT_MAC, "192.168.0.99", T0 + i * 0.5, pdst="192.168.0.1") for i in range(8)]   # requests for other hosts
    assert [e for e in run_arp(sensor(), ordinary) if e.event_type == EventType.ARP_FLOOD] == []


def test_one_mac_claiming_many_ips_is_reported_but_the_gateways_mac_is_exempt() -> None:
    claims = [arp(2, ATT_MAC, f"192.168.0.{100 + i}", T0 + i) for i in range(5)]
    multi = [e for e in run_arp(sensor(), claims) if e.event_type == EventType.ARP_MULTI_IP]
    assert len(multi) == 1 and multi[0].raw["ip_count"] == 4 and len(multi[0].raw["ips"]) == 4
    router = [arp(2, GW_MAC, GW_IP, T0)] + [arp(2, GW_MAC, f"192.168.0.{100 + i}", T0 + 1 + i) for i in range(6)]
    assert [e for e in run_arp(sensor(), router) if e.event_type == EventType.ARP_MULTI_IP] == [], "proxy ARP is normal for a router"


@pytest.mark.asyncio
async def test_arp_events_become_scored_deduplicated_alerts(tmp_path) -> None:
    engine = await make_engine(tmp_path)
    events = run_arp(sensor(), [arp(2, GW_MAC, GW_IP, T0), arp(2, ATT_MAC, GW_IP, T0 + 5)])
    conflict = next(e for e in events if e.event_type == EventType.ARP_CONFLICT)
    first = await engine.correlate(conflict)
    assert first[0].alert_type == AlertType.ARP_SPOOF and first[0].severity == Severity.CRITICAL and "Gateway" in first[0].title
    assert await engine.correlate(conflict) == [], "the same finding is raised once per window"

    flood = next(e for e in run_arp(sensor(), [arp(1, ATT_MAC, "192.168.0.99", T0 + i * 0.5) for i in range(6)]) if e.event_type == EventType.ARP_FLOOD)
    a = (await engine.correlate(flood))[0]
    assert a.alert_type == AlertType.ARP_FLOOD and a.severity == Severity.MEDIUM and "re-announce" in a.evidence.signals[0].detail
    multi = next(e for e in run_arp(sensor(), [arp(2, ATT_MAC, f"192.168.0.{100 + i}", T0 + i) for i in range(5)]) if e.event_type == EventType.ARP_MULTI_IP)
    m = (await engine.correlate(multi))[0]
    assert m.alert_type == AlertType.ARP_MULTI_IP and "virtual machines" in m.evidence.signals[0].detail


# ── warm-up and baseline ────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_fresh_install_learns_quietly_then_announces_arrivals(tmp_path) -> None:
    clock = Clock()
    engine = await make_engine(tmp_path, clock)
    engine.begin_session(fresh=True)
    assert engine.warming_up
    present = ev(EventType.ARP_OBSERVED, mac="aa:aa:aa:00:00:01", ip="192.168.0.20", sensor="arp")
    assert await engine.correlate(present) == [], "already on the network when monitoring began: learned, not announced"
    clock.t += float(get_settings().NETWORK_WARMUP_SECONDS) + 1
    assert not engine.warming_up
    arrival = ev(EventType.ARP_OBSERVED, mac="aa:aa:aa:00:00:02", ip="192.168.0.21", sensor="arp")
    alerts = await engine.correlate(arrival)
    assert [a.alert_type for a in alerts] == [AlertType.NEW_DEVICE]
    assert await engine._store.is_known_device("aa:aa:aa:00:00:01"), "the warm-up device was still learned"


@pytest.mark.asyncio
async def test_an_established_install_has_no_warm_up(tmp_path) -> None:
    engine = await make_engine(tmp_path)
    engine.begin_session(fresh=False)
    assert not engine.warming_up
    alerts = await engine.correlate(ev(EventType.ARP_OBSERVED, mac="aa:aa:aa:00:00:03", ip="192.168.0.22", sensor="arp"))
    assert [a.alert_type for a in alerts] == [AlertType.NEW_DEVICE]


@pytest.mark.asyncio
async def test_a_flagged_name_on_a_blocklist_raises_a_cross_layer_alert_once(tmp_path) -> None:
    engine = await make_engine(tmp_path)
    first = await engine.correlate(query("malicious-evil.example.com"))
    cross = [a for a in first if a.alert_type == AlertType.CROSS_LAYER_HIT]
    assert len(cross) == 1 and cross[0].evidence.app_layer.source == "local_blocklist"
    assert next(s for s in cross[0].evidence.signals if s.name == "app_layer").points == BLOCKLIST_POINTS
    again = await engine.correlate(query("malicious-evil.example.com", T0 + 30))
    assert [a for a in again if a.alert_type == AlertType.CROSS_LAYER_HIT] == []
