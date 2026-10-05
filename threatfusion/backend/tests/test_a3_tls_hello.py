"""A3-3 / B13: TLS ClientHello parsing, SNI, JA3 / JA4 and flow reassembly.

The hellos here are *built by the test* from a documented layout (RFC 8446 §4.1.2) — they are synthetic, not captured traffic —
so what is checked is the parser's arithmetic and its behaviour on truncated / hostile input, not that a given real browser
produces a given fingerprint (see the module docstring for what is and is not cross-checked)."""

from __future__ import annotations

import hashlib

import pytest

from app.network.tls_hello import (
    ClientHello,
    HelloAssembler,
    NeedMoreData,
    NotClientHello,
    is_grease,
    ja3,
    ja4,
    parse_client_hello,
)


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _ext(kind: int, body: bytes) -> bytes:
    return _u16(kind) + _u16(len(body)) + body


def build_hello(*, sni: str | None = "www.example.com", ciphers=(0x1301, 0x1302, 0xC02B), groups=(0x001D, 0x0017), point_formats=(0,),
                sig_algs=(0x0403, 0x0804), alpn=(b"h2", b"http/1.1"), versions=(0x0304, 0x0303), grease=False, extra_ext: bytes = b"",
                legacy_version=0x0303, with_extensions=True, pad_to: int = 0) -> bytes:
    suites = list(ciphers)
    exts = b""
    if grease:
        suites.insert(0, 0x0A0A)
        exts += _ext(0x1A1A, b"")
    if sni is not None:
        name = sni.encode("ascii")
        entry = b"\x00" + _u16(len(name)) + name
        exts += _ext(0, _u16(len(entry)) + entry)
    exts += _ext(11, bytes([len(point_formats)]) + bytes(point_formats))
    exts += _ext(10, _u16(2 * len(groups)) + b"".join(_u16(g) for g in groups))
    exts += _ext(13, _u16(2 * len(sig_algs)) + b"".join(_u16(s) for s in sig_algs))
    if alpn:
        items = b"".join(bytes([len(a)]) + a for a in alpn)
        exts += _ext(16, _u16(len(items)) + items)
    if versions:
        exts += _ext(43, bytes([2 * len(versions)]) + b"".join(_u16(v) for v in versions))
    exts += extra_ext
    if pad_to:
        exts += _ext(21, b"\x00" * pad_to)
    body = _u16(legacy_version) + b"\x11" * 32 + b"\x00" + _u16(2 * len(suites)) + b"".join(_u16(c) for c in suites) + b"\x01\x00"
    if with_extensions:
        body += _u16(len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + _u16(len(hs)) + hs


def test_sni_and_fields_are_read() -> None:
    h = parse_client_hello(build_hello())
    assert h.sni == "www.example.com"
    assert h.ciphers == [0x1301, 0x1302, 0xC02B]
    assert h.groups == [0x001D, 0x0017] and h.point_formats == [0] and h.sig_algs == [0x0403, 0x0804]
    assert h.alpn == [b"h2", b"http/1.1"] and h.supported_versions == [0x0304, 0x0303]
    assert h.client_version == 0x0303


def test_extension_order_is_preserved_because_the_fingerprint_depends_on_it() -> None:
    h = parse_client_hello(build_hello())
    assert h.extensions == [0, 11, 10, 13, 16, 43]


def test_sni_is_lowercased_and_a_missing_sni_is_none() -> None:
    assert parse_client_hello(build_hello(sni="WWW.Example.COM.")).sni == "www.example.com"
    assert parse_client_hello(build_hello(sni=None)).sni is None
    assert parse_client_hello(build_hello(with_extensions=False)).sni is None


def test_grease_values_are_ignored_in_both_fingerprints() -> None:
    plain, greased = parse_client_hello(build_hello()), parse_client_hello(build_hello(grease=True))
    assert is_grease(0x0A0A) and is_grease(0xFAFA) and not is_grease(0x1301) and not is_grease(0x0A1A)
    assert ja3(plain)[1] == ja3(greased)[1]
    assert ja4(plain) == ja4(greased)


def test_ja3_string_and_hash_follow_the_published_layout() -> None:
    h = parse_client_hello(build_hello())
    text, digest = ja3(h)
    assert text == "771,4865-4866-49195,0-11-10-13-16-43,29-23,0"
    assert digest == hashlib.md5(text.encode()).hexdigest()


def test_ja4_structure_and_sorting() -> None:
    h = parse_client_hello(build_hello())
    a, b, c = ja4(h).split("_")
    # t(cp) 13 (TLS 1.3 from supported_versions) d (SNI present) 03 ciphers 06 extensions, ALPN "h2" -> h2
    assert a == "t13d0306h2"
    assert b == hashlib.sha256(b"1301,1302,c02b").hexdigest()[:12]
    # extensions without SNI (0) and ALPN (16), sorted, then "_" and the signature algorithms in the order sent
    assert c == hashlib.sha256(b"000a,000b,000d,002b_0403,0804").hexdigest()[:12]


def test_ja4_has_no_sni_marker_when_there_is_no_sni_and_uses_00_without_alpn() -> None:
    h = parse_client_hello(build_hello(sni=None, alpn=()))
    # no SNI -> "i"; 3 ciphers; extensions 11, 10, 13, 43 -> 04; no ALPN -> "00"
    assert ja4(h).split("_")[0] == "t13i0304" + "00"


def test_ja4_is_order_insensitive_for_ciphers_but_ja3_is_not() -> None:
    a = parse_client_hello(build_hello(ciphers=(0x1301, 0x1302, 0xC02B)))
    b = parse_client_hello(build_hello(ciphers=(0xC02B, 0x1302, 0x1301)))
    assert ja4(a).split("_")[1] == ja4(b).split("_")[1]
    assert ja3(a)[1] != ja3(b)[1]


@pytest.mark.parametrize("bad", [b"", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"\x17\x03\x03\x00\x05hello", b"\x16\x03\x03\x00\x02\x02\x00",
                                  b"\x16\x03\x03\xff\xff" + b"\x01" * 20, b"\x00" * 64, bytes(range(256))])
def test_garbage_is_rejected_without_crashing(bad: bytes) -> None:
    with pytest.raises((NotClientHello, NeedMoreData)):
        parse_client_hello(bad)


def test_a_prefix_of_a_hello_asks_for_more_data_and_the_whole_parses() -> None:
    full = build_hello()
    for cut in (1, 3, 5, 6, 40, len(full) - 1):
        with pytest.raises(NeedMoreData):
            parse_client_hello(full[:cut])
    assert parse_client_hello(full).sni == "www.example.com"


def test_truncated_inside_a_complete_record_is_malformed_not_a_crash() -> None:
    full = bytearray(build_hello())
    # claim a cipher-suite list far longer than the record
    full[5 + 4 + 2 + 32 + 1: 5 + 4 + 2 + 32 + 1 + 2] = _u16(0x7FFF)
    with pytest.raises(NotClientHello):
        parse_client_hello(bytes(full))


def test_a_malformed_optional_extension_does_not_hide_the_sni() -> None:
    bad_alpn = _ext(16, b"\x00\xff\x7f")                       # list length larger than the body
    h = parse_client_hello(build_hello(extra_ext=bad_alpn))
    assert h.sni == "www.example.com"


def test_non_ascii_sni_is_not_trusted() -> None:
    entry = b"\x00" + _u16(3) + "é".encode("utf-8") + b"a"
    ext = _ext(0, _u16(len(entry)) + entry)
    raw = build_hello(sni=None, extra_ext=ext)
    assert parse_client_hello(raw).sni is None


def test_assembler_joins_a_hello_split_across_segments() -> None:
    full = build_hello(pad_to=1700)                            # a hello bigger than one 1500-byte frame, as with post-quantum key shares
    asm = HelloAssembler()
    flow = ("10.0.0.5", 50000, "93.184.216.34", 443)
    assert asm.feed(flow, full[:1400]) is None
    assert len(asm) == 1
    hello = asm.feed(flow, full[1400:])
    assert isinstance(hello, ClientHello) and hello.sni == "www.example.com"
    assert len(asm) == 0
    assert asm.feed(flow, b"\x17\x03\x03\x00\x01x") is None   # later segments of a decided flow are ignored


def test_assembler_ignores_non_tls_flows_and_stays_bounded() -> None:
    asm = HelloAssembler(max_flows=50)
    for i in range(500):
        assert asm.feed(("10.0.0.5", 1000 + i, "1.1.1.1", 443), b"GET / HTTP/1.1\r\n") is None
    assert len(asm) == 0
    hello = build_hello()
    for i in range(500):
        asm.feed(("10.0.0.6", 2000 + i, "1.1.1.1", 443), hello[:20])    # half-open flows
    assert len(asm) <= 50


def test_assembler_gives_up_on_a_flow_that_never_completes() -> None:
    asm = HelloAssembler()
    flow = ("a", 1, "b", 443)
    head = b"\x16\x03\x01\x3f\xff\x01"                          # claims a 16 KB record, then never delivers it
    asm.feed(flow, head)
    for _ in range(40):
        asm.feed(flow, b"\x00" * 1500)
    assert len(asm) == 0
