"""
TLS ClientHello parsing, SNI and client fingerprints (A3-3, B13)
================================================================

A passive sensor sees the first client→server bytes of a TLS connection *unencrypted*: the ClientHello names the server the
client wants (the **SNI**, ``server_name``) and lists, in an order that is characteristic of the TLS library, the cipher suites,
extensions, curves and signature algorithms it supports.  That list is the basis of the **JA3** (Salesforce) and **JA4** (FoxIO)
client fingerprints: they identify the *software* making the connection, not the user, and a handful of malware families use
distinctive TLS stacks.

This module is pure parsing — no sockets, no scapy — so it is testable byte-for-byte:

* ``parse_client_hello(data)`` reads one TLS record carrying a ClientHello.  A hello can be larger than one TCP segment (Chrome's
  post-quantum key share makes it ~1.7 KB), so it raises :class:`NeedMoreData` when the bytes seen so far are a *prefix* of a
  hello; the sensor buffers the flow's first bytes (:class:`HelloAssembler`) and tries again.  Anything that is not a ClientHello
  raises :class:`NotClientHello` — a sensor must never crash on hostile bytes.
* ``ja3`` / ``ja4`` compute the fingerprints from the parsed hello.

What this is **not**: a fingerprint is evidence about the client software, never proof of malice.  Browsers update their stacks
and malware copies browser stacks; the known-bad list match (``fingerprint_feed``) is reported as "matches a fingerprint listed
for <family>", with the list's name and age, and a miss means nothing.  JA4 is implemented from the public FoxIO specification
and is **not** cross-checked against the reference implementation in this repository's tests (see the docs).
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

_MAX_HELLO_BYTES = 16 * 1024 + 5        # a TLS record carries at most 2**14 bytes of payload (+ 5 byte record header)


class NotClientHello(ValueError):
    """The bytes are not (the start of) a TLS ClientHello."""


class NeedMoreData(ValueError):
    """The bytes look like the start of a ClientHello, but the record is not complete yet."""


@dataclass
class ClientHello:
    record_version: int = 0
    client_version: int = 0                          # legacy_version: 0x0303 for TLS 1.2 *and* 1.3
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)       # extension type ids, in the order sent
    sni: Optional[str] = None
    groups: list[int] = field(default_factory=list)           # supported_groups (a.k.a. elliptic curves)
    point_formats: list[int] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)
    alpn: list[bytes] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values (0x0a0a, 0x1a1a, … 0xfafa): random-looking placeholders that must not be fingerprinted."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


class _Reader:
    """Bounds-checked big-endian reader; reading past the end of a *complete* record is a malformed hello."""

    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise NotClientHello("truncated field inside a complete record")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def left(self) -> int:
        return len(self.data) - self.pos


def _sni(body: bytes) -> Optional[str]:
    r = _Reader(body)
    r.take(0)
    end = r.u16()
    names = _Reader(r.take(min(end, r.left())))
    while names.left() >= 3:
        kind, ln = names.u8(), names.u16()
        value = names.take(ln)
        if kind == 0:                                  # host_name
            try:
                host = value.decode("ascii")
            except UnicodeDecodeError:
                return None                            # an SNI that is not ASCII is not a valid host name (IDNs are sent as A-labels)
            return host.rstrip(".").lower() or None
    return None


def _u16_list(body: bytes, length_bytes: int = 2) -> list[int]:
    r = _Reader(body)
    n = r.u16() if length_bytes == 2 else r.u8()
    raw = r.take(min(n, r.left()))
    return [int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw) - 1, 2)]


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse the TLS record at the start of ``data`` as a ClientHello (see the module docstring for the two exceptions)."""
    if len(data) < 5:
        if data[:1] in (b"", b"\x16"):
            raise NeedMoreData
        raise NotClientHello("not a TLS handshake record")
    if data[0] != 0x16 or data[1] != 0x03 or data[2] > 0x04:
        raise NotClientHello("not a TLS handshake record")
    rec_len = int.from_bytes(data[3:5], "big")
    if rec_len < 4 or rec_len > 1 << 14:
        raise NotClientHello("implausible TLS record length")
    if len(data) < 5 + rec_len:
        # a prefix of a record: a hello when the handshake type seen so far is 1
        if len(data) > 5 and data[5] != 0x01:
            raise NotClientHello("handshake message is not a ClientHello")
        raise NeedMoreData
    if data[5] != 0x01:
        raise NotClientHello("handshake message is not a ClientHello")

    hello = ClientHello(record_version=int.from_bytes(data[1:3], "big"))
    r = _Reader(data[5:5 + rec_len])
    r.u8()                                                        # handshake type (1)
    body_len = r.u24()
    if body_len > r.left():
        # The hello continues in the next record (fragmented across records): rare, and not reassembled here.
        raise NotClientHello("ClientHello spans several TLS records (not reassembled)")
    r = _Reader(r.take(body_len))
    hello.client_version = r.u16()
    r.take(32)                                                    # random
    r.take(r.u8())                                                # session id
    suites = r.take(r.u16())
    hello.ciphers = [int.from_bytes(suites[i:i + 2], "big") for i in range(0, len(suites) - 1, 2)]
    r.take(r.u8())                                                # compression methods
    if r.left() == 0:
        return hello                                              # SSLv3 / very old hello without extensions
    ext_total = r.u16()
    ext = _Reader(r.take(min(ext_total, r.left())))
    while ext.left() >= 4:
        etype, elen = ext.u16(), ext.u16()
        body = ext.take(min(elen, ext.left()))
        hello.extensions.append(etype)
        try:
            if etype == 0:
                hello.sni = _sni(body)
            elif etype == 10:
                hello.groups = _u16_list(body)
            elif etype == 11:
                hello.point_formats = list(body[1:1 + body[0]]) if body else []
            elif etype == 13:
                hello.sig_algs = _u16_list(body)
            elif etype == 16:
                lst = _Reader(body)
                lst_end = lst.u16()
                items = _Reader(lst.take(min(lst_end, lst.left())))
                while items.left() >= 1:
                    hello.alpn.append(items.take(items.u8()))
            elif etype == 43:
                hello.supported_versions = [int.from_bytes(body[1 + i:3 + i], "big") for i in range(0, min(body[0], len(body) - 1) - 1, 2)] if body else []
        except NotClientHello:
            continue                                              # a malformed optional extension never hides the rest
    return hello


# ── fingerprints ───────────────────────────────────────────────────────────

def ja3(h: ClientHello) -> tuple[str, str]:
    """JA3 (Salesforce): ``version,ciphers,extensions,curves,point_formats`` with GREASE removed, MD5 of the string."""
    dash = lambda xs: "-".join(str(x) for x in xs if not is_grease(x))  # noqa: E731
    text = ",".join([str(h.client_version), dash(h.ciphers), dash(h.extensions), dash(h.groups), "-".join(str(x) for x in h.point_formats)])
    return text, hashlib.md5(text.encode("ascii")).hexdigest()                          # noqa: S324 (a fingerprint, not security)


_TLS_VERSION_CODE = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2"}


def _alpn_marks(alpn: list[bytes]) -> str:
    if not alpn or not alpn[0]:
        return "00"
    first = alpn[0]
    a, b = first[:1], first[-1:]
    if a.isalnum() and b.isalnum():
        return (a + b).decode("ascii").lower()
    hx = first.hex()
    return hx[0] + hx[-1]                                         # non-alphanumeric ALPN: first and last hex digit


def ja4(h: ClientHello, transport: str = "t") -> str:
    """JA4 (FoxIO): ``<proto><tls><sni><ncipher><next><alpn>_<sha256(sorted ciphers)[:12]>_<sha256(sorted ext + sig algs)[:12]>``."""
    versions = [v for v in h.supported_versions if not is_grease(v)]
    top = max(versions) if versions else h.client_version
    ciphers = [c for c in h.ciphers if not is_grease(c)]
    exts = [e for e in h.extensions if not is_grease(e)]
    head = f"{transport}{_TLS_VERSION_CODE.get(top, '00')}{'d' if h.sni else 'i'}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{_alpn_marks(h.alpn)}"
    cipher_part = hashlib.sha256(",".join(f"{c:04x}" for c in sorted(ciphers)).encode()).hexdigest()[:12] if ciphers else "0" * 12
    ext_sorted = sorted(e for e in exts if e not in (0x0000, 0x0010))
    sigs = [s for s in h.sig_algs if not is_grease(s)]
    ext_text = ",".join(f"{e:04x}" for e in ext_sorted) + ("_" + ",".join(f"{s:04x}" for s in sigs) if sigs else "")
    ext_part = hashlib.sha256(ext_text.encode()).hexdigest()[:12] if ext_sorted else "0" * 12
    return f"{head}_{cipher_part}_{ext_part}"


# ── flow reassembly (the first bytes of a connection) ──────────────────────

class HelloAssembler:
    """Collects the first client→server bytes of each TCP flow until a ClientHello parses (or is ruled out).

    Bounded on purpose: ``max_flows`` flows are tracked at once (oldest dropped), and a flow that has produced
    ``_MAX_HELLO_BYTES`` without a parse is abandoned — a sensor on a busy link cannot be made to buffer without limit.
    A flow is decided once: after a hello, or after a non-TLS first segment, later segments of it are ignored.
    """

    def __init__(self, max_flows: int = 4096) -> None:
        self.max_flows = max_flows
        self._open: "OrderedDict[tuple, bytearray]" = OrderedDict()
        self._done: "OrderedDict[tuple, None]" = OrderedDict()

    def feed(self, flow: tuple, payload: bytes) -> Optional[ClientHello]:
        if not payload or flow in self._done:
            return None
        buf = self._open.pop(flow, bytearray())
        buf.extend(payload)
        try:
            hello = parse_client_hello(bytes(buf))
        except NeedMoreData:
            if len(buf) < _MAX_HELLO_BYTES:
                self._open[flow] = buf
                while len(self._open) > self.max_flows:
                    self._open.popitem(last=False)
                return None
            hello = None
        except NotClientHello:
            hello = None
        self._done[flow] = None
        while len(self._done) > self.max_flows:
            self._done.popitem(last=False)
        return hello

    def forget(self, flow: tuple) -> None:
        self._open.pop(flow, None)
        self._done.pop(flow, None)

    def __len__(self) -> int:
        return len(self._open)
