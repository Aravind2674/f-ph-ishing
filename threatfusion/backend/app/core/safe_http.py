"""
SSRF-safe HTTP fetcher (A0-4)
=============================

Every place that fetches a *user-supplied* target (target validation, technology
fingerprinting, active verification, a future crawler) goes through this module.

Why (AUDIT_REPORT.md §H2)
-------------------------
The old flow validated a hostname once (a DNS lookup plus an internal-range check) and then
*re-resolved* it when it actually fetched, following redirects with no destination check.  That
allowed:

* **DNS rebinding** — the second lookup could return ``127.0.0.1`` / ``169.254.169.254``;
* **redirect SSRF** — a public page answering ``302 -> http://169.254.169.254/…``;
* IPv6 / mapped / NAT64 / 6to4 / legacy-numeric spellings slipping past string checks.

How it works
------------
1. Parse the URL; allow only ``http``/``https`` on configured ports.
2. Resolve **all** A/AAAA records (async).  If *any* resolved address is not globally routable
   (private, loopback, link-local incl. cloud metadata, CGNAT, reserved, multicast, …) the target
   is refused — a hostname with one public and one internal record is an attack, not a website.
   Address classification uses :mod:`ipaddress` (no hand-rolled string checks), after unwrapping
   IPv4-mapped, NAT64 and 6to4 forms and legacy numeric hosts such as ``2130706433`` or ``0x7f.1``.
3. **Pin the connection to the validated IP** (the request URL carries the IP; ``Host`` and TLS
   SNI/certificate verification keep the original name).  There is no second DNS lookup to swap.
4. Follow redirects **manually** and repeat 1-3 for every hop; cap the number of hops.
5. Cap response size (decoded bytes) and total wall-clock time.

An operator can explicitly allow an internal host (e.g. the local vulnerable lab used for active
verification) via ``FetchPolicy.allow_private`` — that is a deliberate, configured exception, never
something a request can grant itself.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional, Union

import httpx

logger = logging.getLogger(__name__)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

DEFAULT_PORTS = frozenset({80, 443, 8080, 8443})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Never reachable, even for operator-allowed hosts: metadata/link-local, unspecified, multicast, Teredo.
_NEVER_ALLOWED = frozenset({"link_local", "unspecified", "multicast", "teredo"})
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
# Legacy IPv4 spellings that inet_aton() understands but ipaddress does not: 2130706433, 0x7f.1,
# 127.1, 0177.0.0.1 …  A resolver may expand them to a loopback/private address, so normalise first.
_LEGACY_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.IGNORECASE)


class UnsafeTargetError(Exception):
    """The destination (initial or via a redirect) is not allowed. ``reason`` is machine-readable."""

    def __init__(self, reason: str, detail: str = "", *, hop: int = 0) -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail
        self.hop = hop


class FetchError(Exception):
    """The fetch failed for a non-policy reason (timeout, network, DNS). ``reason`` is a code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# ── Address classification ──────────────────────────────────────────────────
def _unwrap(ip: IPAddress) -> IPAddress:
    """Reduce IPv6 forms that *embed* an IPv4 address to that IPv4 address, then judge that."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:                       # ::ffff:a.b.c.d
            return ip.ipv4_mapped
        if ip in _NAT64:                                     # 64:ff9b::/96 (RFC 6052)
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip.sixtofour is not None:                         # 2002::/16 (6to4)
            return ip.sixtofour
    return ip


def blocked_reason(ip: IPAddress) -> Optional[str]:
    """Why ``ip`` must not be fetched, or ``None`` if it is a normal public address."""
    ip = _unwrap(ip)
    if isinstance(ip, ipaddress.IPv6Address) and ip.teredo is not None:
        return "teredo"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"           # includes 169.254.169.254 (cloud metadata) and fe80::/10
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if not ip.is_global:
        return "non_global"           # CGNAT 100.64/10, documentation, benchmarking, …
    return None


def parse_host_ip(host: str) -> Optional[IPAddress]:
    """If ``host`` is an IP literal (incl. legacy numeric IPv4 spellings) return it, else None."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if _LEGACY_NUMERIC_HOST.match(h):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(h))
        except OSError:
            return None
    return None


async def resolve_host(host: str, port: int) -> list[IPAddress]:
    """Resolve all A/AAAA records for ``host`` without blocking the event loop."""
    literal = parse_host_ip(host)
    if literal is not None:
        return [literal]
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise FetchError("dns_failure", str(exc)) from exc
    seen: list[IPAddress] = []
    for family, _t, _p, _c, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        ip = ipaddress.ip_address(sockaddr[0].split("%")[0])  # strip IPv6 zone id
        if ip not in seen:
            seen.append(ip)
    if not seen:
        raise FetchError("dns_failure", "no A/AAAA records")
    return seen


# ── Policy ──────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class FetchPolicy:
    """What a fetch may do.  Defaults are conservative; relax only by explicit configuration."""

    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    # None = any port.  Otherwise only these (plus ports of explicitly allowed private hosts).
    allowed_ports: Optional[frozenset[int]] = DEFAULT_PORTS
    max_redirects: int = 5
    max_bytes: int = 2 * 1024 * 1024        # decoded bytes (also bounds decompression bombs)
    total_timeout: float = 15.0             # wall-clock for the whole fetch incl. redirects
    request_timeout: float = 8.0            # per hop (connect/read/write/pool)
    verify_tls: bool = True
    # Explicit operator opt-in: (hostname-or-ip, port-or-None) allowed to resolve to non-public
    # addresses — e.g. the local vulnerable lab. Never derived from request data.
    allow_private: frozenset[tuple[str, Optional[int]]] = frozenset()

    def is_private_allowed(self, host: str, port: int) -> bool:
        h = host.lower().strip("[]")
        return (h, port) in self.allow_private or (h, None) in self.allow_private

    def is_port_allowed(self, host: str, port: int) -> bool:
        if self.allowed_ports is None or port in self.allowed_ports:
            return True
        return (host.lower().strip("[]"), port) in self.allow_private

    @classmethod
    def from_settings(cls, **overrides) -> "FetchPolicy":
        """Build the default policy from configuration (``SAFE_FETCH_PORTS``)."""
        from app.core.config import get_settings

        raw = get_settings().SAFE_FETCH_PORTS.strip()
        ports: Optional[frozenset[int]]
        if raw == "*":
            ports = None
        else:
            ports = frozenset(int(p) for p in raw.split(",") if p.strip().isdigit()) or DEFAULT_PORTS
        return cls(allowed_ports=ports, **overrides)


@dataclass
class FetchResult:
    url: str                       # final (logical) URL after redirects
    status_code: int
    headers: httpx.Headers
    body: bytes
    encoding: str = "utf-8"
    truncated: bool = False
    ip: str = ""                   # the validated address the final hop connected to
    redirects: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def text(self) -> str:
        return self.body.decode(self.encoding or "utf-8", errors="replace")


# ── The fetcher ─────────────────────────────────────────────────────────────
class SafeFetcher:
    """Fetch user-supplied URLs with DNS pinning and per-hop validation. See module docstring."""

    def __init__(self, policy: Optional[FetchPolicy] = None) -> None:
        self.policy = policy or FetchPolicy.from_settings()

    # -- validation -----------------------------------------------------------
    def _check_url(self, url: httpx.URL, hop: int) -> tuple[str, int]:
        scheme = url.scheme.lower()
        if scheme not in self.policy.allowed_schemes:
            raise UnsafeTargetError("blocked_scheme", scheme or "(none)", hop=hop)
        host = url.host
        if not host:
            raise UnsafeTargetError("blocked_host", "empty host", hop=hop)
        if url.userinfo:
            # credentials in the URL are a classic parser-confusion vector; refuse them outright
            raise UnsafeTargetError("blocked_userinfo", "credentials in URL", hop=hop)
        port = url.port or (443 if scheme == "https" else 80)
        if not self.policy.is_port_allowed(host, port):
            raise UnsafeTargetError("blocked_port", str(port), hop=hop)
        return host, port

    async def resolve_checked(self, host: str, port: int, hop: int = 0) -> list[IPAddress]:
        """Resolve ``host`` and refuse it if ANY address is internal (unless explicitly allowed)."""
        ips = await resolve_host(host, port)
        if self.policy.is_private_allowed(host, port):
            # Operator opted this host in (e.g. a local lab) — but never into cloud metadata,
            # link-local, unspecified or multicast space, whatever DNS says.
            for ip in ips:
                why = blocked_reason(ip)
                if why in _NEVER_ALLOWED:
                    raise UnsafeTargetError("blocked_address", f"{host} -> {ip} ({why})", hop=hop)
            return ips
        for ip in ips:
            why = blocked_reason(ip)
            if why:
                raise UnsafeTargetError("blocked_address", f"{host} -> {ip} ({why})", hop=hop)
        return ips

    # -- fetch ----------------------------------------------------------------
    async def fetch(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        follow_redirects: bool = True,
        method: str = "GET",
    ) -> FetchResult:
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self.policy.total_timeout):
                return await self._fetch(url, headers or {}, follow_redirects, method, started)
        except TimeoutError as exc:
            raise FetchError("timeout", f"exceeded {self.policy.total_timeout}s") from exc

    async def _fetch(self, url: str, headers: dict[str, str], follow: bool, method: str,
                     started: float) -> FetchResult:
        logical = httpx.URL(url)
        redirects: list[str] = []
        timeout = httpx.Timeout(self.policy.request_timeout)

        for hop in range(self.policy.max_redirects + 1):
            host, port = self._check_url(logical, hop)
            ips = await self.resolve_checked(host, port, hop)
            ip = ips[0]

            # Connect to the validated IP; keep the original name for Host + TLS SNI/verification.
            pinned = logical.copy_with(host=str(ip))
            default_port = 443 if logical.scheme == "https" else 80
            host_header = host if port == default_port else f"{host}:{port}"
            req_headers = {**headers, "Host": host_header}

            try:
                async with httpx.AsyncClient(
                    verify=self.policy.verify_tls, timeout=timeout, follow_redirects=False,
                    trust_env=False,   # never inherit proxy settings from the environment
                ) as client:
                    request = client.build_request(
                        method, pinned, headers=req_headers,
                        extensions={"sni_hostname": host} if logical.scheme == "https" else {},
                    )
                    response = await client.send(request, stream=True)
                    try:
                        if follow and response.status_code in _REDIRECT_STATUSES and "location" in response.headers:
                            if hop >= self.policy.max_redirects:
                                raise UnsafeTargetError("too_many_redirects", str(hop + 1), hop=hop)
                            redirects.append(str(logical))
                            logical = logical.join(response.headers["location"])
                            continue

                        body, truncated = await self._read_capped(response)
                        return FetchResult(
                            url=str(logical), status_code=response.status_code,
                            headers=response.headers, body=body,
                            encoding=response.encoding or "utf-8", truncated=truncated,
                            ip=str(ip), redirects=redirects,
                            elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
                        )
                    finally:
                        await response.aclose()
            except httpx.TimeoutException as exc:
                raise FetchError("timeout", str(exc)) from exc
            except httpx.TooManyRedirects as exc:  # pragma: no cover - redirects are manual
                raise UnsafeTargetError("too_many_redirects", str(exc), hop=hop) from exc
            except httpx.HTTPError as exc:
                raise FetchError("network", f"{type(exc).__name__}: {exc}") from exc

        raise UnsafeTargetError("too_many_redirects", str(self.policy.max_redirects))  # pragma: no cover

    async def _read_capped(self, response: httpx.Response) -> tuple[bytes, bool]:
        """Read at most ``max_bytes`` of the *decoded* body."""
        cap = self.policy.max_bytes
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            if total + len(chunk) > cap:
                chunks.append(chunk[: cap - total])
                return b"".join(chunks), True
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks), False
