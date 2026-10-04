"""
One input canonicaliser (A1-6)
==============================

Before this module every component parsed the user's raw string its own way: ``scan.py`` split on ``/`` and
``:``, validation stripped ``www.``, the VirusTotal client interpolated whatever it was handed, IP targets went
to the *domain* endpoint, and IP / hash targets were never validated at all (audit §C, §H2).

:func:`canonicalize` turns the raw string into a single immutable :class:`Target`; **everything downstream
consumes the Target, never the raw string**:

=================  ====================================================================================
``host``           ASCII (punycode) lowercase hostname without trailing dot; IPv6 without brackets
``registered_domain`` eTLD+1 from the Public Suffix List (offline snapshot bundled with ``tldextract``)
``ip``             canonical IP when the host is an IP literal — legacy spellings (``2130706433``,
                   ``0x7f.1``, ``0177.0.0.1``) are normalised, never trusted
``url_full``       ``scheme://host[:port]/path[?query]`` — no userinfo, no fragment, default port dropped
``url_public``     as above **without** the query string: the only form that may leave the machine by default
``hash`` / ``hash_type``  lowercase hex digest and md5 / sha1 / sha256
=================  ====================================================================================

Invalid input never raises: the Target has ``valid=False`` and a machine-readable ``problem``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional
from urllib.parse import urlsplit

import tldextract

from app.core import privacy
from app.core.safe_http import parse_host_ip
from app.models.schemas import TargetType

_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"[0-9a-fA-F]+")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
# Opaque schemes (no "//") that must never be mistaken for "host:port".
_OPAQUE_SCHEME = re.compile(
    r"^(javascript|data|mailto|tel|sms|about|blob|view-source|chrome|chrome-extension|vbscript|file):", re.IGNORECASE)
_ALLOWED_SCHEMES = ("http", "https")
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Target:
    """The canonical form of a scan target (see module docstring)."""

    raw: str
    kind: TargetType
    valid: bool = True
    problem: Optional[str] = None

    host: Optional[str] = None
    registered_domain: Optional[str] = None
    subdomain: str = ""
    ip: Optional[str] = None
    port: Optional[int] = None            # explicit, non-default port only (URL kind); as parsed otherwise
    scheme: Optional[str] = None
    path: str = ""
    query: str = ""
    has_userinfo: bool = False

    url_full: Optional[str] = None
    url_public: Optional[str] = None

    hash: Optional[str] = None
    hash_type: Optional[str] = None

    def outbound_block_reason(self) -> Optional[str]:
        """Why this target must not be sent to a third party (see ``core/privacy``), or None."""
        if self.kind == TargetType.FILE_HASH:
            return None
        subject = self.ip or self.host
        return privacy.provider_block_reason(subject) if subject else "invalid_name"


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    """Public Suffix List from the snapshot bundled with the package: no fetch, no on-disk cache."""
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def _registered(host: str) -> tuple[Optional[str], str]:
    ext = _extractor()(host)
    reg = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
    # No recognised public suffix (``*.example``, ``*.local``, ``localhost``): the eTLD+1 is unknowable, so it is
    # ``None`` rather than a guessed split; ``subdomain`` is then just "every label left of the last one".
    return (reg or None), ext.subdomain


def _invalid(raw, kind: TargetType, problem: str, **kw) -> Target:
    return Target(raw=raw if isinstance(raw, str) else "", kind=kind, valid=False, problem=problem, **kw)


def canonicalize(raw: str, declared: Optional[TargetType] = None) -> Target:
    """Canonicalise ``raw``. ``declared`` is the type the caller says it is (e.g. the API's ``target_type``).

    * ``DOMAIN`` accepts a bare host *or* a URL (only the host is kept);
    * ``URL`` accepts a scheme-less ``host/path`` (``https`` is assumed);
    * ``IP`` accepts IPv4/IPv6 incl. brackets, ``ip:port`` and legacy numeric IPv4 spellings;
    * ``FILE_HASH`` accepts a 32/40/64-digit hex string;
    * ``None`` auto-detects.
    """
    fallback_kind = declared or TargetType.DOMAIN
    if not isinstance(raw, str):
        return _invalid("", fallback_kind, "empty")
    if any(ord(c) < 32 or ord(c) == 127 for c in raw):
        return _invalid(raw, fallback_kind, "control_characters")
    s = raw.strip()
    if not s:
        return _invalid(raw, fallback_kind, "empty")
    if re.search(r"\s", s):
        return _invalid(raw, fallback_kind, "whitespace")

    # ── hash ────────────────────────────────────────────────────────────────
    if declared in (None, TargetType.FILE_HASH) and _HEX.fullmatch(s) and len(s) in _HASH_TYPES:
        return Target(raw=raw, kind=TargetType.FILE_HASH, hash=s.lower(), hash_type=_HASH_TYPES[len(s)])
    if declared == TargetType.FILE_HASH:
        return _invalid(raw, TargetType.FILE_HASH, "invalid_hash")

    # ── scheme ──────────────────────────────────────────────────────────────
    scheme: Optional[str] = None
    rest = s
    m = _SCHEME.match(s)
    if m:
        scheme, rest = m.group(1).lower(), s[m.end():]
    elif _OPAQUE_SCHEME.match(s):
        return _invalid(raw, fallback_kind, "unsupported_scheme")
    if scheme is not None and scheme not in _ALLOWED_SCHEMES:
        return _invalid(raw, fallback_kind, "unsupported_scheme")

    # ── a bare IP literal (urlsplit cannot parse un-bracketed IPv6) ─────────
    bare_ip = parse_host_ip(rest) if scheme is None else None
    if bare_ip is not None:
        parts_host, port, path, query, userinfo = str(bare_ip), None, "", "", False
    else:
        try:
            parts = urlsplit("//" + rest)
            port = parts.port
            parts_host = parts.hostname or ""
        except ValueError:
            return _invalid(raw, fallback_kind, "invalid_port" if ":" in rest else "malformed")
        path, query, userinfo = parts.path, parts.query, "@" in parts.netloc
        if not parts_host:
            return _invalid(raw, fallback_kind, "empty_host")

    # ── host ────────────────────────────────────────────────────────────────
    ip = parse_host_ip(parts_host)
    if ip is not None:
        host = str(ip)
    else:
        host = privacy.normalise_name(parts_host)
        if not privacy.is_valid_dns_name(host):
            return _invalid(raw, fallback_kind, "invalid_hostname")

    # ── kind ────────────────────────────────────────────────────────────────
    if declared is None:
        if ip is not None:
            kind = TargetType.IP
        elif scheme is not None or path not in ("", "/") or query:
            kind = TargetType.URL
        else:
            kind = TargetType.DOMAIN
    else:
        kind = declared

    if kind == TargetType.IP:
        if ip is None or path.strip("/") or query:      # "1.2.3.4/8" is a CIDR, not an address
            return _invalid(raw, kind, "invalid_ip")
        return Target(raw=raw, kind=kind, host=host, ip=host, port=port)
    if kind == TargetType.DOMAIN and ip is not None:
        return _invalid(raw, TargetType.IP, "declared_domain_is_ip", host=host, ip=host)

    registered, sub = (None, "") if ip is not None else _registered(host)

    if kind == TargetType.DOMAIN:
        return Target(raw=raw, kind=kind, host=host, registered_domain=registered, subdomain=sub,
                      port=port, scheme=scheme, has_userinfo=userinfo)

    # URL
    scheme = scheme or "https"
    default = _DEFAULT_PORTS[scheme]
    explicit_port = port if port and port != default else None
    shown_host = f"[{host}]" if ":" in host else host
    netloc = shown_host + (f":{explicit_port}" if explicit_port else "")
    path = path or "/"
    public = f"{scheme}://{netloc}{path}"
    return Target(
        raw=raw, kind=TargetType.URL, host=host, registered_domain=registered, subdomain=sub,
        ip=str(ip) if ip is not None else None, port=explicit_port, scheme=scheme, path=path, query=query,
        has_userinfo=userinfo, url_full=public + (f"?{query}" if query else ""), url_public=public,
    )
