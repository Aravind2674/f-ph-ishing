"""
Privacy guards for data that could leave the machine (A0-10)
=============================================================

The audit (AUDIT_REPORT.md §H5/§H6) found that ThreatFusion forwarded things to third parties that it
should never forward:

* the *full URL* of the page the user was looking at (paths, query strings, tokens) went to VirusTotal;
* every DNS name observed on the LAN — including internal hostnames such as ``printer.local`` — went to
  VirusTotal, with attacker-controlled bytes interpolated straight into the provider URL;
* cookies / ``Authorization`` headers of proxied traffic were forwarded to the backend.

This module is the single place that decides *what may leave*:

* :func:`provider_block_reason` — may this host/IP be sent to a third-party service?  Private, local,
  single-label, reverse-DNS, private-IP and syntactically invalid names are refused.
* :func:`strip_url_for_third_parties` — keep scheme/host/port/path, drop userinfo, query and fragment.
* :func:`redact_headers` — replace the values of credential-bearing headers.

Rule of thumb: local processing (the models, the baseline store) may use anything it observed; only what
passes these checks may be put into a request to an external provider.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional
from urllib.parse import urlsplit

from app.core.safe_http import blocked_reason, parse_host_ip

REDACTED = "[redacted]"

# Names that are only meaningful inside a private network (or are not real DNS names at all).
_PRIVATE_SUFFIXES = (
    ".local", ".lan", ".internal", ".home.arpa", ".localdomain", ".localhost", ".intranet", ".corp",
    ".home", ".private",
    ".in-addr.arpa", ".ip6.arpa",           # reverse DNS: encodes an internal IP address
)

# One DNS label: letters/digits/underscore (service names like _ipp._tcp) and hyphens, 1-63 chars,
# not starting/ending with a hyphen.
_LABEL = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?")


def normalise_name(name: str) -> str:
    """Lowercase, drop one trailing dot, and convert Unicode (IDN) names to their punycode form."""
    n = (name or "").strip().lower()
    if n.endswith("."):
        n = n[:-1]
    try:
        n.encode("ascii")
    except UnicodeEncodeError:
        try:
            n = n.encode("idna").decode("ascii")
        except UnicodeError:
            return n   # left as-is; is_valid_dns_name() will reject it
    return n


def is_valid_dns_name(name: str) -> bool:
    """Syntactically a DNS name — and nothing that could alter a URL path/query (``/ ? # @ : %``, spaces)."""
    n = normalise_name(name)
    if not n or len(n) > 253:
        return False
    return all(_LABEL.fullmatch(label) for label in n.split("."))


def provider_block_reason(target: str) -> Optional[str]:
    """Why ``target`` must NOT be sent to a third-party service, or ``None`` if it may be.

    Returns one of ``private_address``, ``invalid_name``, ``single_label``, ``private_name``.
    """
    n = normalise_name(target)
    if not n:
        return "invalid_name"
    ip = parse_host_ip(n)
    if ip is not None:
        return "private_address" if blocked_reason(ip) else None
    if not is_valid_dns_name(n):
        return "invalid_name"
    if "." not in n:
        return "single_label"            # printer, wpad, DESKTOP-ABC123 …
    if n == "localhost" or any(n.endswith(suffix) or n == suffix[1:] for suffix in _PRIVATE_SUFFIXES):
        return "private_name"
    return None


def hostname_of(target: str) -> str:
    """Host part of ``target`` (a bare host, ``host/path`` or a full URL); '' if it cannot be parsed."""
    raw = (target or "").strip()
    try:
        return urlsplit(raw if "://" in raw else "//" + raw).hostname or ""
    except ValueError:
        return ""


def strip_url_for_third_parties(url: str) -> str:
    """``scheme://host[:port]/path`` — without userinfo, query string or fragment.

    The query string and fragment are where session tokens, reset links and PII live; the path can too, but
    it is part of what identifies the page being assessed. Callers wanting the full URL must opt in.
    Returns '' for an unparseable URL.
    """
    raw = (url or "").strip()
    had_scheme = "://" in raw
    try:
        parts = urlsplit(raw if had_scheme else "//" + raw)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    if ":" in host:                      # IPv6 literal
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port else host
    return f"{parts.scheme}://{netloc}{parts.path}" if had_scheme else f"{netloc}{parts.path}"


# ── Header redaction ────────────────────────────────────────────────────────
_SENSITIVE_HEADERS = frozenset({
    "cookie", "cookie2", "set-cookie", "set-cookie2", "authorization", "proxy-authorization",
    "x-api-key", "apikey", "api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
    "x-amz-security-token", "x-goog-api-key",
})
_SENSITIVE_FRAGMENTS = ("token", "secret", "apikey", "api-key", "api_key", "session", "password",
                        "passwd", "credential", "signature")


def is_sensitive_header(name: str) -> bool:
    n = (name or "").strip().lower()
    return n in _SENSITIVE_HEADERS or any(f in n for f in _SENSITIVE_FRAGMENTS)


def redact_headers(headers: Mapping) -> dict:
    """Copy of ``headers`` with the values of credential-bearing headers replaced by ``[redacted]``."""
    return {k: (REDACTED if is_sensitive_header(str(k)) else v) for k, v in (headers or {}).items()}
