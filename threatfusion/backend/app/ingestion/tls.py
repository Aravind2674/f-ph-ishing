"""
ThreatFusion – TLS certificate facts (A1-3)
===========================================

``ssl_cert_valid`` used to be the constant ``1.0`` on every scan (A0-1 made it ``None`` until a real probe
existed).  This module is that probe: it connects to the host's TLS port and reports what the certificate **is**.

What is observed
----------------
* ``chain_valid`` — OpenSSL's verdict on the chain *and* the host name against the system trust store;
  ``verify_error`` says why not: ``expired`` · ``self_signed`` · ``self_signed_in_chain`` · ``unknown_issuer`` ·
  ``hostname_mismatch`` · ``verify_failed:<code>``.
* validity dates (stored; ``days_to_expiry`` / ``cert_age_days`` are derived at use time so a cached record keeps
  ageing), ``san_matches_host`` (RFC 6125: exact name or a single-label wildcard), issuer, key type/size, TLS version.
* **issuer type** — read from the CA/Browser-Forum *certificate-policy OIDs* (DV 2.23.140.1.2.1 · OV …1.2.2 ·
  IV …1.2.3 · EV 2.23.140.1.1), then split DV into ``free_dv`` (issued by a free automated ACME CA such as Let's
  Encrypt, ZeroSSL, Buypass, Google Trust Services) and ``paid_dv``.  Phishing kits favour free DV; that is a
  *context* signal (most legitimate sites use it too), shown as evidence — never a verdict.

How: two handshakes at most
---------------------------
Python's ``ssl`` aborts a handshake whose certificate fails verification, which would leave us unable to say *why*.
So: pass 1 verifies (``chain_valid=True`` on success).  If it fails with a verification error, pass 2 repeats the
handshake **without verification solely to read the certificate** — nothing is sent over it — and the failure reason
from pass 1 is attached.  The expired or self-signed certificate is therefore still parsed and explained.

Three-state & safety
--------------------
``ok`` — incl. ``has_tls=False`` when nothing on the port speaks TLS (connection refused / plain HTTP: a real
answer, which makes ``ssl_cert_valid`` ``0.0``) · ``error`` — timeout / network / handshake trouble (unknown, so
``None``, never ``0``) · ``skipped`` — private/local names and IP literals (no meaningful SNI/name check).
The connection goes to an address validated by :class:`~app.core.safe_http.SafeFetcher` (every A/AAAA checked,
internal ranges refused, connection pinned, SNI = the host name) — a host that resolves to ``10.x`` is never dialled.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app.core import privacy
from app.core import providers as prov
from app.core.cache import ProviderCache
from app.core.safe_http import FetchError, FetchPolicy, SafeFetcher, UnsafeTargetError, parse_host_ip
from app.models.schemas import ProviderResult, TlsInfo

logger = logging.getLogger(__name__)

SOURCE = "tls"

_OID_DV, _OID_OV, _OID_IV, _OID_EV = "2.23.140.1.2.1", "2.23.140.1.2.2", "2.23.140.1.2.3", "2.23.140.1.1"
# Issuers of free, automated (ACME) DV certificates — a heuristic by issuer name.
_FREE_CAS = ("let's encrypt", "lets encrypt", "isrg", "zerossl", "buypass", "google trust services", "cloudflare")
_VERIFY_CODES = {10: "expired", 18: "self_signed", 19: "self_signed_in_chain", 20: "unknown_issuer",
                 21: "unknown_issuer", 62: "hostname_mismatch"}
# SSL errors that mean "the peer is not speaking TLS at all" (plain HTTP on :443, a non-TLS service, …).
_NOT_TLS = ("WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE", "PACKET_LENGTH_TOO_LONG", "HTTP_REQUEST", "HTTPS_PROXY_REQUEST")


# ── pure helpers (usable on cached records) ─────────────────────────────────
def host_matches(host: str, names: list[str]) -> bool:
    """RFC 6125 §6.4: ``host`` equals a name, or matches a ``*.`` wildcard that covers exactly one left-most label."""
    h = (host or "").lower().rstrip(".")
    labels = h.split(".")
    for raw in names:
        n = raw.lower().rstrip(".")
        if n == h:
            return True
        parts = n.split(".")
        if parts[0] == "*" and len(parts) >= 3 and len(parts) == len(labels) and parts[1:] == labels[1:] and labels[0]:
            return True
    return False


def days_to_expiry(info: Optional[TlsInfo], now: Optional[datetime] = None) -> Optional[float]:
    """Days until ``not_after`` (negative once expired); ``None`` when there is no certificate."""
    if info is None or info.not_after is None:
        return None
    return (info.not_after - (now or datetime.now(timezone.utc))).total_seconds() / 86400.0


def cert_age_days(info: Optional[TlsInfo], now: Optional[datetime] = None) -> Optional[float]:
    """Days since ``not_before`` (a brand-new certificate on an old domain, or vice-versa, is informative)."""
    if info is None or info.not_before is None:
        return None
    return (( now or datetime.now(timezone.utc)) - info.not_before).total_seconds() / 86400.0


def tls_cert_valid(info: Optional[TlsInfo], now: Optional[datetime] = None) -> Optional[float]:
    """The ``ssl_cert_valid`` feature: ``1.0`` valid & name-matching & unexpired · ``0.0`` invalid or no TLS ·
    ``None`` when TLS was not probed. Evaluated at ``now`` so a cached record that has since expired reads 0."""
    if info is None:
        return None
    if not info.has_tls:
        return 0.0
    remaining = days_to_expiry(info, now)
    ok = info.chain_valid is True and info.san_matches_host is not False and (remaining is None or remaining > 0)
    return 1.0 if ok else 0.0


def _attr(name: x509.Name, oid) -> Optional[str]:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else None


def _parse_cert(der: bytes, host: str) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    subject_cn = _attr(cert.subject, NameOID.COMMON_NAME)
    names = list(sans) or ([subject_cn] if subject_cn else [])          # CN only as a legacy fallback
    issuer_cn, issuer_org = _attr(cert.issuer, NameOID.COMMON_NAME), _attr(cert.issuer, NameOID.ORGANIZATION_NAME)

    oids: set[str] = set()
    try:
        for pol in cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value:
            oids.add(pol.policy_identifier.dotted_string)
    except x509.ExtensionNotFound:
        pass
    level = "ev" if _OID_EV in oids else "ov" if _OID_OV in oids else "iv" if _OID_IV in oids else "dv" if _OID_DV in oids else None
    issuer_text = f"{issuer_org or ''} {issuer_cn or ''}".lower()
    if level == "ev":
        issuer_type = "ev"
    elif level in ("ov", "iv"):
        issuer_type = "ov"
    elif level == "dv":
        issuer_type = "free_dv" if any(k in issuer_text for k in _FREE_CAS) else "paid_dv"
    else:
        issuer_type = "unknown"

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pub.curve.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key_type, key_bits = "Ed25519", 256
    else:
        key_type, key_bits = type(pub).__name__, None

    return dict(
        not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc,
        san_matches_host=host_matches(host, names), san_names=[str(s) for s in sans][:50],
        self_signed=cert.issuer == cert.subject, subject_cn=subject_cn, issuer_cn=issuer_cn, issuer_org=issuer_org,
        validation_level=level, issuer_type=issuer_type, key_type=key_type, key_bits=key_bits,
    )


class TlsClient:
    def __init__(
        self,
        use_mock: bool = True,
        *,
        policy: Optional[FetchPolicy] = None,
        cache: Optional[ProviderCache] = None,
        cache_ttl: float = 3600.0,
        not_found_ttl: float = 600.0,
        timeout: float = 6.0,
        port: int = 443,
        trust_cafile: Optional[str] = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._use_mock = use_mock
        self._policy = policy
        self._fetcher: Optional[SafeFetcher] = None
        self._cache = cache if cache is not None else ProviderCache()
        self._ttl = cache_ttl
        self._not_found_ttl = not_found_ttl
        self._timeout = timeout
        self._port = port
        self._cafile = trust_cafile            # None = the system trust store (tests pass their own CA)
        self._clock = clock

    def _get_fetcher(self) -> SafeFetcher:
        if self._fetcher is None:
            self._fetcher = SafeFetcher(self._policy)
        return self._fetcher

    async def close(self) -> None:
        return None

    # ── handshake ──────────────────────────────────────────────────────
    async def _handshake(self, ip, host: str, verify: bool) -> tuple[bytes, str]:
        if verify:
            ctx = ssl.create_default_context(cafile=self._cafile)           # CERT_REQUIRED + check_hostname
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)                   # read the certificate only
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), self._port, ssl=ctx, server_hostname=host,
                                        ssl_handshake_timeout=self._timeout),
                timeout=self._timeout + 1.0)
        except ConnectionAbortedError as exc:
            if "taking longer" in str(exc):             # asyncio's own handshake timeout surfaces as an OSError
                raise TimeoutError("TLS handshake timed out") from exc
            raise
        try:
            sslobj = writer.get_extra_info("ssl_object")
            return sslobj.getpeercert(binary_form=True), sslobj.version() or ""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _probe(self, ip, host: str) -> TlsInfo:
        try:
            der, version = await self._handshake(ip, host, verify=True)
            return TlsInfo(host=host, has_tls=True, chain_valid=True, tls_version=version, **_parse_cert(der, host))
        except ssl.SSLCertVerificationError as exc:
            reason = _VERIFY_CODES.get(exc.verify_code, f"verify_failed:{exc.verify_code}")
        der, version = await self._handshake(ip, host, verify=False)
        return TlsInfo(host=host, has_tls=True, chain_valid=False, verify_error=reason, tls_version=version,
                       **_parse_cert(der, host))

    # ── public ─────────────────────────────────────────────────────────
    async def lookup(self, host: str) -> ProviderResult[TlsInfo]:
        host = (host or "").lower().rstrip(".")
        if parse_host_ip(host) is not None:
            return prov.skipped(SOURCE, "ip_literal")
        blocked = privacy.provider_block_reason(host)
        if blocked:
            return prov.skipped(SOURCE, blocked)
        if self._use_mock:
            return prov.ok(SOURCE, self._mock(host), http_status=None, mock=True)

        key = f"tls:{host}:{self._port}"
        try:
            cached = await self._cache.get(SOURCE, key, TlsInfo)
        except Exception:
            logger.exception("provider cache read failed; continuing without it")
            cached = None
        if cached is not None:
            return cached

        started = prov.start_timer()
        try:
            ips = await asyncio.wait_for(self._get_fetcher().resolve_checked(host, self._port), timeout=self._timeout)
            info = await self._probe(ips[0], host)
        except (asyncio.TimeoutError, TimeoutError):
            return prov.error(SOURCE, "timeout", started=started)
        except (UnsafeTargetError, FetchError) as exc:
            return prov.from_exception(SOURCE, exc, started=started)
        except ConnectionRefusedError:
            info = TlsInfo(host=host, has_tls=False)                        # nothing listens: a real answer
        except ssl.SSLError as exc:
            if any(marker in str(exc) for marker in _NOT_TLS):
                info = TlsInfo(host=host, has_tls=False)                    # the port answers, but not with TLS
            else:
                logger.info("TLS handshake with %s failed: %s", host, exc)
                return prov.error(SOURCE, "tls_handshake_failed", started=started)
        except OSError as exc:
            logger.info("TLS probe of %s failed: %s", host, exc)
            return prov.error(SOURCE, "network", started=started)

        result = prov.ok(SOURCE, info, http_status=None, started=started)
        try:
            await self._cache.put(SOURCE, key, result, ttl_ok=self._ttl, ttl_not_found=self._not_found_ttl)
        except Exception:
            logger.exception("provider cache write failed; continuing without it")
        return result

    # ── mock ───────────────────────────────────────────────────────────
    def _mock(self, host: str) -> TlsInfo:
        """Deterministic: established hosts have a long-lived paid OV certificate, 'evil' hosts a self-signed one."""
        now = self._clock()
        if any(w in host for w in ("evil", "malicious", "phish")):
            return TlsInfo(host=host, has_tls=True, chain_valid=False, verify_error="self_signed", self_signed=True,
                           san_matches_host=True, san_names=[host], subject_cn=host, issuer_cn=host,
                           not_before=now - timedelta(days=3), not_after=now + timedelta(days=87),
                           issuer_type="unknown", tls_version="TLSv1.3", key_type="RSA", key_bits=2048)
        if any(w in host for w in ("google", "microsoft")):
            return TlsInfo(host=host, has_tls=True, chain_valid=True, self_signed=False, san_matches_host=True,
                           san_names=[host], subject_cn=host, issuer_cn="Mock Issuing CA", issuer_org="Mock Trust Services",
                           not_before=now - timedelta(days=120), not_after=now + timedelta(days=240),
                           validation_level="ov", issuer_type="ov", tls_version="TLSv1.3", key_type="EC", key_bits=256)
        age = 5 + int(hashlib.sha256(host.encode()).hexdigest(), 16) % 60
        return TlsInfo(host=host, has_tls=True, chain_valid=True, self_signed=False, san_matches_host=True,
                       san_names=[host], subject_cn=host, issuer_cn="Mock R3", issuer_org="Let's Encrypt",
                       not_before=now - timedelta(days=age), not_after=now + timedelta(days=90 - age),
                       validation_level="dv", issuer_type="free_dv", tls_version="TLSv1.3", key_type="EC", key_bits=256)
