"""
ThreatFusion – DNS records & hosting ASN (A1-3)
===============================================

What the zone says about a host, with ``dnspython``'s async resolver:

* ``A`` / ``AAAA`` for the host; ``MX`` / ``NS`` / ``TXT`` / ``CAA`` and the **DMARC** policy
  (``_dmarc.<registered domain>``) for the registered domain (those records live at the apex, not at ``www``);
* **SPF** presence (a ``v=spf1`` TXT record) and the DMARC policy (``p=none|quarantine|reject``);
* the **hosting ASN** of the first public address, from Team Cymru's DNS-based IP→ASN mapping (no HTTP API, no
  key).

Why these signals: a freshly registered phishing domain typically has no MX/SPF/DMARC/CAA at all, sits on a
bulk-hosting ASN and has a handful of A records — individually weak, together a profile (they feed the exposure
and phishing work in A2/B-items).  They are *evidence*, shown to the user with their provenance, not a verdict.

Three-state, per record family
------------------------------
``[]`` = the zone answered and has no such record; ``None`` = the lookup *failed* (timeout / SERVFAIL) and is
listed in ``DnsInfo.failed_types``.  "No CAA record" and "the CAA lookup timed out" must never look the same.
NXDOMAIN on the *host* (both A and AAAA) is ``not_found``; every family failing is ``error``.

Privacy (A0-10): private / local / single-label names are never resolved through public resolvers
(``provider_block_reason``), and internal *addresses* are never sent to the ASN service.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
from typing import Any, Optional

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.core import privacy
from app.core import providers as prov
from app.core.cache import ProviderCache
from app.core.safe_http import blocked_reason
from app.models.schemas import DnsInfo, ProviderResult, ProviderStatus

logger = logging.getLogger(__name__)

SOURCE = "dns"
_CYMRU_V4 = "origin.asn.cymru.com"
_CYMRU_V6 = "origin6.asn.cymru.com"
_CYMRU_AS = "asn.cymru.com"
_MAX_TXT = 20
_MAX_TXT_LEN = 512


class _Outcome:
    """Result of one query: ``records`` is a list (possibly empty) or ``None`` when the lookup failed."""

    __slots__ = ("records", "state")

    def __init__(self, records: Optional[list[str]], state: str) -> None:
        self.records = records
        self.state = state          # ok | empty | nxdomain | timeout | dns_failure


def _rdata_text(rdtype: str, rdata: Any) -> str:
    """One answer as plain text (no trailing dots, no quotes)."""
    if rdtype in ("A", "AAAA"):
        return str(rdata.address)
    if rdtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    if rdtype == "NS":
        return rdata.target.to_text().rstrip(".")
    if rdtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="replace")[:_MAX_TXT_LEN]
    if rdtype == "CAA":
        value = rdata.value.decode("utf-8", errors="replace") if isinstance(rdata.value, bytes) else str(rdata.value)
        tag = rdata.tag.decode("ascii", errors="replace") if isinstance(rdata.tag, bytes) else str(rdata.tag)
        return f"{rdata.flags} {tag} {value}"
    return rdata.to_text()


def _reverse_label(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """The reversed-octet / reversed-nibble form used by Team Cymru's zones."""
    pointer = ip.reverse_pointer
    return pointer.removesuffix(".in-addr.arpa").removesuffix(".ip6.arpa")


class DnsClient:
    def __init__(
        self,
        use_mock: bool = True,
        *,
        resolver: Any = None,
        cache: Optional[ProviderCache] = None,
        cache_ttl: float = 900.0,
        not_found_ttl: float = 300.0,
        timeout: float = 4.0,
        lifetime: float = 6.0,
        nameservers: Optional[list[str]] = None,
    ) -> None:
        self._use_mock = use_mock
        self._resolver = resolver
        self._cache = cache if cache is not None else ProviderCache()
        self._ttl = cache_ttl
        self._not_found_ttl = not_found_ttl
        self._timeout = timeout
        self._lifetime = lifetime
        self._nameservers = nameservers

    def _get_resolver(self):
        if self._resolver is None:
            r = dns.asyncresolver.Resolver()          # system configuration (registry / resolv.conf)
            r.timeout = self._timeout
            r.lifetime = self._lifetime
            if self._nameservers:
                r.nameservers = list(self._nameservers)
            self._resolver = r
        return self._resolver

    async def close(self) -> None:                   # symmetry with the other clients; nothing to release
        return None

    # ── one query ──────────────────────────────────────────────────────
    async def _query(self, name: str, rdtype: str) -> _Outcome:
        try:
            answer = await self._get_resolver().resolve(name, rdtype, lifetime=self._lifetime)
        except dns.resolver.NXDOMAIN:
            return _Outcome([], "nxdomain")
        except dns.resolver.NoAnswer:
            return _Outcome([], "empty")
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            return _Outcome(None, "timeout")
        except (dns.resolver.NoNameservers, dns.exception.DNSException, OSError) as exc:
            logger.debug("DNS %s %s failed: %s", rdtype, name, exc)
            return _Outcome(None, "dns_failure")
        records = [_rdata_text(rdtype, r) for r in answer]
        return _Outcome(records, "ok" if records else "empty")

    async def _asn(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[dict, bool]:
        """Origin AS of ``ip`` via Team Cymru DNS → ``(fields, lookup_failed)``."""
        zone = _CYMRU_V4 if ip.version == 4 else _CYMRU_V6
        origin = await self._query(f"{_reverse_label(ip)}.{zone}", "TXT")
        if origin.records is None:
            return {}, True
        if not origin.records:
            return {}, False                          # unannounced prefix: a real "no ASN", not a failure
        fields = [p.strip() for p in origin.records[0].split("|")]
        if len(fields) < 3 or not fields[0].split()[0].isdigit():
            return {}, False
        asn = int(fields[0].split()[0])
        out: dict[str, Any] = {"asn": asn, "asn_prefix": fields[1] or None, "asn_country": fields[2] or None}
        name = await self._query(f"AS{asn}.{_CYMRU_AS}".lower(), "TXT")
        if name.records:
            parts = [p.strip() for p in name.records[0].split("|")]
            if len(parts) >= 5:
                out["asn_org"] = parts[4] or None
        return out, False

    # ── public ─────────────────────────────────────────────────────────
    async def lookup(self, host: str, registered_domain: Optional[str] = None) -> ProviderResult[DnsInfo]:
        host = (host or "").lower().rstrip(".")
        blocked = privacy.provider_block_reason(host)
        if blocked:                                   # never resolve internal names through public resolvers
            return prov.skipped(SOURCE, blocked)
        apex = (registered_domain or host).lower().rstrip(".")
        if self._use_mock:
            return prov.ok(SOURCE, self._mock(host, apex), http_status=None, mock=True)

        key = f"dns:{host}|{apex}"
        try:
            cached = await self._cache.get(SOURCE, key, DnsInfo)
        except Exception:
            logger.exception("provider cache read failed; continuing without it")
            cached = None
        if cached is not None:
            return cached

        started = prov.start_timer()
        families = {"a": (host, "A"), "aaaa": (host, "AAAA"), "mx": (apex, "MX"), "ns": (apex, "NS"),
                    "txt": (apex, "TXT"), "caa": (apex, "CAA"), "dmarc": (f"_dmarc.{apex}", "TXT")}
        outcomes = dict(zip(families, await asyncio.gather(*(self._query(n, t) for n, t in families.values()))))

        # The host does not exist at all.
        if outcomes["a"].state == "nxdomain" and outcomes["aaaa"].state == "nxdomain":
            return prov.not_found(SOURCE, http_status=None, started=started)
        # Nothing answered.
        if all(o.records is None for o in outcomes.values()):
            states = {o.state for o in outcomes.values()}
            return prov.error(SOURCE, "timeout" if "timeout" in states else "dns_failure", started=started)

        failed: list[str] = []

        def family(name: str) -> Optional[list[str]]:
            o = outcomes[name]
            if o.records is None:
                failed.append(name)
                return None
            return o.records                              # NXDOMAIN at an apex family = "none exist"

        a, aaaa = family("a"), family("aaaa")
        mx, ns, txt, caa = family("mx"), family("ns"), family("txt"), family("caa")

        spf: Optional[bool] = None
        spf_record: Optional[str] = None
        if txt is not None:
            spf_record = next((t for t in txt if t.lower().startswith("v=spf1")), None)
            spf = spf_record is not None
        dmarc: Optional[bool] = None
        dmarc_policy: Optional[str] = None
        dmarc_records = family("dmarc")
        if dmarc_records is not None:
            record = next((t for t in dmarc_records if t.upper().startswith("V=DMARC1")), None)
            dmarc = record is not None
            if record:
                m = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)", record, re.IGNORECASE)
                dmarc_policy = m.group(1).lower() if m else None

        # Hosting ASN of the first *public* address (internal addresses never leave the machine).
        asn_fields: dict[str, Any] = {}
        candidates = [ipaddress.ip_address(x) for x in (a or []) + (aaaa or []) if _is_ip(x)]
        public = next((ip for ip in candidates if blocked_reason(ip) is None), None)
        if public is not None:
            asn_fields, asn_failed = await self._asn(public)
            if asn_failed:
                failed.append("asn")

        info = DnsInfo(
            host=host, lookup_domain=apex,
            a=a, aaaa=aaaa, mx=mx, ns=ns, txt=txt[:_MAX_TXT] if txt is not None else None, caa=caa,
            spf=spf, spf_record=spf_record, dmarc=dmarc, dmarc_policy=dmarc_policy,
            failed_types=sorted(set(failed)), **asn_fields,
        )
        reason = f"partial:{','.join(info.failed_types)}" if info.failed_types else None
        result = prov.ok(SOURCE, info, http_status=None, started=started, reason=reason)
        if not info.failed_types:                       # a partial answer must not be remembered for the full TTL
            try:
                await self._cache.put(SOURCE, key, result, ttl_ok=self._ttl, ttl_not_found=self._not_found_ttl)
            except Exception:
                logger.exception("provider cache write failed; continuing without it")
        return result

    # ── mock ───────────────────────────────────────────────────────────
    @staticmethod
    def _mock(host: str, apex: str) -> DnsInfo:
        """Deterministic, plausible records: established brands have mail auth, 'evil' hosts have none."""
        digest = int(hashlib.sha256(host.encode()).hexdigest(), 16)
        suspicious = any(w in host for w in ("evil", "malicious", "phish"))
        established = any(w in host for w in ("google", "microsoft"))
        ip = f"93.184.{(digest >> 8) % 250 + 1}.{digest % 250 + 1}"
        if suspicious:
            return DnsInfo(host=host, lookup_domain=apex, a=[ip], aaaa=[], mx=[], ns=["ns1.cheap-dns.example", "ns2.cheap-dns.example"],
                           txt=[], caa=[], spf=False, dmarc=False, asn=64500, asn_org="BULK-HOSTING-MOCK, ZZ",
                           asn_prefix=f"{ip.rsplit('.', 1)[0]}.0/24", asn_country="ZZ")
        return DnsInfo(host=host, lookup_domain=apex, a=[ip], aaaa=["2606:2800:220:1:248:1893:25c8:1946"] if established else [],
                       mx=[f"10 mail.{apex}"], ns=[f"ns1.{apex}", f"ns2.{apex}"],
                       txt=["v=spf1 include:_spf.example.net ~all"], caa=["0 issue letsencrypt.org"],
                       spf=True, spf_record="v=spf1 include:_spf.example.net ~all", dmarc=True,
                       dmarc_policy="reject" if established else "none", asn=15169 if established else 64496,
                       asn_org="MOCK-AS, ZZ", asn_prefix=f"{ip.rsplit('.', 1)[0]}.0/24", asn_country="ZZ")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
