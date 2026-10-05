"""
ThreatFusion – Active Verification Engine  (Phase 4, hardened in A0-3)
======================================================================

Closes the detection loop: Phases 2–3 *flag* likely injection points from
request text; this module *confirms* them by actively probing the target and
observing its response — the "simulate the attack and check" step a pentester
performs to separate a real finding from a false positive.

SAFETY IS THE DESIGN, NOT AN AFTERTHOUGHT
-----------------------------------------
1. **Server-side scope (default-deny).**  Probing only runs against hosts the *operator* listed in
   ``VERIFY_ALLOWED_HOSTS`` (and only if ``VERIFY_ENABLED`` is on).  The scope is **never** taken
   from the request: the original design let the caller list their own "authorised" hosts, which
   meant anyone who could reach the API could point the probes at any host (audit §H1).
   Loopback is not special any more — the bundled local lab is simply the default allowlist entry.
2. **Every request goes through the SSRF-safe fetcher** (:mod:`app.core.safe_http`): the connection
   is pinned to a validated IP, redirects are not followed, link-local/cloud-metadata space is
   unreachable even for listed hosts, TLS verification is on by default, size/time are capped.
3. **Non-destructive payloads only.**  Read-only detection signals — a reflection canary, boolean
   truth/false comparison, and error fingerprinting.  There is deliberately **no** payload that
   deletes, writes, exfiltrates, or executes anything (no ``DROP``, no stacked queries, no OS
   commands, no out-of-band callbacks).
4. **Bounded.**  Short timeouts and a hard cap on the number of probes.

These are the same safe techniques a DAST scanner (Burp/ZAP active scan) uses to
*verify* — nothing here escalates to exploitation.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.core.config import parse_host_port
from app.core.safe_http import FetchError, FetchPolicy, SafeFetcher, UnsafeTargetError

logger = logging.getLogger(__name__)

# SQL error fingerprints — presence in a response after a single-quote probe is
# strong evidence the input reaches an SQL interpreter unsanitised.
_SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlite3.operationalerror", "sqlite_error", "near \"'\": syntax error",
    "unrecognized token", "syntax error near",
    "org.postgresql", "psql:", "pg_query", "ora-00933", "ora-01756",
    "odbc", "microsoft ole db", "sqlstate", "warning: mysql",
]

TECHNIQUES = ("reflected-xss", "error-sqli", "boolean-sqli")


@dataclass
class ProbeResult:
    """Outcome of one active check against one parameter."""

    param: str
    technique: str  # "reflected-xss" | "error-sqli" | "boolean-sqli"
    confirmed: bool
    confidence: float
    evidence: str
    payload: str


@dataclass
class VerifyReport:
    """Full result of verifying a target URL."""

    target: str
    authorized: bool
    tested_params: List[str] = field(default_factory=list)
    probes: List[ProbeResult] = field(default_factory=list)
    error: Optional[str] = None
    # Audit data (A0-3)
    resolved_ip: Optional[str] = None
    checks_run: List[str] = field(default_factory=list)
    blocked: Optional[str] = None

    @property
    def confirmed(self) -> List[ProbeResult]:
        return [p for p in self.probes if p.confirmed]


# ── Scope ───────────────────────────────────────────────────────────────────
def _normalise_scope(entries: Iterable) -> frozenset[tuple[str, Optional[int]]]:
    out: set[tuple[str, Optional[int]]] = set()
    for e in entries:
        if isinstance(e, tuple):
            host, port = e
            out.add((str(host).lower().strip("[]"), port))
        else:
            out.add(parse_host_port(str(e)))
    return frozenset(out)


def host_is_authorized(host: str, allowed: Iterable, port: Optional[int] = None) -> bool:
    """Default-deny scope check against the **server-configured** allowlist.

    ``allowed`` holds ``"host"`` / ``"host:port"`` strings or ``(host, port)`` tuples.  An entry
    without a port matches any port; an entry with a port matches only that port.  Nothing is
    in scope by default — not even loopback.
    """
    h = (host or "").lower().strip("[]")
    return any(h == eh and (ep is None or ep == port) for eh, ep in _normalise_scope(allowed))


class _FetchedResponse:
    """Minimal response object the probes read (``.text``, ``.status_code``)."""

    def __init__(self, text: str, status_code: int) -> None:
        self.text = text
        self.status_code = status_code


class _SafeClient:
    """Adapter giving the probes a ``get(url)`` that goes through the SSRF-safe fetcher.

    Redirects are never followed (a verification target must answer directly), and the validated IP
    of the last connection is remembered for the audit record.
    """

    def __init__(self, fetcher: SafeFetcher) -> None:
        self._fetcher = fetcher
        self.last_ip: Optional[str] = None

    async def get(self, url: str, follow_redirects: bool = False) -> _FetchedResponse:
        res = await self._fetcher.fetch(
            url, follow_redirects=False, headers={"User-Agent": "ThreatFusion-Verify/1.0"})
        self.last_ip = res.ip
        return _FetchedResponse(res.text, res.status_code)


class ActiveVerifier:
    """Runs safe, scope-gated active confirmation probes against a target URL."""

    def __init__(
        self,
        allowed_hosts: Optional[Iterable] = None,
        timeout: float = 6.0,
        max_params: int = 15,
        verify_tls: bool = True,
    ) -> None:
        self.allowed = _normalise_scope(allowed_hosts or ())
        self.timeout = timeout
        self.max_params = max_params
        # Listed hosts may resolve to private/lab addresses (explicit operator opt-in), but the
        # fetcher still refuses link-local/metadata space for them.
        self.fetcher = SafeFetcher(FetchPolicy.from_settings(
            max_bytes=512 * 1024, total_timeout=timeout * 2, request_timeout=timeout,
            verify_tls=verify_tls, allow_private=self.allowed,
        ))

    # ------------------------------------------------------------------
    def in_scope(self, host: str, port: Optional[int]) -> bool:
        return host_is_authorized(host, self.allowed, port)

    def _swap_param(self, url: str, name: str, value: str) -> str:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        new = [(k, value if k == name else v) for k, v in pairs]
        return urlunsplit(parts._replace(query=urlencode(new)))

    async def _get(self, client, url: str):
        return await client.get(url, follow_redirects=False)

    # ------------------------------------------------------------------
    async def _probe_param(self, client, url: str, name: str, original: str) -> List[ProbeResult]:
        """Run the three probes on one parameter.

        Transport hiccups (timeout/network) just mean "no evidence"; but a policy refusal
        (:class:`UnsafeTargetError`) propagates so the whole run stops and is reported as blocked.
        """
        results: List[ProbeResult] = []
        soft_errors = (httpx.HTTPError, FetchError)

        # ── Reflected-XSS canary ────────────────────────────────────────
        # A unique marker containing raw angle brackets. If it comes back
        # *unescaped*, the parameter reflects markup → XSS-susceptible. The
        # marker is inert (not a <script>), so nothing executes.
        token = secrets.token_hex(4)
        canary = f"tfx{token}<x>"
        try:
            resp = await self._get(client, self._swap_param(url, name, canary))
            body = resp.text
            if canary in body:
                results.append(ProbeResult(
                    param=name, technique="reflected-xss", confirmed=True, confidence=0.95,
                    evidence=f"Raw marker '{canary}' reflected unescaped in the response body.",
                    payload=canary,
                ))
            elif f"tfx{token}&lt;x&gt;" in body or f"tfx{token}" in body:
                results.append(ProbeResult(
                    param=name, technique="reflected-xss", confirmed=False, confidence=0.6,
                    evidence="Marker reflected but HTML-escaped (output encoding present).",
                    payload=canary,
                ))
        except soft_errors as exc:
            logger.debug("xss probe error on %s: %s", name, exc)

        # ── Error-based SQLi ────────────────────────────────────────────
        # A lone single quote. A raw SQL error in the response means the value
        # reaches the database unsanitised. Read-only; breaks no data.
        try:
            resp = await self._get(client, self._swap_param(url, name, original + "'"))
            low = resp.text.lower()
            hit = next((sig for sig in _SQL_ERRORS if sig in low), None)
            if hit:
                results.append(ProbeResult(
                    param=name, technique="error-sqli", confirmed=True, confidence=0.9,
                    evidence=f"SQL error signature '{hit}' surfaced after a single-quote probe.",
                    payload=original + "'",
                ))
        except soft_errors as exc:
            logger.debug("error-sqli probe error on %s: %s", name, exc)

        # ── Boolean-based SQLi ──────────────────────────────────────────
        # Compare a tautology (always TRUE) against a contradiction (always
        # FALSE). A large, consistent divergence in the responses indicates the
        # boolean is being evaluated by the backend. SELECT-logic only.
        try:
            true_url = self._swap_param(url, name, f"{original}' OR '1'='1")
            false_url = self._swap_param(url, name, f"{original}' AND '1'='2")
            t_resp, f_resp = await asyncio.gather(
                self._get(client, true_url), self._get(client, false_url)
            )
            sim = SequenceMatcher(None, t_resp.text, f_resp.text).ratio()
            len_delta = abs(len(t_resp.text) - len(f_resp.text))
            if sim < 0.9 and len_delta > 25:
                results.append(ProbeResult(
                    param=name, technique="boolean-sqli", confirmed=True, confidence=0.8,
                    evidence=(f"TRUE vs FALSE payloads diverged (similarity {sim:.2f}, "
                              f"len-delta {len_delta}) - boolean condition evaluated server-side."),
                    payload="' OR '1'='1  /  ' AND '1'='2",
                ))
        except soft_errors as exc:
            logger.debug("boolean-sqli probe error on %s: %s", name, exc)

        return results

    # ------------------------------------------------------------------
    async def verify(self, url: str) -> VerifyReport:
        """Scope-check, then run non-destructive confirmation probes on each param."""
        parts = urlsplit(url)
        host = parts.hostname or ""
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            port = None
        if not self.in_scope(host, port):
            return VerifyReport(
                target=url, authorized=False,
                error=(f"Refusing to probe '{host}': not in scope. Active verification is limited to "
                       f"hosts the server operator has listed in VERIFY_ALLOWED_HOSTS."),
            )

        params = parse_qsl(parts.query, keep_blank_values=True)[: self.max_params]
        report = VerifyReport(target=url, authorized=True,
                              tested_params=[k for k, _ in params])
        if not params:
            report.error = "No query parameters to probe."
            return report

        client = _SafeClient(self.fetcher)
        try:
            for name, value in params:
                report.probes.extend(await self._probe_param(client, url, name, value))
                report.checks_run.extend(TECHNIQUES)
        except UnsafeTargetError as exc:
            # e.g. a listed host that resolves to link-local/metadata space: stop, don't probe.
            report.blocked = exc.reason
            report.error = f"blocked: {exc.reason} ({exc.detail})"
        report.resolved_ip = client.last_ip
        return report
