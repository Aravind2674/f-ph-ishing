"""
ThreatFusion – Active Verification Engine  (Phase 4)
=====================================================

Closes the detection loop: Phases 2–3 *flag* likely injection points from
request text; this module *confirms* them by actively probing the target and
observing its response — the "simulate the attack and check" step a pentester
performs to separate a real finding from a false positive.

SAFETY IS THE DESIGN, NOT AN AFTERTHOUGHT
-----------------------------------------
1. **Scope gate (default-deny).** Probing only runs against loopback or a host
   the caller *explicitly* attests it is authorised to test (``authorized_hosts``).
   Any other host is refused before a single packet is sent. This makes the tool
   a scoped assessment aid, not a weapon that can be pointed anywhere.
2. **Non-destructive payloads only.** The probes are read-only detection
   signals — a reflection canary, boolean truth/false comparison, and error
   fingerprinting. There is deliberately **no** payload that deletes, writes,
   exfiltrates, or executes anything (no ``DROP``, no stacked queries, no OS
   commands, no out-of-band callbacks).
3. **Bounded.** Short timeouts and a hard cap on the number of probes.

These are the same safe techniques a DAST scanner (Burp/ZAP active scan) uses to
*verify* — nothing here escalates to exploitation.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

logger = logging.getLogger(__name__)

# Hosts always considered in-scope (local lab). Everything else must be opted in.
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

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

    @property
    def confirmed(self) -> List[ProbeResult]:
        return [p for p in self.probes if p.confirmed]


def host_is_authorized(host: str, authorized_hosts: set[str]) -> bool:
    """Default-deny scope check: loopback, or an explicitly authorised host."""
    h = (host or "").lower().split(":")[0]
    return h in LOOPBACK_HOSTS or h in {a.lower() for a in authorized_hosts}


class ActiveVerifier:
    """Runs safe, scope-gated active confirmation probes against a target URL."""

    def __init__(
        self,
        authorized_hosts: Optional[set[str]] = None,
        timeout: float = 6.0,
        max_params: int = 15,
    ) -> None:
        self.authorized_hosts = {h.lower() for h in (authorized_hosts or set())}
        self.timeout = timeout
        self.max_params = max_params

    # ------------------------------------------------------------------
    def _swap_param(self, url: str, name: str, value: str) -> str:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        new = [(k, value if k == name else v) for k, v in pairs]
        return urlunsplit(parts._replace(query=urlencode(new)))

    async def _get(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        return await client.get(url, follow_redirects=False)

    # ------------------------------------------------------------------
    async def _probe_param(
        self, client: httpx.AsyncClient, url: str, name: str, original: str
    ) -> List[ProbeResult]:
        results: List[ProbeResult] = []

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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
            logger.debug("boolean-sqli probe error on %s: %s", name, exc)

        return results

    # ------------------------------------------------------------------
    async def verify(self, url: str) -> VerifyReport:
        """Scope-check, then run non-destructive confirmation probes on each param."""
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not host_is_authorized(host, self.authorized_hosts):
            return VerifyReport(
                target=url, authorized=False,
                error=(f"Refusing to probe '{host}': not in scope. Active verification "
                       f"is limited to localhost or hosts you explicitly authorise."),
            )

        params = parse_qsl(parts.query, keep_blank_values=True)[: self.max_params]
        report = VerifyReport(target=url, authorized=True,
                              tested_params=[k for k, _ in params])
        if not params:
            report.error = "No query parameters to probe."
            return report

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for name, value in params:
                report.probes.extend(await self._probe_param(client, url, name, value))
        return report
