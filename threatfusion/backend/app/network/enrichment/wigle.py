"""
ThreatFusion – WiGLE Public-History Client (Rogue-AP Signal)
=============================================================

Implements **differentiator #2**: WiGLE as a *signal*, not a competitor.
When a possibly-rogue access point is detected we query its BSSID against
WiGLE's real public wardriving history:

* **Zero prior observations** (a BSSID never publicly seen) → suspicion up.
* **Years of sightings** → suspicion down (an established, mapped AP).

This is exactly one real input to the AP's fused score — the correlation
engine decides how many points it is worth.

API
---
WiGLE v2 uses HTTP Basic auth with an *API name* + *API token* (both from
https://wigle.net/account), not a single key. We call::

    GET https://api.wigle.net/api/v2/network/search?netid=<BSSID>

Honesty contract
----------------
If credentials are missing, or WiGLE is rate-limited/unreachable at
runtime, the returned :class:`WigleResult` is ``available=False`` with the
real reason. The AP scorer then relies on the remaining real signals and
says so in the alert evidence — it never invents a WiGLE history.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.core import providers as prov
from app.models.schemas import ProviderResult, ProviderStatus
from app.network.models import WigleResult

logger = logging.getLogger(__name__)

SOURCE = "wigle"

_HUMAN = {
    "not_configured": "WiGLE credentials not configured (set WIGLE_API_NAME / WIGLE_API_TOKEN)",
    "auth": "WiGLE authentication failed (HTTP 401/403) — check credentials",
    "rate_limited": "WiGLE rate limit reached (429) — daily quota exhausted",
    "parse_error": "WiGLE response was not usable JSON",
}


def to_evidence(res: ProviderResult[WigleResult], bssid: str) -> WigleResult:
    """Bridge a ``ProviderResult`` to the alert-evidence model the engine and UI already use.

    ``ok`` → the parsed result; ``not_found`` → a real answer "WiGLE has never seen this BSSID"
    (a *signal*); anything else → ``available=False`` with the reason, so the AP is scored on
    its other signals and the alert says why.
    """
    if res.status == ProviderStatus.OK and res.data is not None:
        return res.data
    if res.status == ProviderStatus.NOT_FOUND:
        return WigleResult(available=True, bssid=bssid, found=False, total_observations=0)
    code = res.reason or res.status.value
    if code in _HUMAN:
        reason = _HUMAN[code]
    elif code.startswith("http_"):
        reason = f"WiGLE returned HTTP {code[5:]}"
    elif code.startswith("api_error"):
        reason = f"WiGLE error: {code.partition(':')[2] or 'unknown'}"
    else:
        reason = f"WiGLE request failed: {code}"
    return WigleResult(available=False, reason=reason, bssid=bssid)


class WigleClient:
    """Async client for the WiGLE v2 network-search endpoint.

    Parameters
    ----------
    api_name : str
        WiGLE API name (Basic-auth username).
    api_token : str
        WiGLE API token (Basic-auth password).
    """

    def __init__(self, api_name: str = "", api_token: str = "") -> None:
        self._api_name = api_name
        self._api_token = api_token
        self._base_url = "https://api.wigle.net/api/v2"
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def configured(self) -> bool:
        """True only when both halves of the WiGLE credential are present."""
        return bool(self._api_name and self._api_token)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=20.0,
                auth=(self._api_name, self._api_token),
                headers={"Accept": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def lookup_bssid(self, bssid: str) -> ProviderResult[WigleResult]:
        """Query WiGLE for the public history of a single BSSID.

        Returns a ``ProviderResult`` (A0-1): ``ok`` (found), ``not_found`` (WiGLE has never
        seen it — meaningful for rogue-AP scoring), ``not_configured`` or ``error`` with a
        reason code.  Use :func:`to_evidence` for the alert-evidence view.
        """
        if not self.configured:
            return prov.not_configured(SOURCE)

        client = await self._get_client()
        started = prov.start_timer()
        try:
            resp = await client.get(
                f"{self._base_url}/network/search",
                params={"netid": bssid},
            )
        except Exception as e:
            logger.warning("WiGLE request error for %s: %s", bssid, e)
            return prov.from_exception(SOURCE, e, started=started)

        # WiGLE: 404 is not used for "no results" (that is a 200 with totalResults=0).
        failure = prov.from_http_status(SOURCE, resp.status_code, started=started)
        if failure is not None:
            if failure.status == ProviderStatus.NOT_FOUND:  # unexpected 404 → treat as an error
                return prov.error(SOURCE, "http_404", http_status=404, started=started)
            return failure

        try:
            data = resp.json()
        except ValueError:
            return prov.error(SOURCE, "parse_error", http_status=resp.status_code, started=started)

        if not isinstance(data, dict) or not data.get("success", False):
            # WiGLE reports auth/quota problems in-band with success=false.
            msg = str((data or {}).get("message", "unknown error"))[:80] if isinstance(data, dict) else "bad payload"
            return prov.error(SOURCE, f"api_error:{msg}", http_status=resp.status_code, started=started)

        results = data.get("results", []) or []
        total = int(data.get("totalResults", len(results)) or 0)

        if total == 0 or not results:
            # A real, meaningful answer: WiGLE has never publicly seen this AP.
            return prov.not_found(SOURCE, http_status=resp.status_code, started=started)

        top = results[0]
        ssids = []
        for r in results:
            s = r.get("ssid")
            if s and s not in ssids:
                ssids.append(s)

        return prov.ok(SOURCE, WigleResult(
            available=True,
            bssid=bssid,
            found=True,
            total_observations=total,
            first_seen=top.get("firsttime"),
            last_seen=top.get("lasttime"),
            known_ssids=ssids[:5],
        ), http_status=resp.status_code, started=started)
