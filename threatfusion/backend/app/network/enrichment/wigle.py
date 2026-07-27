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

from app.network.models import WigleResult

logger = logging.getLogger(__name__)


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

    async def lookup_bssid(self, bssid: str) -> WigleResult:
        """Query WiGLE for the public history of a single BSSID.

        Returns a fully-populated :class:`WigleResult` on success, or an
        ``available=False`` result carrying the concrete failure reason.
        """
        if not self.configured:
            return WigleResult(
                available=False,
                reason="WiGLE credentials not configured (set WIGLE_API_NAME / WIGLE_API_TOKEN)",
                bssid=bssid,
            )

        client = await self._get_client()
        try:
            resp = await client.get(
                f"{self._base_url}/network/search",
                params={"netid": bssid},
            )
        except httpx.HTTPError as e:
            logger.warning("WiGLE request error for %s: %s", bssid, e)
            return WigleResult(available=False, reason=f"WiGLE request failed: {e}", bssid=bssid)

        if resp.status_code == 401:
            return WigleResult(
                available=False, reason="WiGLE authentication failed (401) — check credentials",
                bssid=bssid,
            )
        if resp.status_code == 429:
            return WigleResult(
                available=False, reason="WiGLE rate limit reached (429) — daily quota exhausted",
                bssid=bssid,
            )
        if resp.status_code != 200:
            return WigleResult(
                available=False,
                reason=f"WiGLE returned HTTP {resp.status_code}",
                bssid=bssid,
            )

        try:
            data = resp.json()
        except ValueError as e:
            return WigleResult(available=False, reason=f"WiGLE response not JSON: {e}", bssid=bssid)

        if not data.get("success", False):
            # WiGLE reports auth/quota problems in-band with success=false.
            msg = data.get("message", "unknown error")
            return WigleResult(available=False, reason=f"WiGLE error: {msg}", bssid=bssid)

        results = data.get("results", []) or []
        total = int(data.get("totalResults", len(results)) or 0)

        if total == 0 or not results:
            # A real, meaningful answer: WiGLE has never publicly seen this AP.
            return WigleResult(
                available=True,
                bssid=bssid,
                found=False,
                total_observations=0,
            )

        top = results[0]
        ssids = []
        for r in results:
            s = r.get("ssid")
            if s and s not in ssids:
                ssids.append(s)

        return WigleResult(
            available=True,
            bssid=bssid,
            found=True,
            total_observations=total,
            first_seen=top.get("firsttime"),
            last_seen=top.get("lasttime"),
            known_ssids=ssids[:5],
        )
