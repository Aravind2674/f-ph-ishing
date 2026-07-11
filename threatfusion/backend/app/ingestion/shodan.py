"""
ThreatFusion – Shodan Ingestion Client
=======================================

Wraps **two** Shodan data sources behind a single async interface:

1. **InternetDB** (``https://internetdb.shodan.io/{ip}``) – free, no API
   key required, returns open ports, hostnames, CPEs, CVEs, and tags for
   any public IPv4 address.  This is our primary source.
2. **Shodan REST API** (``https://api.shodan.io/shodan/host/{ip}``) – paid,
   requires an API key, returns richer banner / service data.  Used only
   when the user has supplied a Shodan key.

Design rationale
----------------
Having *two* tiers means the system always works (InternetDB is free) but
can be *upgraded* by simply providing an API key – no code changes needed.
"""

from __future__ import annotations

import logging
import time
from typing import Optional, Dict, Tuple, Any

import httpx

from app.models.schemas import ShodanResult

logger = logging.getLogger(__name__)


class ShodanClient:
    """Async client for Shodan InternetDB and the full Shodan REST API.

    Parameters
    ----------
    api_key : str
        Shodan API key.  May be an empty string when only InternetDB
        (key‑less) lookups are needed.
    use_mock : bool
        When True, return deterministic synthetic data instead of
        making real HTTP calls.
    """

    def __init__(self, api_key: str = "", use_mock: bool = True) -> None:
        self._api_key: str = api_key
        self._use_mock: bool = use_mock
        self._internetdb_url: str = "https://internetdb.shodan.io"
        self._full_api_url: str = "https://api.shodan.io"
        
        # Simple in-memory cache to reduce network latency for identical IPs
        self._cache: Dict[str, Tuple[ShodanResult, float]] = {}
        self._cache_ttl = 3600  # 1 hour
        
        self._client: Optional[httpx.AsyncClient] = None
        logger.info(
            "ShodanClient initialised (mock_mode=%s, has_api_key=%s)",
            self._use_mock,
            bool(self._api_key),
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-initialize HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=15.0)
        return self._client
        
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
            
    def _check_cache(self, key: str) -> Optional[ShodanResult]:
        """Check cache for fresh data."""
        if self._use_mock:
            return None
        if key in self._cache:
            result, timestamp = self._cache[key]
            if time.time() - timestamp < self._cache_ttl:
                logger.debug("Cache hit for %s", key)
                return result
            else:
                del self._cache[key]
        return None

    def _set_cache(self, key: str, result: ShodanResult) -> None:
        """Store data in cache."""
        if not self._use_mock:
            self._cache[key] = (result, time.time())

    def _generate_mock(self, ip: str, is_full: bool) -> ShodanResult:
        """Generate deterministic mock data for the IP."""
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
            return ShodanResult()  # Private IPs usually have no InternetDB entry
            
        if ip == "8.8.8.8":
            return ShodanResult(
                open_ports=[53, 443],
                hostnames=["dns.google"],
                cpes=[],
                vulns=[],
                tags=["dns"]
            )
            
        # Default mock profile
        tags = ["cloud", "vpn"] if is_full else ["cloud"]
        hostnames = ["full.api.example.com"] if is_full else ["example.com"]
            
        return ShodanResult(
            open_ports=[80, 443, 8080, 22],
            hostnames=hostnames,
            cpes=["cpe:/a:apache:http_server:2.4.49"],
            vulns=["CVE-2021-44228", "CVE-2021-41773"],
            tags=tags,
            org="Mock Organization" if is_full else None,
            isp="Mock ISP" if is_full else None,
            asn="AS12345" if is_full else None,
            country="United States" if is_full else None,
            city="New York" if is_full else None,
            banner_data=[{"port": "80", "protocol": "tcp", "product": "Apache httpd", "version": "2.4.49"}] if is_full else []
        )

    # ------------------------------------------------------------------
    # Public async methods
    # ------------------------------------------------------------------

    async def lookup_ip(self, ip: str) -> ShodanResult:
        """Query InternetDB for basic port / CVE data on an IP."""
        if self._use_mock:
            return self._generate_mock(ip, is_full=False)
            
        cache_key = f"internetdb:{ip}"
        cached = self._check_cache(cache_key)
        if cached:
            return cached
            
        client = await self._get_client()
        try:
            response = await client.get(f"{self._internetdb_url}/{ip}")
            if response.status_code == 404:
                # 404 is a valid response meaning the IP has no open ports known
                result = ShodanResult()
                self._set_cache(cache_key, result)
                return result
                
            response.raise_for_status()
            data = response.json()
            
            result = ShodanResult(
                open_ports=data.get("ports", []),
                hostnames=data.get("hostnames", []),
                cpes=data.get("cpes", []),
                vulns=data.get("vulns", []),
                tags=data.get("tags", [])
            )
            self._set_cache(cache_key, result)
            return result
        except httpx.HTTPError as e:
            logger.warning("InternetDB API error for %s: %s", ip, e)
            return ShodanResult()

    async def lookup_ip_full(self, ip: str) -> ShodanResult:
        """Query the full Shodan REST API for rich service data."""
        if self._use_mock:
            return self._generate_mock(ip, is_full=True)
            
        if not self._api_key:
            logger.info("No Shodan API key provided, falling back to InternetDB for %s", ip)
            return await self.lookup_ip(ip)
            
        cache_key = f"full:{ip}"
        cached = self._check_cache(cache_key)
        if cached:
            return cached
            
        client = await self._get_client()
        try:
            response = await client.get(
                f"{self._full_api_url}/shodan/host/{ip}",
                params={"key": self._api_key}
            )
            if response.status_code == 404:
                result = ShodanResult()
                self._set_cache(cache_key, result)
                return result
                
            response.raise_for_status()
            data = response.json()
            
            result = ShodanResult(
                open_ports=data.get("ports", []),
                hostnames=data.get("hostnames", []),
                tags=data.get("tags", []),
                org=data.get("org"),
                isp=data.get("isp"),
                asn=data.get("asn"),
                country=data.get("country_name"),
                city=data.get("city")
            )
            
            # The full API structure requires iteration to pull all CPEs/vulns
            # since they are often nested within individual port service banners.
            vulns = set(data.get("vulns", []))
            cpes = set()
            banners = []
            for item in data.get("data", []):
                if "cpe" in item:
                    for cpe in item["cpe"]:
                        cpes.add(cpe)
                if "vulns" in item:
                    for vuln in item["vulns"].keys():
                        vulns.add(vuln)
                
                banner = {
                    "port": str(item.get("port", "")),
                    "protocol": str(item.get("transport", "")),
                    "product": str(item.get("product", "")),
                    "version": str(item.get("version", ""))
                }
                banners.append(banner)
                        
            result.cpes = list(cpes)
            result.vulns = list(vulns)
            result.banner_data = banners
            
            self._set_cache(cache_key, result)
            return result
        except httpx.HTTPError as e:
            logger.warning("Shodan Full API error for %s: %s", ip, e)
            return ShodanResult()
