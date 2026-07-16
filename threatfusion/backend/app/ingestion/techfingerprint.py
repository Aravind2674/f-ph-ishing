"""
ThreatFusion – Technology Fingerprinting Client
================================================

Detects web technologies (frameworks, CMS, servers, analytics, CDNs, …)
using the industry-standard python-Wappalyzer library.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import httpx
from Wappalyzer import Wappalyzer, WebPage

from app.models.schemas import TechFingerprintResult, DetectedTechnology

logger = logging.getLogger(__name__)

# Initialize Wappalyzer globally
try:
    _WAPPALYZER = Wappalyzer.latest()
except Exception as e:
    logger.error("Failed to load Wappalyzer: %s", e)
    _WAPPALYZER = None


class TechFingerprintClient:
    """Async technology fingerprinting client using Wappalyzer data."""

    def __init__(self, use_mock: bool = True) -> None:
        self._use_mock: bool = use_mock
        self._client: Optional[httpx.AsyncClient] = None
        logger.info(
            "TechFingerprintClient initialised (mock_mode=%s)", self._use_mock
        )

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=10.0, 
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _generate_mock(self, url: str) -> TechFingerprintResult:
        import hashlib
        import random
        
        url_lower = url.lower()
        techs = []
        
        # Seed based on URL to generate unique but deterministic technologies
        seed_val = int(hashlib.md5(url.encode('utf-8')).hexdigest(), 16)
        rng = random.Random(seed_val)
        
        if "wordpress" in url_lower:
            techs.extend([
                DetectedTechnology(name="WordPress", version="6.1", categories=["CMS"], confidence=100),
                DetectedTechnology(name="PHP", categories=["Programming languages"], confidence=100),
                DetectedTechnology(name="Apache", categories=["Web servers"], confidence=100)
            ])
        elif "react" in url_lower or "vercel" in url_lower:
            techs.extend([
                DetectedTechnology(name="React", categories=["JavaScript frameworks"], confidence=100),
                DetectedTechnology(name="Next.js", categories=["Web frameworks"], confidence=100),
                DetectedTechnology(name="Vercel", categories=["PaaS"], confidence=100)
            ])
        else:
            # Generate deterministic mix of popular technologies
            web_servers = [("Nginx", "1.21.0"), ("Apache", "2.4.41"), ("LiteSpeed", None)]
            js_libs = [("jQuery", "3.6.0"), ("Lodash", "4.17.21"), ("React", "18.2.0")]
            analytics = [("Google Analytics", None), ("Mixpanel", None), ("Hotjar", None)]
            cms = [("Drupal", "9.2"), ("Joomla", "4.0"), ("Shopify", None), (None, None)]
            
            server_name, server_ver = rng.choice(web_servers)
            js_name, js_ver = rng.choice(js_libs)
            anal_name = rng.choice(analytics)[0]
            cms_name, cms_ver = rng.choice(cms)
            
            if server_name:
                techs.append(DetectedTechnology(name=server_name, version=server_ver, categories=["Web servers"], confidence=100))
            if js_name:
                techs.append(DetectedTechnology(name=js_name, version=js_ver, categories=["JavaScript libraries"], confidence=100))
            if anal_name:
                techs.append(DetectedTechnology(name=anal_name, categories=["Analytics"], confidence=95))
            if cms_name:
                techs.append(DetectedTechnology(name=cms_name, version=cms_ver, categories=["CMS"], confidence=100))
                
        return TechFingerprintResult(
            technologies=techs,
            headers_analyzed=rng.randint(8, 20),
            scripts_analyzed=rng.randint(3, 12)
        )

    async def fingerprint_url(self, url: str) -> TechFingerprintResult:
        """Detect web technologies used by the page at ``url``."""
        if self._use_mock:
            return self._generate_mock(url)
            
        if not _WAPPALYZER:
            return TechFingerprintResult()

        client = await self._get_client()
        try:
            response = await client.get(url)
            html = response.text
            
            # Check for bot-block / challenge pages
            is_short = len(html) < 20000
            lower_html = html.lower()
            is_challenge = is_short and any(marker in lower_html for marker in ["just a moment", "attention required", "cloudflare"])
            if is_challenge:
                logger.warning("Response from %s appears to be a Cloudflare/bot challenge page. Skipping tech fingerprinting.", url)
                return TechFingerprintResult()
            
            # Prepare headers for Wappalyzer
            headers = {k: v for k, v in response.headers.items()}
            
            # Create WebPage object and analyze
            page = WebPage(url=url, html=html, headers=headers)
            analysis = _WAPPALYZER.analyze_with_versions_and_categories(page)
            
            # Convert analysis to DetectedTechnology objects
            detected = []
            for tech_name, tech_data in analysis.items():
                version = tech_data['versions'][0] if tech_data.get('versions') else None
                detected.append(DetectedTechnology(
                    name=tech_name,
                    version=version,
                    categories=tech_data.get('categories', []),
                    confidence=100
                ))
            
            scripts_count = len(re.findall(r'<script', html, re.IGNORECASE))
            
            return TechFingerprintResult(
                technologies=detected,
                headers_analyzed=len(headers),
                scripts_analyzed=scripts_count
            )
        except httpx.HTTPError as e:
            logger.warning("Tech fingerprinting failed for %s: %s", url, e)
            return TechFingerprintResult()
