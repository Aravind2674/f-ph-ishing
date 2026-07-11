"""
ThreatFusion – Feature Engineering
===================================

Transforms the heterogeneous, nested outputs of four data sources into a
single flat ``FeatureVector`` of 13 numeric features that can be consumed
by both the deterministic baseline scorer and the trained ML model.

Design principles
-----------------
1. **Every feature has a clear security rationale.**  No feature is
   included "just because the data is available" – each one maps to a
   well‑understood risk signal.
2. **Graceful degradation.**  If a data source failed (i.e. its result
   object is ``None``), the corresponding features default to *neutral*
   values (typically 0.0) so the rest of the pipeline still works.
3. **Deterministic and side‑effect‑free.**  Given the same inputs, the
   same ``FeatureVector`` is always produced – important for
   reproducibility in the viva.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Set

from app.models.schemas import (
    CVEResult,
    FeatureVector,
    ShodanResult,
    TechFingerprintResult,
    VirusTotalResult,
)

# Common ports often targeted by automated scanners and ransomware
HIGH_RISK_PORTS: Set[int] = {
    21,    # FTP
    22,    # SSH (if password auth is allowed)
    23,    # Telnet (plaintext, extremely high risk)
    135,   # RPC
    139,   # NetBIOS
    445,   # SMB (WannaCry, etc.)
    1433,  # MSSQL
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    9200,  # Elasticsearch
}

# A simplified set of End-of-Life technology indicators for demonstration
# In a real system, this would be backed by a CVE/EOL database.
EOL_SET: Set[str] = {
    "jQuery 1",
    "jQuery 2",
    "Python 2",
    "PHP 5",
    "AngularJS",
    "React 15",
}


def is_eol(name: str, version: Optional[str]) -> bool:
    """Check if a technology and version is known to be end-of-life."""
    if not version:
        return False
    # Simplified check: just look at the major version number
    major_version = version.split('.')[0]
    tech_str = f"{name} {major_version}"
    return tech_str in EOL_SET


def extract_features(
    vt: Optional[VirusTotalResult],
    shodan: Optional[ShodanResult],
    cve: Optional[CVEResult],
    tech: Optional[TechFingerprintResult],
) -> FeatureVector:
    """Derive a ``FeatureVector`` from the raw results of all data sources.

    Parameters
    ----------
    vt : VirusTotalResult | None
        Normalised VirusTotal analysis.  ``None`` if the VT lookup failed.
    shodan : ShodanResult | None
        Normalised Shodan / InternetDB data.  ``None`` if the lookup failed.
    cve : CVEResult | None
        Aggregated CVE details.  ``None`` if the NVD lookup failed.
    tech : TechFingerprintResult | None
        Technology fingerprinting results.  ``None`` if fingerprinting failed.

    Returns
    -------
    FeatureVector
        A 13‑dimensional numeric vector ready for scoring / inference.
    """
    # Start with a neutral baseline vector (all 0.0 except where noted)
    vec = FeatureVector()

    # ── VirusTotal ──────────────────────────────────────────────────
    if vt:
        # Avoid division by zero
        total = max(vt.total_engines, 1)
        vec.vt_malicious_ratio = vt.malicious_count / total
        vec.vt_suspicious_ratio = vt.suspicious_count / total
        
        # VT reputation ranges from -100 to +100.
        # We normalize this to [0.0, 1.0] where 1.0 is maximum positive reputation
        # (meaning 0.0 represents -100, which is maximum bad reputation).
        vec.vt_reputation_score = max(0.0, min(1.0, (vt.reputation_score + 100.0) / 200.0))
        
        if vt.last_analysis_date:
            now = datetime.now(timezone.utc)
            delta = now - vt.last_analysis_date
            # Ensure we don't get negative days if clock is skewed
            vec.vt_last_seen_days_ago = max(0.0, delta.total_seconds() / 86400.0)

    # ── Shodan ──────────────────────────────────────────────────────
    if shodan:
        vec.shodan_open_port_count = float(len(shodan.open_ports))
        
        has_high_risk = any(port in HIGH_RISK_PORTS for port in shodan.open_ports)
        vec.shodan_has_high_risk_port = 1.0 if has_high_risk else 0.0
        
        vec.shodan_cve_count = float(len(shodan.vulns))
        
        tags_lower = [t.lower() for t in shodan.tags]
        vec.shodan_has_iot_tag = 1.0 if "iot" in tags_lower else 0.0
        vec.shodan_has_compromised_tag = 1.0 if "compromised" in tags_lower or "malware" in tags_lower else 0.0
        
        if shodan.banner_data:
            products = {b.get("product") for b in shodan.banner_data if b.get("product")}
            vec.shodan_service_diversity_score = float(len(products))
        else:
            vec.shodan_service_diversity_score = float(len(shodan.cpes))
            
        high_risk_cpe_count = sum(1 for cpe in shodan.cpes if any(x in cpe.lower() for x in ["apache", "php", "iis", "nginx", "mysql", "proftpd"]))
        vec.shodan_high_risk_cpe_count = float(high_risk_cpe_count)
        
    if cve:
        # We rely on the CVEResult object for the max score, 
        # as it already calculated it from the NVD data.
        vec.shodan_max_cvss_score = cve.max_cvss_score

    # ── Tech fingerprint ────────────────────────────────────────────
    if tech and tech.technologies:
        vec.tech_count = float(len(tech.technologies))
        
        has_eol = any(is_eol(t.name, t.version) for t in tech.technologies)
        vec.tech_has_known_eol_component = 1.0 if has_eol else 0.0
        
        # Average confidence scaled to [0, 1]
        avg_conf = sum(t.confidence for t in tech.technologies) / len(tech.technologies)
        vec.tech_avg_confidence = avg_conf / 100.0
        
        categories = set()
        has_eol_cms = False
        for t in tech.technologies:
            categories.update(t.categories)
            if "CMS" in t.categories and is_eol(t.name, t.version):
                has_eol_cms = True
                
        vec.tech_stack_diversity_count = float(len(categories))
        vec.tech_has_eol_cms_version = 1.0 if has_eol_cms else 0.0

    # ── Supplementary ───────────────────────────────────────────────
    # These are placeholders that would be hydrated by additional micro-services
    # (e.g. WHOIS lookup, SSL certificate verification) in a production setting.
    # For this project scope, we provide static neutral defaults.
    vec.ssl_cert_valid = 1.0
    vec.domain_age_days = 365.0  # Assumes domain is 1 year old (moderate trust)

    return vec
