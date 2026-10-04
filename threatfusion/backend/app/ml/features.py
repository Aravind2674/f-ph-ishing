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

from app.ingestion.rdap import domain_age_days
from app.ingestion.tls import tls_cert_valid
from app.models.schemas import (
    CVEResult,
    DnsInfo,
    FeatureCoverage,
    FeatureVector,
    RdapInfo,
    ShodanResult,
    TechFingerprintResult,
    TlsInfo,
    VirusTotalResult,
)

# Version of the feature *semantics* stored with every scan:
#   1 = original floats with neutral constants (ssl=1.0, age=365) standing in for missing data
#   2 = A0-1: unknown is None (XGBoost sees NaN); no fabricated constants
#   3 = A1-3: ssl_cert_valid / domain_age_days are real (TLS probe / RDAP registration date), still None if unknown
FEATURE_SCHEMA_VERSION = 3

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


def extract_features_with_coverage(
    vt: Optional[VirusTotalResult],
    shodan: Optional[ShodanResult],
    cve: Optional[CVEResult],
    tech: Optional[TechFingerprintResult],
    tls: Optional[TlsInfo] = None,
    rdap: Optional[RdapInfo] = None,
    dns: Optional[DnsInfo] = None,
) -> tuple[FeatureVector, FeatureCoverage]:
    """Derive a ``FeatureVector`` *and* which providers contributed to it.

    Each argument is the provider's **data** (``ProviderResult.data``) when that provider
    answered, else ``None``.  Unknown stays unknown (A0-1):

    * a provider that did not answer leaves *its* features ``None`` (XGBoost sees NaN) —
      never ``0.0`` (which reads as "clean") and never ``0.5`` (which reads as "neutral");
    * ``ssl_cert_valid`` comes from the TLS probe (``1.0`` valid, ``0.0`` invalid or no TLS) and
      ``domain_age_days`` from the RDAP/WHOIS registration date (A1-3); each stays ``None`` when its probe did
      not answer or the registry publishes no date.  They used to be the constants 1.0 and 365.0 on every scan —
      fabricated evidence that also shifted every baseline score.

    ``FeatureCoverage`` carries the has_<provider> missingness flags.  They are kept out of
    ``FeatureVector`` on purpose: the deployed XGBoost artifact expects exactly 19 columns.
    """
    vec = FeatureVector(**{name: None for name in FeatureVector.model_fields})
    cov = FeatureCoverage(
        has_virustotal=vt is not None,
        has_shodan=shodan is not None,
        has_cve=cve is not None,
        has_tech=tech is not None,
        has_tls=tls is not None,
        has_rdap=rdap is not None,
        has_dns=dns is not None,
    )

    # ── Host signals (A1-3) ─────────────────────────────────────────
    if tls is not None:
        vec.ssl_cert_valid = tls_cert_valid(tls)
    if rdap is not None:
        vec.domain_age_days = domain_age_days(rdap)      # None if the registry published no registration date

    # ── VirusTotal ──────────────────────────────────────────────────
    if vt is not None:
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
    if shodan is not None:
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

    # ── CVSS (NVD) ──────────────────────────────────────────────────
    if cve is not None:
        # We rely on the CVEResult object for the max score,
        # as it already calculated it from the NVD data.
        vec.shodan_max_cvss_score = cve.max_cvss_score
    elif shodan is not None and not shodan.vulns:
        # Shodan answered and lists no CVEs, so there was nothing to look up: 0.0 is true here.
        # (If Shodan lists CVEs but NVD did not answer, the score stays unknown — it must not
        # silently become 0.0.)
        vec.shodan_max_cvss_score = 0.0

    # ── Tech fingerprint ────────────────────────────────────────────
    if tech is not None:
        vec.tech_count = float(len(tech.technologies))

        has_eol = any(is_eol(t.name, t.version) for t in tech.technologies)
        vec.tech_has_known_eol_component = 1.0 if has_eol else 0.0

        categories = set()
        has_eol_cms = False
        for t in tech.technologies:
            categories.update(t.categories)
            if "CMS" in t.categories and is_eol(t.name, t.version):
                has_eol_cms = True

        vec.tech_stack_diversity_count = float(len(categories))
        vec.tech_has_eol_cms_version = 1.0 if has_eol_cms else 0.0

        if tech.technologies:
            # Average confidence scaled to [0, 1]; undefined (None) when nothing was detected.
            avg_conf = sum(t.confidence for t in tech.technologies) / len(tech.technologies)
            vec.tech_avg_confidence = avg_conf / 100.0

    return vec, cov


def extract_features(
    vt: Optional[VirusTotalResult],
    shodan: Optional[ShodanResult],
    cve: Optional[CVEResult],
    tech: Optional[TechFingerprintResult],
    tls: Optional[TlsInfo] = None,
    rdap: Optional[RdapInfo] = None,
    dns: Optional[DnsInfo] = None,
) -> FeatureVector:
    """Backward-compatible wrapper: the 19-dimensional vector without the coverage flags."""
    return extract_features_with_coverage(vt, shodan, cve, tech, tls, rdap, dns)[0]
