"""
ThreatFusion – Provider-evidence scorer (the rule-based baseline)
==================================================================

Produces a deterministic score in [0.0, 1.0] as a **weighted linear combination** of the provider-derived features
(VirusTotal, Shodan InternetDB, NVD, technology fingerprint, TLS, registration age), with weights written down from
cybersecurity domain knowledge *before* any data was looked at.  It is shown as "Provider evidence" next to the URL model:
the two answer different questions (what do the providers know? / does the URL text look like phishing?).

The score is the clamped sum of the terms returned by :func:`baseline_terms`, so every point of it can be named — the UI shows
the largest ones as the reasons when provider evidence drives a verdict.  A feature that is ``None`` (its provider did not answer)
contributes no term: an unanswered provider is neither evidence of risk nor of safety.
"""

from __future__ import annotations

from app.models.schemas import FeatureVector

Term = tuple[str, float]


def baseline_terms(features: FeatureVector) -> list[Term]:
    """The non-zero contributions to the score as ``(plain-English reason, points)``, in the order they are added."""
    f = features
    terms: list[Term] = []

    def add(text: str, points: float) -> None:
        if points:
            terms.append((text, points))

    # ── VirusTotal (max ~0.90) ──────────────────────────────────────
    # A malicious verdict from AV engines is a definitive indicator of compromise; a high detection ratio must push the
    # risk into High/Critical on its own.
    if f.vt_malicious_ratio is not None:
        add(f"{f.vt_malicious_ratio:.0%} of antivirus engines flag it as malicious", f.vt_malicious_ratio * 0.85)
    # Suspicious flags indicate potential novel threats or PUAs, warranting a moderate bump.
    if f.vt_suspicious_ratio is not None:
        add(f"{f.vt_suspicious_ratio:.0%} of antivirus engines flag it as suspicious", f.vt_suspicious_ratio * 0.20)
    # Poor community reputation adds risk. Reputation is [0, 1] where 1.0 is +100 (good): invert it.
    if f.vt_reputation_score is not None:
        add(f"VirusTotal community reputation {round(f.vt_reputation_score * 200 - 100):+d}", (1.0 - f.vt_reputation_score) * 0.10)

    # ── Shodan InternetDB / NVD (max ~0.60) ─────────────────────────
    # Critical CVSS vulnerabilities expose the system to immediate, known exploitation.
    if f.shodan_max_cvss_score is not None:
        add(f"highest CVSS score on the host is {f.shodan_max_cvss_score:.1f}", (f.shodan_max_cvss_score / 10.0) * 0.35)
    # High-risk ports (Telnet, SMB, RDP) correlate with ransomware and brute force.
    if f.shodan_has_high_risk_port:
        add("a high-risk port is open (SSH, Telnet, RDP, SMB…)", f.shodan_has_high_risk_port * 0.15)
    # Many open ports widen the attack surface but are not inherently malicious (cap at 10).
    if f.shodan_open_port_count is not None:
        add(f"{f.shodan_open_port_count:.0f} open ports", min(f.shodan_open_port_count / 10.0, 1.0) * 0.05)
    # The raw count of CVEs indicates a poor patching cadence.
    if f.shodan_cve_count is not None:
        add(f"{f.shodan_cve_count:.0f} known CVEs on the host", min(f.shodan_cve_count / 10.0, 1.0) * 0.05)

    # ── Technology fingerprint (max ~0.17) ──────────────────────────
    # Outdated or end-of-life components are a common initial access vector for automated scanners.
    if f.tech_has_known_eol_component:
        add("software past its end-of-life date", f.tech_has_known_eol_component * 0.15)
    # A bloated stack increases the surface area for logic flaws.
    if f.tech_count is not None:
        add(f"{f.tech_count:.0f} technologies detected", min(f.tech_count / 20.0, 1.0) * 0.02)

    # ── Supplementary (can reduce risk) ─────────────────────────────
    # A valid certificate and an aged domain indicate legitimate infrastructure: a minor reduction for otherwise clean
    # targets.  None (unknown) earns no bonus.
    if f.ssl_cert_valid == 1.0:
        add("valid TLS certificate", -0.05)
    # Newly registered domains (< 30 days old) add risk: 0 days old = full weight, >= 30 days = none.
    if f.domain_age_days is not None and f.domain_age_days < 30.0:
        add(f"registered {f.domain_age_days:.0f} days ago", (1.0 - (f.domain_age_days / 30.0)) * 0.05)

    return terms


def baseline_score(features: FeatureVector) -> float:
    """The provider-evidence score in [0.0, 1.0]: the clamped sum of :func:`baseline_terms` (0 = nothing found, 1 = critical)."""
    score = 0.0
    for _, points in baseline_terms(features):      # a plain loop, not sum(): Python 3.12's sum() compensates float error, which would
        score += points                              # move the last digit of scores that were computed this way before the refactor
    return max(0.0, min(1.0, score))
