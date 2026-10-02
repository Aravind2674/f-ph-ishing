"""
ThreatFusion – Baseline Rule‑Based Scorer
==========================================

Produces a deterministic threat score in [0.0, 1.0] using a **weighted
linear combination** of the engineered features, with hand‑tuned weights
derived from cybersecurity domain knowledge.

Why do we need a baseline?
--------------------------
1. **Sanity check** – if the ML model's predictions diverge wildly from
   the baseline, something is wrong with the training data or pipeline.
2. **Fallback** – if the trained model file is missing or corrupted, the
   API can still return a meaningful score.
3. **Benchmark** – the viva panel will expect to see how much value the
   ML model adds over a simple heuristic.  The baseline provides that
   comparison point.

The weights are intentionally *not* learned from data – they are expert
priors.  This makes the baseline fully transparent and easy to explain
in the viva.
"""

from __future__ import annotations

from app.models.schemas import FeatureVector


def baseline_score(features: FeatureVector) -> float:
    """Compute a rule‑based risk score from a ``FeatureVector``.

    The score is a **clamped weighted sum** of the individual features,
    where the weights reflect expert judgement about each signal's
    relative importance. Unbounded features (like counts and days) are
    normalised to [0, 1] internally before applying the weight.

    Parameters
    ----------
    features : FeatureVector
        The 13‑dimensional feature vector produced by ``extract_features``.

    Returns
    -------
    float
        Risk score in [0.0, 1.0] where 0 = safe, 1 = critical.
    """
    # Unknown (None) features contribute nothing: an unanswered provider is neither evidence
    # of risk nor evidence of safety (A0-1). Coverage is reported separately by the caller.
    f = features
    n = lambda x: 0.0 if x is None else x  # noqa: E731

    score = 0.0

    # ── VirusTotal (Max theoretical contribution: ~0.90) ─────────────
    # Rationale: A malicious verdict from AV engines is a definitive indicator of compromise.
    # A highly malicious file (e.g. >50% detection ratio) must immediately push the risk into
    # the High/Critical tier, overriding passive factors like SSL validity.
    score += n(f.vt_malicious_ratio) * 0.85
    
    # Rationale: Suspicious flags indicate potential novel threats or PUAs, warranting a moderate bump.
    score += n(f.vt_suspicious_ratio) * 0.20
    
    # Rationale: Poor community reputation provides crowd-sourced context for emerging threats.
    # Reputation is [0.0, 1.0] where 1.0 is +100 (good) and 0.0 is -100 (bad).
    # We want a bad reputation to *add* risk, so we invert it.
    bad_rep_factor = 0.0 if f.vt_reputation_score is None else 1.0 - f.vt_reputation_score
    score += bad_rep_factor * 0.10

    # ── Shodan (Max theoretical contribution: ~0.50) ─────────────────
    # Rationale: Critical CVSS vulnerabilities expose the system to immediate, known exploitation.
    score += (n(f.shodan_max_cvss_score) / 10.0) * 0.35
    
    # Rationale: High-risk ports (Telnet, SMB, RDP) are highly correlated with ransomware and brute force.
    score += n(f.shodan_has_high_risk_port) * 0.15
    
    # Rationale: High number of open ports widens the attack surface but isn't inherently malicious.
    # Port count (cap at 10 ports)
    port_factor = min(n(f.shodan_open_port_count) / 10.0, 1.0)
    score += port_factor * 0.05
    
    # Rationale: Raw count of CVEs indicates poor patching cadence.
    cve_factor = min(n(f.shodan_cve_count) / 10.0, 1.0)
    score += cve_factor * 0.05

    # ── Tech Fingerprint (Max theoretical contribution: ~0.15) ───────
    # Rationale: Outdated or EOL components are common initial access vectors for automated scanners.
    score += n(f.tech_has_known_eol_component) * 0.15
    
    # Rationale: A highly bloated tech stack increases the surface area for logic flaws.
    tech_count_factor = min(n(f.tech_count) / 20.0, 1.0)
    score += tech_count_factor * 0.02
    
    # ── Supplementary (Can reduce risk) ──────────────────────────────
    # Rationale: Valid SSL certificates and aged domains indicate legitimate infrastructure,
    # providing a minor reduction in baseline suspicion for otherwise clean targets.
    if f.ssl_cert_valid == 1.0:  # None (unknown) earns no bonus
        score -= 0.05
        
    # Newly registered domains (< 30 days old) add risk
    # We invert age: 0 days old = max risk, >= 30 days old = 0 risk
    if f.domain_age_days is not None and f.domain_age_days < 30.0:
        age_risk = 1.0 - (f.domain_age_days / 30.0)
        score += age_risk * 0.05

    # Clamp the final result to [0.0, 1.0]
    return max(0.0, min(1.0, score))
