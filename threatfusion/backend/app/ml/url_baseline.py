"""
A transparent lexical baseline for URL phishing (A2-1)
======================================================

The research question is *does a learned model beat a rule-based baseline?*  The existing ``baseline.py`` scores **provider**
features (VirusTotal, Shodan…), which a URL-only dataset does not have, so the comparison on URL data needs a baseline of the
same kind: a hand-written score over the same URL features, in the style of the classic "suspicious URL" checklists
(Sahingoz et al. 2019; Mohammad et al. 2014).

**The weights below were fixed before any model was trained and are not fitted to any data.**  Only the *decision threshold*
is chosen on the validation split, exactly as for the learned models, so both are evaluated under the same protocol.  Every
term is individually explainable: ``url_baseline_terms`` returns the contributions, which is also what the UI shows.
"""

from __future__ import annotations

from typing import Mapping

# (feature, weight, condition description). Weights are additive evidence; the total is clipped to [0, 1].
RULES: list[tuple[str, float, str]] = [
    ("host_is_ip", 0.30, "the host is a raw IP address"),
    ("host_has_userinfo", 0.25, "user@host trick hides the real destination"),
    ("host_mixed_script", 0.25, "the host mixes alphabets (homograph)"),
    ("host_is_punycode", 0.10, "internationalised (punycode) host"),
    ("lookalike_flagged", 0.35, "the host imitates a protected brand"),
    ("brand_in_path", 0.20, "a brand name appears in the path of an unrelated host"),
    ("path_has_double_slash", 0.05, "'//' inside the path"),
]
# Graded rules: (feature, step function description, [(threshold, weight)…]) — the largest satisfied threshold counts.
GRADED: list[tuple[str, list[tuple[float, float]], str]] = [
    ("subdomain_depth", [(2, 0.10), (3, 0.20)], "many subdomain levels"),
    ("host_hyphens", [(1, 0.05), (2, 0.15), (3, 0.25)], "hyphens in the host"),
    ("host_digit_ratio", [(0.2, 0.10), (0.4, 0.20)], "digits in the host"),
    ("url_len", [(75, 0.05), (120, 0.15)], "a long URL"),
    ("risk_words_host", [(1, 0.15), (2, 0.25)], "phishing words in the host"),
    ("risk_words_path", [(1, 0.05), (3, 0.15)], "phishing words in the path"),
    ("special_count", [(3, 0.05), (8, 0.15)], "many special characters"),
]
OFFICIAL_CREDIT = -0.50          # the registered domain is one of a protected brand's own domains
UNCOMMON_TLD = 0.10


def url_baseline_terms(features: Mapping[str, float]) -> list[tuple[str, float]]:
    """``[(description, contribution)]`` for every rule that fired."""
    terms: list[tuple[str, float]] = []
    for name, weight, text in RULES:
        if features.get(name, 0.0) > 0:
            terms.append((text, weight))
    for name, steps, text in GRADED:
        value = features.get(name, 0.0)
        hit = [w for t, w in steps if value >= t]
        if hit:
            terms.append((text, max(hit)))
    if features.get("tld_is_common", 1.0) == 0 and features.get("host_is_ip", 0.0) == 0:
        terms.append(("an uncommon top-level domain", UNCOMMON_TLD))
    if features.get("is_official_domain", 0.0) > 0:
        terms.append(("this is a protected brand's own domain", OFFICIAL_CREDIT))
    return terms


def url_baseline_score(features: Mapping[str, float]) -> float:
    """The baseline's phishing score in [0, 1] — a heuristic ranking, *not* a calibrated probability."""
    return float(min(1.0, max(0.0, sum(w for _, w in url_baseline_terms(features)))))
