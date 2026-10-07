"""
The headline verdict: the higher-risk band of two independent channels
======================================================================

A scan has two channels that measure different things:

* **URL model** — does the URL *text* look like phishing? (calibrated tree + character-CNN fusion; ``ml_score`` / ``ml_label``)
* **Provider evidence** — what do VirusTotal, open ports, CVEs, TLS and domain age say? (``baseline_score`` / ``baseline_label``)

The headline is the **higher-risk band of the two**, and ``driven_by`` says which channel produced it.  That is the usual
max-of-evidence rule for detection: a hit from either channel must not be averaged away by a quiet one.  What this module
never does is change a score: both channels keep exactly the value they were computed with, ``agreement`` only reports whether
they are within 15 points of each other, and a disagreement is shown, not smoothed.

Cost, stated: the URL channel flags about 1 % of benign URLs (more on real login pages — see ``ml/results/report.md``), so the
headline will occasionally be High on a harmless site because of its URL text alone.  ``driven_by`` is what lets the UI say so.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

DrivenBy = Literal["url_model", "provider_evidence", "both"]

#: Scores are on 0..1; "agree" means within 15 points of 100.
AGREEMENT_POINTS = 15.0

_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def band_rank(band: Optional[str]) -> int:
    """Low < Medium < High < Critical; ``Unknown`` / ``None`` rank 0 (no opinion — never a low one)."""
    return _RANK.get(band or "", 0)


@dataclass(frozen=True)
class Verdict:
    headline_band: Optional[str]
    driven_by: Optional[DrivenBy]
    agreement: Optional[bool]


def headline_verdict(provider_score: Optional[float], provider_band: Optional[str],
                     url_score: Optional[float], url_band: Optional[str]) -> Verdict:
    """Combine the two channels' *bands* into a headline without touching either score."""
    # rounded first: 0.65 - 0.50 is 15.000000000000002 in floating point, and "15 points apart" must count as agreeing
    agreement = None if provider_score is None or url_score is None else round(abs(url_score - provider_score) * 100.0, 6) <= AGREEMENT_POINTS
    p, u = band_rank(provider_band), band_rank(url_band)
    if p == 0 and u == 0:
        return Verdict(None, None, agreement)
    if u > p:
        return Verdict(url_band, "url_model", agreement)
    if p > u:
        return Verdict(provider_band, "provider_evidence", agreement)
    return Verdict(provider_band, "both", agreement)
