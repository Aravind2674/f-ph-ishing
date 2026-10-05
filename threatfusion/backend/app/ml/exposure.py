"""
Exploit-informed exposure score (B11)
=====================================

**Why a separate score.**  Two different questions are easy to blur into one unexplained number:

* *Is this target malicious?* — the research question (ML vs baseline), answered by reputation channels and models.
* *How exposed is this host?* — how likely is it that a vulnerability it exposes gets exploited?  CVSS cannot answer
  that: it measures *severity*, not *likelihood*.  A CVSS 9.8 bug nobody exploits matters less today than a 7.5 bug in
  CISA's KEV catalogue that ransomware crews use.

This module answers only the second question, transparently, and never feeds the first one's number.

Inputs (all optional, all three-state — ``None`` = the source failed, ``{}`` = it answered with nothing):

* **EPSS** (FIRST.org) — the probability a CVE is exploited in the next 30 days, and its percentile;
* **KEV** (CISA) — confirmed exploitation in the wild, plus the ``knownRansomwareCampaignUse`` flag;
* **Vulnrichment** (CISA ADP in the CVE record) — SSVC decision points: *Exploitation* (none / poc / active),
  *Automatable* (yes / no), *Technical Impact* (partial / total).

Outputs
-------
* a per-CVE **SSVC-style category**, ``Track < Track* < Attend < Act`` (:func:`ssvc_category`);
* a per-CVE **exploitation probability** (:func:`cve_probability`): KEV ⇒ 0.95 (0.99 with ransomware use) — an
  *observation*, not a prediction — otherwise the EPSS probability; unknown stays ``None``, never 0.0;
* a per-host **exposure score**: the probability that *at least one* listed CVE is exploited, ``1 − Π(1 − pᵢ)`` (noisy-OR),
  shown with every CVE's evidence and with how many CVEs it could actually be computed for.

The category mapping below is **our own transparent rule set over the decision points CISA publishes — it is not CISA's
official decision tree** (which also needs deployment context: mission prevalence and public well-being, that a scanner
cannot know).  :attr:`ExposureAssessment.method` says so on every result.
"""

from __future__ import annotations

from typing import Optional

from app.models.schemas import EpssRow, ExposureAssessment, ExposureCve, KevRow, SsvcRow

CATEGORIES = ("Track", "Track*", "Attend", "Act")
KEV_PROBABILITY = 0.95               # observed exploitation in the wild
KEV_RANSOMWARE_PROBABILITY = 0.99    # ... by a known ransomware campaign
HIGH_EPSS_PERCENTILE = 0.95

METHOD = (
    "SSVC-style category from the decision points CISA publishes (Vulnrichment) plus KEV and EPSS — our own mapping, "
    "not CISA's official decision tree. Exposure = probability that at least one listed CVE is exploited "
    "(noisy-OR of per-CVE probabilities: KEV = 0.95, 0.99 with ransomware use; otherwise EPSS). "
    "CVSS is shown for context, not folded in."
)


def _rank(category: Optional[str]) -> int:
    return -1 if category is None else CATEGORIES.index(category)


def ssvc_category(
    *,
    exploitation: Optional[str] = None,
    automatable: Optional[str] = None,
    technical_impact: Optional[str] = None,
    in_kev: Optional[bool] = None,
    ransomware: Optional[bool] = None,
    epss_percentile: Optional[float] = None,
) -> tuple[Optional[str], list[str]]:
    """``(category, basis)`` — or ``(None, [])`` when nothing is known (not "Track": absence of evidence is not safety).

    KEV *membership* counts as ``Exploitation = active``; KEV *absence* is no evidence at all (the catalogue is
    incomplete by design).
    """
    basis: list[str] = []
    effective = exploitation
    if in_kev:
        effective = "active"
        basis.append("KEV: exploitation observed in the wild (CISA)")
    if ransomware:
        basis.append("KEV: known ransomware campaign use")
    points = [f"{label}={value}" for label, value in
              (("Exploitation", exploitation), ("Automatable", automatable), ("Technical Impact", technical_impact))
              if value is not None]
    if points:
        basis.append("Vulnrichment SSVC: " + ", ".join(points))
    if epss_percentile is not None:
        basis.append(f"EPSS percentile {round(epss_percentile * 100)}%")

    if not (in_kev or points or epss_percentile is not None):
        return None, []
    if ransomware:
        return "Act", basis
    if effective == "active":
        return ("Act" if automatable == "yes" or technical_impact == "total" else "Attend"), basis
    if effective == "poc":
        return ("Attend" if automatable == "yes" and technical_impact == "total" else "Track*"), basis
    if (epss_percentile is not None and epss_percentile >= HIGH_EPSS_PERCENTILE) or (
        automatable == "yes" and technical_impact == "total"
    ):
        return "Track*", basis
    return "Track", basis


def cve_probability(*, epss: Optional[float], in_kev: Optional[bool], ransomware: Optional[bool]) -> Optional[float]:
    """Estimated probability the CVE is exploited: observed (KEV) beats predicted (EPSS); unknown is ``None``."""
    if in_kev:
        return KEV_RANSOMWARE_PROBABILITY if ransomware else KEV_PROBABILITY
    return epss


def assess_exposure(
    cve_ids: list[str],
    *,
    cvss: dict[str, Optional[float]],
    epss: Optional[dict[str, EpssRow]],
    kev: Optional[dict[str, KevRow]],
    ssvc: Optional[dict[str, SsvcRow]],
    cves_listed_by_host: bool = True,
    feed_ages: Optional[dict[str, Optional[float]]] = None,
) -> ExposureAssessment:
    """Per-host exposure from the host's CVE ids.

    ``cves_listed_by_host=False`` means the source that lists a host's CVEs (InternetDB) did not answer: then "no
    CVEs" is *unknown*, not zero.
    """
    feed_ages = feed_ages or {}
    ids = list(dict.fromkeys(c.upper() for c in cve_ids))
    if not ids:
        if cves_listed_by_host:
            return ExposureAssessment(score=0.0, category=None, cves_total=0, cves_assessed=0, complete=True,
                                      notes=["No known vulnerabilities are listed for this host."], method=METHOD,
                                      feed_ages=feed_ages)
        return ExposureAssessment(score=None, category=None, cves_total=0, cves_assessed=0, complete=False,
                                  notes=["The host's vulnerability list is unavailable, so exposure is unknown."],
                                  method=METHOD, feed_ages=feed_ages)

    rows: list[ExposureCve] = []
    for cve in ids:
        e = epss.get(cve) if epss is not None else None
        in_kev = None if kev is None else cve in kev
        k = kev.get(cve) if kev else None
        ransomware = k.ransomware if k is not None else (None if kev is None else False)
        s = ssvc.get(cve) if ssvc else None
        category, basis = ssvc_category(
            exploitation=s.exploitation if s else None,
            automatable=s.automatable if s else None,
            technical_impact=s.technical_impact if s else None,
            in_kev=in_kev, ransomware=ransomware,
            epss_percentile=e.percentile if e else None,
        )
        rows.append(ExposureCve(
            cve_id=cve, cvss=cvss.get(cve),
            epss=e.epss if e else None, epss_percentile=e.percentile if e else None, epss_date=e.date if e else None,
            in_kev=in_kev, kev_ransomware=ransomware if in_kev else None, kev_date_added=k.date_added if k else None,
            ssvc_exploitation=s.exploitation if s else None, ssvc_automatable=s.automatable if s else None,
            ssvc_technical_impact=s.technical_impact if s else None,
            category=category,
            probability=cve_probability(epss=e.epss if e else None, in_kev=in_kev, ransomware=ransomware),
            basis=basis,
        ))

    assessed = [r for r in rows if r.probability is not None]
    score: Optional[float] = None
    if assessed:
        none_exploited = 1.0
        for r in assessed:
            none_exploited *= 1.0 - float(r.probability)
        score = round(100.0 * (1.0 - none_exploited), 2)

    rows.sort(key=lambda r: (_rank(r.category), r.probability if r.probability is not None else -1.0), reverse=True)
    categories = [r.category for r in rows if r.category is not None]
    notes: list[str] = []
    if len(assessed) < len(rows):
        notes.append(f"Exposure is based on {len(assessed)} of {len(rows)} listed CVEs; "
                     f"{len(rows) - len(assessed)} have no EPSS or KEV data, so they are neither counted as safe nor as dangerous.")
    if not assessed:
        notes.append("No exploitation evidence could be obtained for any listed CVE.")
    epss_values = [r.epss for r in rows if r.epss is not None]
    return ExposureAssessment(
        score=score,
        category=max(categories, key=_rank) if categories else None,
        cves_total=len(rows), cves_assessed=len(assessed), complete=len(assessed) == len(rows),
        kev_count=sum(1 for r in rows if r.in_kev), max_epss=max(epss_values) if epss_values else None,
        cves=rows, notes=notes, method=METHOD, feed_ages=feed_ages,
    )
