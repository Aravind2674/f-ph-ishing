"""B11 (logic) — the exploit-informed *exposure* score, kept apart from "maliciousness".

CVSS measures severity, not likelihood.  EPSS predicts exploitation probability, CISA KEV confirms exploitation in the
wild, and CISA Vulnrichment publishes SSVC decision points (Exploitation, Automatable, Technical Impact).  This module
turns those into (a) an SSVC-style category per CVE — Track < Track* < Attend < Act — and (b) a per-host exposure
score = the probability that *at least one* of the host's listed vulnerabilities gets exploited (noisy-OR), shown with
its evidence.  It is a transparent score, deliberately never blended into the maliciousness model's number.

Acceptance (master prompt B11): *a KEV-listed CVE vs a high-CVSS CVE with low EPSS rank correctly.*
"""

from __future__ import annotations

import pytest

from app.ml.exposure import assess_exposure, cve_probability, ssvc_category
from app.models.schemas import EpssRow, KevRow, SsvcRow

ORDER = ["Track", "Track*", "Attend", "Act"]


def rank(category: str | None) -> int:
    return -1 if category is None else ORDER.index(category)


# ── SSVC-style category ─────────────────────────────────────────────────────
@pytest.mark.parametrize("kwargs,expected", [
    # KEV = observed exploitation; ransomware use is the strongest signal we have
    (dict(in_kev=True, ransomware=True), "Act"),
    (dict(in_kev=True), "Attend"),
    (dict(in_kev=True, automatable="yes"), "Act"),
    (dict(in_kev=True, technical_impact="total"), "Act"),
    # exploitation straight from Vulnrichment
    (dict(exploitation="active", automatable="yes", technical_impact="partial"), "Act"),
    (dict(exploitation="active", automatable="no", technical_impact="total"), "Act"),
    (dict(exploitation="active", automatable="no", technical_impact="partial"), "Attend"),
    (dict(exploitation="active"), "Attend"),
    (dict(exploitation="poc", automatable="yes", technical_impact="total"), "Attend"),
    (dict(exploitation="poc", automatable="no", technical_impact="total"), "Track*"),
    (dict(exploitation="poc"), "Track*"),
    (dict(exploitation="none", automatable="no", technical_impact="partial"), "Track"),
    (dict(exploitation="none", automatable="yes", technical_impact="total"), "Track*"),
    # no exploitation evidence, but EPSS says it is very likely to be exploited
    (dict(exploitation="none", epss_percentile=0.97), "Track*"),
    (dict(epss_percentile=0.97), "Track*"),
    (dict(epss_percentile=0.40), "Track"),
    (dict(exploitation="none", epss_percentile=0.40), "Track"),
])
def test_ssvc_style_category(kwargs, expected) -> None:
    category, basis = ssvc_category(**kwargs)
    assert category == expected and basis, "every category says what it was based on"


def test_nothing_known_is_not_assessable_rather_than_track() -> None:
    assert ssvc_category() == (None, [])
    assert ssvc_category(in_kev=False) == (None, []), "'not in KEV' is not evidence that nothing is exploited"


def test_categories_are_ordered_and_kev_never_lowers_one() -> None:
    low, _ = ssvc_category(exploitation="none", automatable="no", technical_impact="partial")
    with_kev, _ = ssvc_category(exploitation="none", automatable="no", technical_impact="partial", in_kev=True)
    assert rank(with_kev) > rank(low)
    assert [rank(c) for c in ORDER] == [0, 1, 2, 3]


# ── per-CVE exploitation probability ────────────────────────────────────────
def test_probability_prefers_observed_exploitation_over_prediction() -> None:
    assert cve_probability(epss=0.02, in_kev=True, ransomware=False) == pytest.approx(0.95)
    assert cve_probability(epss=0.02, in_kev=True, ransomware=True) == pytest.approx(0.99)
    assert cve_probability(epss=0.37, in_kev=False, ransomware=None) == pytest.approx(0.37)
    assert cve_probability(epss=0.0004, in_kev=None, ransomware=None) == pytest.approx(0.0004)
    assert cve_probability(epss=None, in_kev=False, ransomware=None) is None, "unknown, never 0.0"
    assert cve_probability(epss=None, in_kev=None, ransomware=None) is None


# ── host exposure ───────────────────────────────────────────────────────────
KEV_CVE = "CVE-2021-44228"           # Log4Shell: in KEV, high EPSS (CVSS 10.0 in reality; here 7.5 on purpose)
HIGH_CVSS_LOW_EPSS = "CVE-2020-9999"  # 9.8 CVSS, almost never exploited

EPSS = {KEV_CVE: EpssRow(epss=0.94, percentile=0.999, date="2026-10-03"),
        HIGH_CVSS_LOW_EPSS: EpssRow(epss=0.0004, percentile=0.08, date="2026-10-03")}
KEV = {KEV_CVE: KevRow(date_added="2021-12-10", due_date="2021-12-24", ransomware=True, vendor="Apache", product="Log4j2")}


def test_a_kev_listed_cve_outranks_a_higher_cvss_one_that_is_never_exploited() -> None:
    kev_host = assess_exposure([KEV_CVE], cvss={KEV_CVE: 7.5}, epss=EPSS, kev=KEV, ssvc={})
    cvss_host = assess_exposure([HIGH_CVSS_LOW_EPSS], cvss={HIGH_CVSS_LOW_EPSS: 9.8}, epss=EPSS, kev=KEV, ssvc={})
    assert kev_host.score > cvss_host.score
    assert kev_host.score == pytest.approx(99, abs=1) and cvss_host.score == pytest.approx(0, abs=1)
    assert rank(kev_host.category) > rank(cvss_host.category)
    assert kev_host.category == "Act" and cvss_host.category == "Track"


def test_the_score_is_the_probability_that_at_least_one_cve_is_exploited() -> None:
    cves = ["CVE-2021-0001", "CVE-2021-0002"]
    epss = {c: EpssRow(epss=0.5, percentile=0.9, date="2026-10-03") for c in cves}
    a = assess_exposure(cves, cvss={}, epss=epss, kev={}, ssvc={})
    assert a.score == pytest.approx(75.0) and a.cves_assessed == 2 and a.complete is True


def test_severity_is_shown_beside_exposure_but_not_folded_into_it() -> None:
    cve = "CVE-2021-0003"
    epss = {cve: EpssRow(epss=0.1, percentile=0.5, date="2026-10-03")}
    low = assess_exposure([cve], cvss={cve: 2.0}, epss=epss, kev={}, ssvc={})
    high = assess_exposure([cve], cvss={cve: 10.0}, epss=epss, kev={}, ssvc={})
    assert low.score == high.score == pytest.approx(10.0)
    assert low.cves[0].cvss == 2.0 and high.cves[0].cvss == 10.0


def test_unknown_cves_reduce_coverage_instead_of_counting_as_zero() -> None:
    cves = [KEV_CVE, "CVE-2022-1111", "CVE-2022-2222"]
    a = assess_exposure(cves, cvss={}, epss=EPSS, kev=KEV, ssvc={})
    assert a.cves_total == 3 and a.cves_assessed == 1 and a.complete is False
    assert a.score == pytest.approx(99, abs=1), "the unknown ones are not assumed harmless OR assumed dangerous"
    unknown = [c for c in a.cves if c.cve_id != KEV_CVE]
    assert all(c.probability is None and c.category is None for c in unknown)
    assert any("2 of 3" in n or "1 of 3" in n for n in a.notes), a.notes


def test_a_failed_lookup_is_not_the_same_as_an_empty_one() -> None:
    cves = [KEV_CVE]
    answered_none = assess_exposure(cves, cvss={}, epss={}, kev={}, ssvc={})          # both sources answered: no rows
    failed = assess_exposure(cves, cvss={}, epss=None, kev=None, ssvc=None)           # both sources failed
    assert answered_none.cves[0].in_kev is False and answered_none.cves[0].epss is None
    assert failed.cves[0].in_kev is None and failed.cves[0].epss is None
    assert failed.score is None and failed.cves_assessed == 0
    assert answered_none.score is None, "answered, but with no signal for this CVE: still not 0"


def test_no_listed_cves_is_a_genuine_zero_only_when_the_host_source_answered() -> None:
    clean = assess_exposure([], cvss={}, epss={}, kev={}, ssvc={}, cves_listed_by_host=True)
    assert clean.score == 0.0 and clean.cves_total == 0 and clean.complete is True and clean.category is None
    unknown = assess_exposure([], cvss={}, epss={}, kev={}, ssvc={}, cves_listed_by_host=False)
    assert unknown.score is None, "InternetDB did not answer: we do not know the host has no CVEs"


def test_ssvc_decision_points_come_from_vulnrichment_when_available() -> None:
    cve = "CVE-2023-1234"
    ssvc = {cve: SsvcRow(exploitation="poc", automatable="yes", technical_impact="total")}
    a = assess_exposure([cve], cvss={cve: 9.0}, epss={cve: EpssRow(epss=0.2, percentile=0.8, date="2026-10-03")}, kev={}, ssvc=ssvc)
    c = a.cves[0]
    assert (c.ssvc_exploitation, c.ssvc_automatable, c.ssvc_technical_impact) == ("poc", "yes", "total")
    assert c.category == "Attend" and a.category == "Attend"
    assert any("Vulnrichment" in b for b in c.basis)


def test_the_host_category_is_the_worst_cve_and_cves_are_listed_worst_first() -> None:
    cves = ["CVE-2021-0001", KEV_CVE, "CVE-2021-0002"]
    epss = {**EPSS, "CVE-2021-0001": EpssRow(epss=0.01, percentile=0.3, date="2026-10-03"),
            "CVE-2021-0002": EpssRow(epss=0.2, percentile=0.97, date="2026-10-03")}
    a = assess_exposure(cves, cvss={}, epss=epss, kev=KEV, ssvc={})
    assert a.category == "Act" and a.kev_count == 1
    assert a.cves[0].cve_id == KEV_CVE, "worst first"
    assert a.max_epss == pytest.approx(0.94)


def test_the_method_is_stated_so_nobody_mistakes_it_for_cisas_official_decision() -> None:
    a = assess_exposure([KEV_CVE], cvss={}, epss=EPSS, kev=KEV, ssvc={})
    assert "SSVC-style" in a.method and "not CISA" in a.method
