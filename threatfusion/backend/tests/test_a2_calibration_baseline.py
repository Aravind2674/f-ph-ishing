"""A2-1 / B7 — calibration maps and the a-priori lexical baseline."""

from __future__ import annotations

import numpy as np
import pytest

from app.ml.calibration import PiecewiseCalibrator, PlattCalibrator, calibrator_from_dict, prior_shift
from app.ml.url_baseline import RULES, GRADED, url_baseline_score, url_baseline_terms
from app.ml.url_features import FEATURE_NAMES, extract_url_features
from ml import metrics as m


def _overconfident(n=20000, seed=0):
    """Scores that rank well but are badly calibrated: the true P(phish | score) = score**3."""
    rng = np.random.default_rng(seed)
    s = rng.random(n)
    y = (rng.random(n) < s ** 3).astype(int)
    return s, y


@pytest.mark.parametrize("cls", [PiecewiseCalibrator, PlattCalibrator])
def test_calibration_reduces_ece_and_keeps_the_ranking(cls) -> None:
    s_val, y_val = _overconfident(seed=1)
    s_test, y_test = _overconfident(seed=2)
    cal = cls.fit(s_val, y_val)
    out = cal(s_test)
    assert m.ece(y_test, out) < m.ece(y_test, s_test) * 0.5 and m.brier(y_test, out) < m.brier(y_test, s_test)
    assert abs(m.roc_auc(y_test, out) - m.roc_auc(y_test, s_test)) < 0.01, "a monotone map must not change the ranking"
    assert np.all(np.diff(cal(np.linspace(0, 1, 200))) >= -1e-9), "monotone"


@pytest.mark.parametrize("cls", [PiecewiseCalibrator, PlattCalibrator])
def test_calibrators_round_trip_through_json_and_stay_in_unit_interval(cls) -> None:
    s, y = _overconfident()
    cal = cls.fit(s, y)
    back = calibrator_from_dict(cal.to_dict())
    grid = np.linspace(-0.2, 1.2, 50)
    np.testing.assert_allclose(cal(grid), back(grid))
    assert back(grid).min() >= 0.0 and back(grid).max() <= 1.0


def test_unknown_calibrator_kinds_are_refused() -> None:
    with pytest.raises(ValueError):
        calibrator_from_dict({"kind": "magic"})


def test_prior_shift_matches_bayes() -> None:
    p = np.array([0.5, 0.9, 0.1])
    assert np.allclose(prior_shift(p, 0.45, 0.45), p)
    shifted = prior_shift(0.9, 0.45, 0.001)
    assert 0.010 < shifted < 0.012, "a 0.9 score at 45 % prevalence is a ~1.1 % probability at 0.1 % prevalence"
    assert float(shifted) == pytest.approx(0.9 / 0.1 * (0.001 / 0.999) / (0.45 / 0.55) / (1 + 0.9 / 0.1 * (0.001 / 0.999) / (0.45 / 0.55)), rel=1e-6)


# ── the baseline ────────────────────────────────────────────────────────────
def test_the_baseline_ranks_obvious_phishing_above_obvious_benign() -> None:
    phish = [url_baseline_score(extract_url_features(u)) for u in [
        "http://203.0.113.9/login/verify/account", "https://paypal.com@evil.example/signin", "https://paypa1-secure-login.top/verify",
        "https://secure-login-update.account-verify.xyz/confirm"]]
    good = [url_baseline_score(extract_url_features(u)) for u in [
        "https://www.paypal.com/us/home", "https://en.wikipedia.org/wiki/Cat", "https://github.com/python/cpython"]]
    assert min(phish) > max(good), (phish, good)


def test_every_term_is_explained_and_the_score_is_their_clipped_sum() -> None:
    f = extract_url_features("https://a.b.c.paypa1-secure-login.top/verify/account/login?x=1")
    terms = url_baseline_terms(f)
    assert terms and all(isinstance(t, str) and len(t) > 5 for t, _ in terms)
    assert url_baseline_score(f) == pytest.approx(min(1.0, max(0.0, sum(w for _, w in terms))))
    assert 0.0 <= url_baseline_score({}) <= 1.0


def test_an_official_brand_domain_is_credited() -> None:
    assert url_baseline_score(extract_url_features("https://netbanking.hdfcbank.com/login")) < 0.1


def test_the_rules_only_use_real_features_and_cannot_use_label_sources() -> None:
    used = {r[0] for r in RULES} | {g[0] for g in GRADED}
    assert used <= set(FEATURE_NAMES), used - set(FEATURE_NAMES)
    assert not [u for u in used if any(b in u for b in ("rank", "listed", "https", "scheme"))]
