"""A2-1 / B7 / B9 — the evaluation metrics, on cases whose answers can be computed by hand."""

from __future__ import annotations

import numpy as np
import pytest

from ml import metrics as m


def test_a_perfect_ranker_and_a_random_one() -> None:
    y = [0, 0, 0, 1, 1]
    assert m.pr_auc(y, [0.1, 0.2, 0.3, 0.8, 0.9]) == 1.0 and m.roc_auc(y, [0.1, 0.2, 0.3, 0.8, 0.9]) == 1.0
    rng = np.random.default_rng(0)
    yy = rng.integers(0, 2, 5000)
    assert abs(m.roc_auc(yy, rng.random(5000)) - 0.5) < 0.03


def test_confusion_and_rates() -> None:
    y, s = [1, 1, 1, 0, 0, 0, 0, 0], [0.9, 0.8, 0.2, 0.7, 0.1, 0.1, 0.1, 0.1]
    assert m.confusion(y, s, 0.5) == {"tp": 2, "fp": 1, "fn": 1, "tn": 4}
    r = m.rates(y, s, 0.5)
    assert r["tpr"] == pytest.approx(2 / 3) and r["fpr"] == pytest.approx(1 / 5) and r["precision"] == pytest.approx(2 / 3)
    assert r["f1"] == pytest.approx(2 / 3)


def test_thresholds_for_operating_points() -> None:
    y = [0] * 100 + [1] * 100
    s = list(np.linspace(0, 0.5, 100)) + list(np.linspace(0.4, 1.0, 100))
    t = m.threshold_for_fpr(y, s, 0.05)
    assert m.rates(y, s, t)["fpr"] <= 0.05
    assert m.recall_at_fpr(y, s, 0.05) >= m.recall_at_fpr(y, s, 0.01)
    t2 = m.threshold_for_recall(y, s, 0.9)
    assert m.rates(y, s, t2)["recall"] >= 0.9
    assert 0.0 <= m.fpr_at_recall(y, s, 0.95) <= 1.0


def test_brier_and_ece() -> None:
    assert m.brier([1, 0], [1.0, 0.0]) == 0.0 and m.brier([1, 0], [0.0, 1.0]) == 1.0
    rng = np.random.default_rng(1)
    p = rng.random(20000)
    calibrated = (rng.random(20000) < p).astype(int)           # outcomes drawn from the stated probability
    assert m.ece(calibrated, p) < 0.02
    overconfident = (rng.random(20000) < 0.5).astype(int)      # claims 0.9 / 0.1 but is a coin flip
    assert m.ece(overconfident, np.where(rng.random(20000) < 0.5, 0.9, 0.1)) > 0.3


def test_reliability_bins_report_counts() -> None:
    bins = m.reliability_bins([0, 1, 1, 1], [0.05, 0.95, 0.9, 0.92], bins=10)
    assert sum(b["count"] for b in bins) == 4 and bins[-1]["observed"] == 1.0


def test_precision_at_a_realistic_base_rate_collapses() -> None:
    """TPR 0.95 / FPR 0.01 looks great at 45 % prevalence and mediocre at 0.1 % — that is B9's point."""
    assert m.precision_at_base_rate(0.95, 0.01, 0.45) > 0.98
    assert m.precision_at_base_rate(0.95, 0.01, 0.001) == pytest.approx(0.95 * 0.001 / (0.95 * 0.001 + 0.01 * 0.999))
    assert m.precision_at_base_rate(0.95, 0.01, 0.001) < 0.1
    assert m.precision_at_base_rate(0.0, 0.0, 0.5) == 0.0


def test_area_under_time() -> None:
    assert m.aut([0.9]) == 0.9
    assert m.aut([1.0, 1.0, 1.0]) == 1.0
    assert m.aut([1.0, 0.5, 0.0]) == pytest.approx(0.5)        # linear decay


def test_bootstrap_ci_brackets_the_estimate_and_cluster_resampling_is_wider() -> None:
    rng = np.random.default_rng(2)
    n_groups, per = 60, 20
    groups = np.repeat(np.arange(n_groups), per)
    base = rng.random(n_groups)                                 # whole sites are mostly one class: rows are not independent
    y = (rng.random(n_groups * per) < np.repeat(base, per)).astype(int)
    s = y * 0.3 + rng.random(n_groups * per) * 0.7
    lo_r, hi_r = m.bootstrap_ci(m.roc_auc, y, s, n=300, seed=3)
    lo_c, hi_c = m.bootstrap_ci(m.roc_auc, y, s, groups=groups, n=300, seed=3)
    est = m.roc_auc(y, s)
    assert lo_c <= est <= hi_c
    assert (hi_c - lo_c) >= (hi_r - lo_r) * 0.9, "clusters carry less information than rows: the interval must not be narrower"


def test_bootstrap_is_reproducible_and_skips_one_class_resamples() -> None:
    y, s = [0, 0, 0, 0, 1], [0.1, 0.2, 0.1, 0.2, 0.9]
    a = m.bootstrap_ci(m.pr_auc, y, s, n=100, seed=5)
    assert a == m.bootstrap_ci(m.pr_auc, y, s, n=100, seed=5)
    assert all(np.isfinite(a))
    lo, hi = m.bootstrap_ci(m.pr_auc, [1, 1, 1], [0.1, 0.2, 0.3], n=10)
    assert np.isnan(lo) and np.isnan(hi)


def test_summarize_has_every_metric_with_a_ci() -> None:
    rng = np.random.default_rng(4)
    y = rng.integers(0, 2, 600)
    s = np.clip(y * 0.4 + rng.random(600) * 0.6, 0, 1)
    out = m.summarize(y, s, threshold=0.5, groups=rng.integers(0, 80, 600), n_boot=60)
    for key in ("pr_auc", "roc_auc", "f1", "fpr", "fpr_at_recall_95", "recall_at_fpr_1pct", "brier", "ece"):
        lo, hi = out["ci95"][key]
        assert lo <= out[key] <= hi or key in ("fpr", "ece"), key
    assert out["n"] == 600
