"""B7 — calibrated multi-channel fusion: noisy-OR and a stacked logistic regression with missingness flags."""

from __future__ import annotations

import math

import numpy as np
import pytest

from app.ml.fusion import StackedFusion, noisy_or
from ml import metrics as m


def test_noisy_or_properties() -> None:
    assert noisy_or([]) is None and noisy_or([None, None]) is None
    assert noisy_or([0.3]) == pytest.approx(0.3)
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert noisy_or([0.9, 0.0, None]) == pytest.approx(0.9), "a missing channel is left out, not counted as 0 or 0.5"
    assert noisy_or([0.95, 0.1]) > 0.95, "one confident channel is not averaged away"
    assert noisy_or([1.0, 0.2]) == 1.0 and noisy_or([0.0, 0.0]) == 0.0
    assert noisy_or([1.5, -0.2]) == 1.0, "inputs are clipped to [0, 1]"


def _channels(n=6000, seed=0):
    """Two channels of different reliability about the same labels (a good one and a weak one), plus a pure-noise one."""
    rng = np.random.default_rng(seed)
    y = rng.integers(0, 2, n)
    good = np.clip(0.5 + (y - 0.5) * 0.9 + rng.normal(0, 0.25, n), 0.01, 0.99)
    weak = np.clip(0.5 + (y - 0.5) * 0.25 + rng.normal(0, 0.3, n), 0.01, 0.99)
    noise = rng.random(n)
    return y, np.column_stack([good, weak, noise])


def test_the_stacker_trusts_the_reliable_channel_most_and_ignores_noise() -> None:
    y, S = _channels()
    f = StackedFusion.fit(["good", "weak", "noise"], S, y)
    w = dict(zip(f.names, f.weights))
    assert w["good"] > w["weak"] > 0 and abs(w["noise"]) < 0.3 * w["good"]


def test_fusion_beats_each_single_channel_and_survives_an_outage() -> None:
    y, S = _channels(seed=1)
    yt, St = _channels(seed=2)
    f = StackedFusion.fit(["good", "weak", "noise"], S, y)
    fused = f.predict_matrix(St)
    assert m.pr_auc(yt, fused) >= max(m.pr_auc(yt, St[:, 0]), m.pr_auc(yt, St[:, 1])) - 0.005
    outage = St.copy()
    outage[:, 0] = np.nan                                              # the best channel is down
    degraded = f.predict_matrix(outage)
    assert np.isfinite(degraded).all() and m.roc_auc(yt, degraded) > 0.6, "still informative without the best channel"
    assert m.roc_auc(yt, degraded) <= m.roc_auc(yt, fused)


def test_missing_is_never_a_neutral_constant() -> None:
    y, S = _channels()
    f = StackedFusion.fit(["good", "weak", "noise"], S, y)
    only_good = f.predict({"good": 0.9, "weak": None, "noise": None})
    assert only_good is not None and f.predict({"good": None, "weak": None, "noise": None}) is None
    contrib = f.contributions({"good": 0.9, "weak": None, "noise": 0.5})
    assert contrib["weak"] == pytest.approx(f.missing_weights[1]), "a missing channel contributes only its learned missingness term"


def test_contributions_plus_intercept_are_the_logit_of_the_prediction() -> None:
    y, S = _channels()
    f = StackedFusion.fit(["good", "weak", "noise"], S, y)
    scores = {"good": 0.8, "weak": 0.3, "noise": None}
    p = f.predict(scores)
    assert math.log(p / (1 - p)) == pytest.approx(f.intercept + sum(f.contributions(scores).values()))


def test_json_round_trip_and_matrix_agree_with_scalar_prediction() -> None:
    y, S = _channels()
    f = StackedFusion.fit(["good", "weak", "noise"], S, y)
    g = StackedFusion.from_dict(f.to_dict())
    row = {"good": 0.7, "weak": 0.2, "noise": 0.9}
    assert g.predict(row) == pytest.approx(f.predict(row))
    assert f.predict_matrix(np.array([[0.7, 0.2, 0.9]]))[0] == pytest.approx(f.predict(row))


def test_fitting_is_reproducible() -> None:
    y, S = _channels()
    assert StackedFusion.fit(["a", "b", "c"], S, y, seed=3).to_dict() == StackedFusion.fit(["a", "b", "c"], S, y, seed=3).to_dict()
