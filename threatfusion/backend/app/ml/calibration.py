"""
Probability calibration (A2-1, B7)
==================================

A classifier's raw score is a *ranking*, not a probability: "0.9" from a boosted-tree model does not mean nine in ten such URLs
are phishing.  Calibration learns a monotone map from raw score to observed frequency on **held-out validation data** (never the
training data, never the test data).  Two standard maps are supported; both are stored as plain arrays/numbers so the API can
apply them with NumPy alone (scikit-learn is only needed offline, to fit):

* **Isotonic regression** (``PiecewiseCalibrator``) — non-parametric, monotone, piecewise-linear here (the fitted step function is
  interpolated between its knots, which keeps the map continuous).  Best with plenty of validation data.
* **Platt scaling** (``PlattCalibrator``) — a 2-parameter sigmoid on the logit of the raw score; stable with little data.

A calibrator is only valid for the *prevalence* of the data it was fitted on (the share of phishing).  Moving to a population
with a different base rate needs a prior-shift correction — see ``prior_shift`` and B9's base-rate analysis.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Sequence

import numpy as np

_EPS = 1e-6


def _logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, _EPS, 1 - _EPS)
    return np.log(p / (1 - p))


@dataclass
class PiecewiseCalibrator:
    """Monotone piecewise-linear map ``x_knots -> y_knots`` (an isotonic fit); values outside the knots are clamped."""

    x_knots: list[float] = field(default_factory=list)
    y_knots: list[float] = field(default_factory=list)
    kind: str = "isotonic"

    def __call__(self, scores) -> np.ndarray:
        s = np.asarray(scores, dtype=np.float64)
        if not self.x_knots:
            return s
        return np.interp(s, self.x_knots, self.y_knots)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "x_knots": self.x_knots, "y_knots": self.y_knots}

    @classmethod
    def fit(cls, scores, labels) -> "PiecewiseCalibrator":
        from sklearn.isotonic import IsotonicRegression

        iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(np.asarray(scores, float), np.asarray(labels, float))
        xs, ys = iso.X_thresholds_, iso.y_thresholds_
        return cls(x_knots=[float(x) for x in xs], y_knots=[float(y) for y in ys])


@dataclass
class PlattCalibrator:
    """``sigmoid(a * logit(score) + b)``."""

    a: float = 1.0
    b: float = 0.0
    kind: str = "platt"

    def __call__(self, scores) -> np.ndarray:
        z = self.a * _logit(np.asarray(scores, dtype=np.float64)) + self.b
        return 1.0 / (1.0 + np.exp(-z))

    def to_dict(self) -> dict:
        return {"kind": self.kind, "a": self.a, "b": self.b}

    @classmethod
    def fit(cls, scores, labels) -> "PlattCalibrator":
        from sklearn.linear_model import LogisticRegression

        x = _logit(np.asarray(scores, dtype=np.float64)).reshape(-1, 1)
        lr = LogisticRegression(C=1e6, solver="lbfgs", max_iter=1000).fit(x, np.asarray(labels, int))
        return cls(a=float(lr.coef_[0][0]), b=float(lr.intercept_[0]))


def calibrator_from_dict(d: dict):
    kind = d.get("kind")
    if kind == "isotonic":
        return PiecewiseCalibrator(x_knots=list(d["x_knots"]), y_knots=list(d["y_knots"]))
    if kind == "platt":
        return PlattCalibrator(a=float(d["a"]), b=float(d["b"]))
    raise ValueError(f"unknown calibrator kind {kind!r}")


def prior_shift(p: Sequence[float] | np.ndarray, train_prevalence: float, target_prevalence: float) -> np.ndarray:
    """Re-express calibrated probabilities for a population with a different phishing base rate (Saerens et al. 2002).

    ``odds' = odds * (π'/(1-π')) / (π/(1-π))`` — exact when the class-conditional distributions are unchanged."""
    p = np.clip(np.asarray(p, dtype=np.float64), _EPS, 1 - _EPS)
    ratio = (target_prevalence / (1 - target_prevalence)) / (train_prevalence / (1 - train_prevalence))
    odds = p / (1 - p) * ratio
    return odds / (1 + odds)
