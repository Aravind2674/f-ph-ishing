"""
Calibrated multi-channel fusion (B7)
====================================

Each independent channel (the URL tree model, the URL CNN, the lexical baseline, …) is first **calibrated** to a probability
(``calibration.py``), then combined.  Two combiners are provided and compared in ``ml/evaluate.py``:

``noisy_or``
    ``1 - Π(1 - p_i)`` over the channels that answered (a 2026 hybrid pipeline, arXiv 2606.21690, argues for this: one
    confident channel can raise the verdict without being averaged away).  Its assumption — independent channels — is *false*
    for our channels (they all read the same URL), so it over-states confidence when channels agree; the evaluation measures
    that rather than assuming it.  A missing channel is simply left out.

``StackedFusion``
    A logistic regression over each channel's **logit** plus a **missingness flag** per channel, fitted on held-out validation
    scores (cross-fitted so no channel is calibrated and stacked on the same rows) with random channel *dropout*, so it learns
    both how much to trust each channel and what to do when one is down.  Every prediction comes with the per-channel
    contribution in log-odds, so the UI can show which channel moved the verdict.

Missing means missing: a ``None`` score is never replaced by a neutral constant; the stacker sees the flag instead.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence

import numpy as np

_EPS = 1e-6


def _logit(p: float) -> float:
    p = min(max(p, _EPS), 1 - _EPS)
    return math.log(p / (1 - p))


def noisy_or(probs: Sequence[Optional[float]]) -> Optional[float]:
    """Probability that at least one answering channel is right about "malicious"; ``None`` if no channel answered."""
    answered = [min(max(float(p), 0.0), 1.0) for p in probs if p is not None]
    if not answered:
        return None
    miss = 1.0
    for p in answered:
        miss *= 1.0 - p
    return 1.0 - miss


@dataclass
class StackedFusion:
    names: list[str] = field(default_factory=list)
    weights: list[float] = field(default_factory=list)          # per channel, on the logit
    missing_weights: list[float] = field(default_factory=list)  # per channel, on the missingness flag
    intercept: float = 0.0

    def contributions(self, scores: Mapping[str, Optional[float]]) -> dict[str, float]:
        """Per-channel log-odds contribution (a missing channel contributes only its learned missingness term)."""
        out = {}
        for name, w, v in zip(self.names, self.weights, self.missing_weights):
            p = scores.get(name)
            out[name] = v if p is None else w * _logit(float(p))
        return out

    def predict(self, scores: Mapping[str, Optional[float]]) -> Optional[float]:
        """The fused probability, or ``None`` when *no* channel answered."""
        if all(scores.get(n) is None for n in self.names):
            return None
        z = self.intercept + sum(self.contributions(scores).values())
        return 1.0 / (1.0 + math.exp(-z))

    def design_matrix(self, scores: np.ndarray) -> np.ndarray:
        """``scores`` has NaN for a missing channel; columns are ``[logit·present…, missing flags…]``."""
        present = ~np.isnan(scores)
        p = np.clip(np.where(present, scores, 0.5), _EPS, 1 - _EPS)
        logits = np.where(present, np.log(p / (1 - p)), 0.0)
        return np.hstack([logits, (~present).astype(np.float64)])

    @classmethod
    def fit(cls, names: Sequence[str], scores: np.ndarray, labels, *, dropout: float = 0.25, copies: int = 3, seed: int = 0,
            C: float = 1.0) -> "StackedFusion":
        """Fit on validation scores (rows x channels, NaN = missing). Random dropout copies teach it to handle outages."""
        from sklearn.linear_model import LogisticRegression

        rng = np.random.default_rng(seed)
        labels = np.asarray(labels, dtype=int)
        parts, ys = [scores], [labels]
        for _ in range(copies):
            drop = rng.random(scores.shape) < dropout
            drop[np.all(drop, axis=1), 0] = False               # never drop every channel of a row
            parts.append(np.where(drop, np.nan, scores))
            ys.append(labels)
        model = cls(names=list(names))
        X = model.design_matrix(np.vstack(parts))
        lr = LogisticRegression(C=C, max_iter=2000).fit(X, np.concatenate(ys))
        k = len(names)
        model.weights = [float(w) for w in lr.coef_[0][:k]]
        model.missing_weights = [float(w) for w in lr.coef_[0][k:]]
        model.intercept = float(lr.intercept_[0])
        return model

    def predict_matrix(self, scores: np.ndarray) -> np.ndarray:
        X = self.design_matrix(scores)
        z = self.intercept + X @ np.array(self.weights + self.missing_weights)
        out = 1.0 / (1.0 + np.exp(-z))
        out[np.all(np.isnan(scores), axis=1)] = np.nan
        return out

    def to_dict(self) -> dict:
        return {"names": self.names, "weights": self.weights, "missing_weights": self.missing_weights, "intercept": self.intercept}

    @classmethod
    def from_dict(cls, d: dict) -> "StackedFusion":
        return cls(names=list(d["names"]), weights=list(d["weights"]), missing_weights=list(d["missing_weights"]),
                   intercept=float(d["intercept"]))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
