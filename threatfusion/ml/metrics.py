"""
Evaluation metrics for the maliciousness models (A2-1, B7, B9)
==============================================================

Pure NumPy / scikit-learn; every function takes plain arrays so it can be unit-tested on hand-computable cases.

Why these metrics (the master prompt's list, with the reason each one is here)
------------------------------------------------------------------------------
* **PR-AUC** (average precision) — phishing is rare in practice; ROC-AUC flatters a detector when negatives dominate.
* **ROC-AUC** — reported for comparison with the literature, never alone.
* **FPR at a fixed recall** and **recall at a fixed FPR** — what an operator tunes: "catch 95 % of phishing, how many good
  sites do I block?" / "never block more than 1 % of good sites, how much phishing do I catch?".
* **Brier score** and **ECE** — whether the probabilities mean something (calibration), which B7's fusion depends on.
* **Precision at a realistic base rate** (B9) — benchmark datasets are ~45 % phishing; real traffic is far below 1 %.  With
  TPR and FPR measured on the benchmark, precision at prevalence π is ``TPR·π / (TPR·π + FPR·(1-π))``; this is a *derivation
  from measured rates*, not a re-measurement, and is reported as such.
* **AUT** (area under time, TESSERACT, USENIX Sec 2019) — how a metric decays as the test period moves away from training.
* **Bootstrap 95 % CIs** — resampling *registered domains* (clusters), not rows, because URLs of one site are not independent;
  a row bootstrap would give intervals that are too narrow.
"""

from __future__ import annotations

from typing import Callable, Optional, Sequence

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve


def _arr(x) -> np.ndarray:
    return np.asarray(x, dtype=np.float64)


def pr_auc(y, s) -> float:
    return float(average_precision_score(_arr(y), _arr(s)))


def roc_auc(y, s) -> float:
    return float(roc_auc_score(_arr(y), _arr(s)))


def confusion(y, s, threshold: float) -> dict[str, int]:
    y, pred = _arr(y) > 0.5, _arr(s) >= threshold
    return {"tp": int((y & pred).sum()), "fp": int((~y & pred).sum()), "fn": int((y & ~pred).sum()), "tn": int((~y & ~pred).sum())}


def rates(y, s, threshold: float) -> dict[str, float]:
    c = confusion(y, s, threshold)
    pos, neg = c["tp"] + c["fn"], c["fp"] + c["tn"]
    tpr = c["tp"] / pos if pos else 0.0
    fpr = c["fp"] / neg if neg else 0.0
    precision = c["tp"] / (c["tp"] + c["fp"]) if (c["tp"] + c["fp"]) else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) else 0.0
    return {"threshold": float(threshold), "tpr": tpr, "fpr": fpr, "precision": precision, "recall": tpr, "f1": f1}


def threshold_for_fpr(y, s, max_fpr: float = 0.01) -> float:
    """The lowest threshold whose false-positive rate on ``(y, s)`` does not exceed ``max_fpr`` (chosen on VALIDATION data)."""
    fpr, tpr, thr = roc_curve(_arr(y), _arr(s))
    ok = np.where(fpr <= max_fpr)[0]
    return float(thr[ok[-1]]) if len(ok) else float(np.nextafter(np.max(_arr(s)), np.inf))


def threshold_for_recall(y, s, recall: float = 0.95) -> float:
    """The highest threshold that still reaches ``recall``."""
    fpr, tpr, thr = roc_curve(_arr(y), _arr(s))
    ok = np.where(tpr >= recall)[0]
    return float(thr[ok[0]]) if len(ok) else float(np.min(_arr(s)))


def fpr_at_recall(y, s, recall: float = 0.95) -> float:
    fpr, tpr, _ = roc_curve(_arr(y), _arr(s))
    ok = np.where(tpr >= recall)[0]
    return float(fpr[ok[0]]) if len(ok) else 1.0


def recall_at_fpr(y, s, max_fpr: float = 0.01) -> float:
    fpr, tpr, _ = roc_curve(_arr(y), _arr(s))
    ok = np.where(fpr <= max_fpr)[0]
    return float(tpr[ok[-1]]) if len(ok) else 0.0


def brier(y, p) -> float:
    y, p = _arr(y), _arr(p)
    return float(np.mean((p - y) ** 2))


def reliability_bins(y, p, bins: int = 10) -> list[dict[str, float]]:
    """Equal-width bins of predicted probability: mean prediction, observed frequency and count (the reliability diagram)."""
    y, p = _arr(y), _arr(p)
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    out = []
    for b in range(bins):
        m = idx == b
        if m.any():
            out.append({"bin": b, "mean_pred": float(p[m].mean()), "observed": float(y[m].mean()), "count": int(m.sum())})
    return out


def ece(y, p, bins: int = 15) -> float:
    """Expected calibration error: the count-weighted gap between predicted probability and observed frequency."""
    rel = reliability_bins(y, p, bins)
    n = sum(r["count"] for r in rel)
    return float(sum(r["count"] / n * abs(r["mean_pred"] - r["observed"]) for r in rel)) if n else 0.0


def precision_at_base_rate(tpr: float, fpr: float, prevalence: float) -> float:
    """Precision if the same detector (same TPR / FPR) faced traffic with this phishing prevalence."""
    num = tpr * prevalence
    den = num + fpr * (1.0 - prevalence)
    return float(num / den) if den > 0 else 0.0


def aut(values: Sequence[float]) -> float:
    """Area under time (TESSERACT): the mean of the trapezoids of a per-window metric, in [0, 1] for a [0, 1] metric."""
    v = [float(x) for x in values]
    if len(v) == 1:
        return v[0]
    return float(sum((a + b) / 2.0 for a, b in zip(v[:-1], v[1:])) / (len(v) - 1))


def bootstrap_ci(metric: Callable[[np.ndarray, np.ndarray], float], y, s, *, groups: Optional[Sequence] = None, n: int = 500,
                 seed: int = 0, alpha: float = 0.05) -> tuple[float, float]:
    """Percentile CI of ``metric(y, s)``; resamples whole ``groups`` (e.g. registered domains) when given, else rows.

    Resamples that contain a single class are skipped (a ranking metric is undefined on them)."""
    y, s = _arr(y), _arr(s)
    rng = np.random.default_rng(seed)
    if groups is None:
        units = [np.array([i]) for i in range(len(y))] if len(y) <= 2000 else None
        n_units = len(y)
    else:
        g = np.asarray(groups)
        order = np.argsort(g, kind="stable")
        bounds = np.flatnonzero(np.r_[True, g[order][1:] != g[order][:-1], True])
        units = [order[a:b] for a, b in zip(bounds[:-1], bounds[1:])]
        n_units = len(units)
    values: list[float] = []
    for _ in range(n):
        pick = rng.integers(0, n_units, n_units)
        idx = pick if units is None else np.concatenate([units[i] for i in pick])
        yy, ss = y[idx], s[idx]
        if yy.min() == yy.max():
            continue
        values.append(float(metric(yy, ss)))
    if not values:
        return float("nan"), float("nan")
    lo, hi = np.percentile(values, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(lo), float(hi)


def bootstrap_many(metric_fns: dict, y, s, *, groups: Optional[Sequence] = None, n: int = 500, seed: int = 0,
                   alpha: float = 0.05) -> dict[str, tuple[float, float]]:
    """Percentile CIs for several metrics computed on the SAME resamples (one pass; resampling units as in ``bootstrap_ci``)."""
    y, s = _arr(y), _arr(s)
    rng = np.random.default_rng(seed)
    if groups is None:
        units, n_units = None, len(y)
    else:
        g = np.asarray(groups)
        order = np.argsort(g, kind="stable")
        bounds = np.flatnonzero(np.r_[True, g[order][1:] != g[order][:-1], True])
        units = [order[a:b] for a, b in zip(bounds[:-1], bounds[1:])]
        n_units = len(units)
    values: dict[str, list[float]] = {k: [] for k in metric_fns}
    for _ in range(n):
        pick = rng.integers(0, n_units, n_units)
        idx = pick if units is None else np.concatenate([units[i] for i in pick])
        yy, ss = y[idx], s[idx]
        if yy.min() == yy.max():
            continue
        for k, fn in metric_fns.items():
            values[k].append(float(fn(yy, ss)))
    out = {}
    for k, v in values.items():
        out[k] = (float("nan"), float("nan")) if not v else tuple(float(x) for x in np.percentile(v, [100 * alpha / 2, 100 * (1 - alpha / 2)]))
    return out


def summarize(y, s, *, threshold: float, groups: Optional[Sequence] = None, n_boot: int = 500, seed: int = 0) -> dict:
    """The master prompt's metric set for one score vector, each with a bootstrap 95 % CI (clusters = ``groups``)."""
    y, s = _arr(y), _arr(s)
    r = rates(y, s, threshold)
    out = {
        "n": int(len(y)), "positives": int(y.sum()), "threshold": float(threshold),
        "pr_auc": pr_auc(y, s), "roc_auc": roc_auc(y, s), "f1": r["f1"], "precision": r["precision"], "recall": r["recall"],
        "fpr": r["fpr"], "fpr_at_recall_95": fpr_at_recall(y, s, 0.95), "recall_at_fpr_1pct": recall_at_fpr(y, s, 0.01),
        "brier": brier(y, s), "ece": ece(y, s),
    }
    fns = {
        "pr_auc": pr_auc, "roc_auc": roc_auc, "f1": lambda a, b: rates(a, b, threshold)["f1"],
        "precision": lambda a, b: rates(a, b, threshold)["precision"], "recall": lambda a, b: rates(a, b, threshold)["recall"],
        "fpr": lambda a, b: rates(a, b, threshold)["fpr"],
        "fpr_at_recall_95": lambda a, b: fpr_at_recall(a, b, 0.95), "recall_at_fpr_1pct": lambda a, b: recall_at_fpr(a, b, 0.01),
        "brier": brier, "ece": ece,
    }
    out["ci95"] = bootstrap_many(fns, y, s, groups=groups, n=n_boot, seed=seed)
    return out
