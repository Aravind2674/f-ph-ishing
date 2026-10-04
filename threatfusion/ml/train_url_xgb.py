"""
Train the URL-level maliciousness model on real data (A2-1)
===========================================================

``python -m ml.train_url_xgb``

Replaces the audited, synthetic-data model (3 of 19 features used, one output value over 20,000 inputs).  Protocol:

1. **Data** — PhreshPhish URLs (``ml/collect.py``), canonicalised, de-duplicated, featurised with the same code the API runs
   (``app/ml/url_features.py``): 39 URL-string features, none of which a label feed also supplies.
2. **Splits** — time-ordered and host-disjoint (``ml/dataset.py``): fit on the oldest period, tune and calibrate on the next,
   test (once, in ``ml/evaluate.py``) on the newest period the dataset has.
3. **Tuning** — a seeded random search over tree hyper-parameters, early-stopped and ranked on the **validation** PR-AUC.  The
   test split is never read here.
4. **Calibration** — isotonic or Platt, whichever has the lower cross-validated Brier score on the validation scores
   (``app/ml/calibration.py``); fitted on validation only.
5. **Artifacts** — ``ml/models/url_xgb.ubj`` (booster), ``url_xgb_calibration.json`` (calibrator + the prevalence it is valid
   for) and ``url_xgb_training.json`` (every trial, the seed, data hashes).  ``ml/hash_models.py`` then records their SHA-256 in
   the manifest the API verifies before loading anything.

Nothing is "tuned until a metric looks good": the number of trials is fixed in advance (``--trials``), every trial is logged,
and the reported metrics come from data the search never saw.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold

from app.ml.calibration import PiecewiseCalibrator, PlattCalibrator
from app.ml.url_features import FEATURE_NAMES, URL_FEATURE_SCHEMA_VERSION
from ml import dataset, metrics

logger = logging.getLogger("ml.train_url_xgb")

MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "url_xgb.ubj"          # UBJSON: ~4x smaller than the JSON dump of the same trees
CALIBRATION_PATH = MODELS_DIR / "url_xgb_calibration.json"
TRAINING_LOG = MODELS_DIR / "url_xgb_training.json"
# A-priori monotonic constraints (domain knowledge, not fitted): more evidence of brand impersonation, a user@ trick or a
# mixed-script host never *lowers* the phishing score; being a protected brand's own domain never raises it. Enforced inside
# the trees so the model-health test (A2-2) is a guarantee rather than a hope. Features without a defensible direction (e.g.
# "login" words, which are common on benign pages) are left free.
MONOTONE = {"lookalike_flagged": 1, "lookalike_score": 1, "brand_keyword": 1, "brand_in_subdomain": 1, "host_has_userinfo": 1,
            "host_mixed_script": 1, "is_official_domain": -1}
SEARCH_SPACE = {
    "max_depth": [4, 6, 8, 10], "learning_rate": [0.05, 0.1], "min_child_weight": [1, 5, 20],
    "subsample": [0.7, 0.9, 1.0], "colsample_bytree": [0.6, 0.8, 1.0], "reg_lambda": [1.0, 5.0, 20.0],
}


def sample_params(rng: np.random.Generator) -> dict:
    return {k: v[int(rng.integers(len(v)))] for k, v in SEARCH_SPACE.items()}


def fit_one(params: dict, X_tr, y_tr, X_va, y_va, seed: int) -> xgb.XGBClassifier:
    model = xgb.XGBClassifier(
        n_estimators=1500, tree_method="hist", eval_metric="aucpr", early_stopping_rounds=40, random_state=seed,
        n_jobs=-1, verbosity=0, monotone_constraints=tuple(MONOTONE.get(n, 0) for n in FEATURE_NAMES), **params)
    model.fit(X_tr, y_tr, eval_set=[(X_va, y_va)], verbose=False)
    return model


def choose_calibrator(scores: np.ndarray, labels: np.ndarray, seed: int = 0):
    """Isotonic vs Platt by 5-fold cross-validated Brier score on the validation scores; the winner is refit on all of them."""
    results = {}
    skf = StratifiedKFold(5, shuffle=True, random_state=seed)
    for cls in (PiecewiseCalibrator, PlattCalibrator):
        briers = []
        for tr, te in skf.split(scores, labels):
            cal = cls.fit(scores[tr], labels[tr])
            briers.append(metrics.brier(labels[te], cal(scores[te])))
        results[cls.__name__] = float(np.mean(briers))
    best_cls = PiecewiseCalibrator if results["PiecewiseCalibrator"] <= results["PlattCalibrator"] else PlattCalibrator
    return best_cls.fit(scores, labels), results


def train(trials: int = 10, seed: int = 0, limit: Optional[int] = None, models_dir: Path = MODELS_DIR, augment: float = 0.3) -> dict:
    df = dataset.load()
    if limit:
        df = df.sample(n=min(limit, len(df)), random_state=seed)
    sp = dataset.make_splits(df)
    train_frame = sp.train
    if augment > 0:
        # Adversarial training (B9/B10): label-preserving cheap edits of a fraction of the training URLs, so the model does not
        # lean on features an attacker can change for free (a benign-looking path prefix, a tracking query, a sub-domain).
        train_frame = pd.concat([sp.train, dataset.augmented(sp.train, augment, seed)], ignore_index=True)
    X_tr, y_tr = train_frame[FEATURE_NAMES].to_numpy(np.float32), train_frame["label"].to_numpy()
    X_va, y_va = sp.val[FEATURE_NAMES].to_numpy(np.float32), sp.val["label"].to_numpy()
    logger.info("train %d rows, validation %d rows", len(y_tr), len(y_va))

    rng = np.random.default_rng(seed)
    log = []
    best = None
    for t in range(trials):
        params = sample_params(rng)
        t0 = time.time()
        model = fit_one(params, X_tr, y_tr, X_va, y_va, seed)
        scores = model.predict_proba(X_va)[:, 1]
        pr = metrics.pr_auc(y_va, scores)
        log.append({"trial": t, "params": params, "val_pr_auc": pr, "val_roc_auc": metrics.roc_auc(y_va, scores),
                    "best_iteration": int(model.best_iteration), "seconds": round(time.time() - t0, 1)})
        logger.info("trial %d: val PR-AUC %.4f (%d trees, %.0fs) %s", t, pr, model.best_iteration, time.time() - t0, params)
        if best is None or pr > best[0]:
            best = (pr, model, params)
    _, model, params = best
    raw_val = model.predict_proba(X_va)[:, 1]
    calibrator, cv_brier = choose_calibrator(raw_val, y_va, seed)
    cal_val = calibrator(raw_val)
    models_dir.mkdir(parents=True, exist_ok=True)
    model.save_model(models_dir / "url_xgb.ubj")
    calibration = {
        "calibrator": calibrator.to_dict(), "fit_on": "validation", "validation_rows": int(len(y_va)),
        "validation_prevalence": float(y_va.mean()), "train_prevalence": float(y_tr.mean()), "cv_brier": cv_brier,
        "threshold_fpr_1pct": metrics.threshold_for_fpr(y_va, cal_val, 0.01),
        "threshold_recall_95": metrics.threshold_for_recall(y_va, cal_val, 0.95),
    }
    (models_dir / "url_xgb_calibration.json").write_text(json.dumps(calibration, indent=2), encoding="utf-8")
    training = {
        "seed": seed, "trials": log, "chosen_params": params, "best_iteration": int(model.best_iteration),
        "features": FEATURE_NAMES, "monotone_constraints": MONOTONE, "augment_fraction": augment, "feature_schema_version": URL_FEATURE_SCHEMA_VERSION, "split_report": sp.report,
        "dataset_provenance": json.loads(dataset.PROVENANCE.read_text(encoding="utf-8")) if dataset.PROVENANCE.exists() else None,
        "xgboost_version": xgb.__version__, "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (models_dir / "url_xgb_training.json").write_text(json.dumps(training, indent=2), encoding="utf-8")
    logger.info("saved %s; calibrator %s", models_dir / "url_xgb.ubj", calibrator.kind)
    return training


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m ml.train_url_xgb")
    p.add_argument("--trials", type=int, default=10)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--limit", type=int, default=None, help="train on a random sample only (smoke test)")
    p.add_argument("--augment", type=float, default=0.3, help="fraction of training URLs given a perturbed copy (0 = off)")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    train(trials=args.trials, seed=args.seed, limit=args.limit, augment=args.augment)
    return 0


if __name__ == "__main__":
    sys.exit(main())
