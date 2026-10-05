"""
Evaluation report: does the learned model beat the baseline, honestly? (A2-1, A2-3, B4, B7, B9)
================================================================================================

``python -m ml.evaluate --report``  regenerates **every number quoted in the docs** from the cached data and the shipped models:

* ``ml/results/report.md`` / ``report.json`` — the comparison tables, with 95 % bootstrap CIs (clusters = registered domains);
* ``ml/results/*.png`` — reliability diagrams, PR curves, the decay-over-time plot, permutation importance;
* ``ml/models/*.card.json`` — the model cards (A2-6), rewritten from the same run, plus the fusion artifacts (B7).

Protocol (set in advance; nothing here is tuned on the test split)
------------------------------------------------------------------
1. **Splits** — time-ordered and host-disjoint (``ml/dataset.py``).  The primary TEST set is the newest period; rows whose
   registered domain was in the fitted data are removed (the unfiltered number is reported as secondary, so the size of the
   host-overlap leak is visible).
2. **Operating points are chosen on VALIDATION**: each model's threshold is the one that keeps the false-positive rate ≤ 1 %
   on validation.  The test set only measures.
3. **Same protocol for every model**: the tree model, the character CNN, the a-priori lexical baseline, and the fusions.
4. **Calibration** (isotonic / Platt) was fitted on validation; ECE and Brier are measured on test, before and after.
5. **B9 — time-aware**: per-month windows over the test period with AUT (TESSERACT); precision re-derived at realistic base
   rates (0.05 % … 5 %) from the measured TPR / FPR; permutation importance by feature and by group (how much the model leans
   on cheap-to-evade *surface* features); cheap evasions (appended query, extra sub-domain, benign path prefix) re-scored.
6. **B4 on real data** — the brand-impersonation detector's false-positive rate on real benign URLs and its recall / brand
   accuracy on real phishing pages whose targeted brand is in the curated list.
7. **B7** — noisy-OR vs a stacked logistic regression with missingness flags, also under simulated channel outages.

Limits stated up front: the data is PhreshPhish (≈45 % phishing — a *benchmark*, not traffic); the model reads the URL **text**
only (no page, no infrastructure features); host-disjointness removes the easy repeats, which lowers every score and is the
point.  Numbers are for *this* data and period and will drift (see the decay table).
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
import torch
import xgboost as xgb

from app.ml.calibration import PiecewiseCalibrator, PlattCalibrator, calibrator_from_dict
from app.ml.fusion import StackedFusion, noisy_or
from app.ml.url_baseline import url_baseline_score
from app.ml.url_cnn import UrlCnn, UrlCnnConfig
from app.ml.url_features import FEATURE_GROUPS, FEATURE_NAMES, URL_FEATURE_SCHEMA_VERSION, feature_row
from ml import dataset, metrics
from ml.train_url_cnn import encode_all, predict as cnn_predict
from ml.train_url_xgb import MODELS_DIR

logger = logging.getLogger("ml.evaluate")
RESULTS_DIR = Path(__file__).resolve().parent / "results"
PREVALENCES = [0.0005, 0.001, 0.005, 0.01, 0.05]
CHANNELS = ["xgb", "cnn", "baseline"]


# ── scoring ─────────────────────────────────────────────────────────────────
def load_models(models_dir: Path = MODELS_DIR) -> dict:
    xgbm = xgb.XGBClassifier()
    xgbm.load_model(str(models_dir / "url_xgb.ubj"))
    xcal = calibrator_from_dict(json.loads((models_dir / "url_xgb_calibration.json").read_text())["calibrator"])
    config = UrlCnnConfig.from_json(models_dir / "url_cnn_config.json")
    net = UrlCnn(config)
    net.load_state_dict(torch.load(models_dir / "url_cnn.pt", map_location="cpu", weights_only=True))
    net.eval()
    ccal = calibrator_from_dict(json.loads((models_dir / "url_cnn_calibration.json").read_text())["calibrator"])
    return {"xgb": xgbm, "xgb_cal": xcal, "cnn": net, "cnn_config": config, "cnn_cal": ccal}


def raw_scores(models: dict, frame: pd.DataFrame) -> dict[str, np.ndarray]:
    X = frame[FEATURE_NAMES].to_numpy(np.float32)
    return {
        "xgb": models["xgb"].predict_proba(X)[:, 1],
        "cnn": cnn_predict(models["cnn"], encode_all(frame["canon"], models["cnn_config"])),
        "baseline": np.array([url_baseline_score(dict(zip(FEATURE_NAMES, row))) for row in X]),
    }


def calibrate_channels(raw: dict[str, np.ndarray], cals: dict) -> dict[str, np.ndarray]:
    return {"xgb": cals["xgb"](raw["xgb"]), "cnn": cals["cnn"](raw["cnn"]), "baseline": cals["baseline"](raw["baseline"])}


def oof_calibrated(raw: np.ndarray, y: np.ndarray, seed: int = 0) -> np.ndarray:
    """Two-fold cross-fitted isotonic calibration of validation scores (no row is calibrated by a map fitted on itself)."""
    rng = np.random.default_rng(seed)
    fold = rng.integers(0, 2, len(y))
    out = np.empty(len(y))
    for k in (0, 1):
        cal = PiecewiseCalibrator.fit(raw[fold != k], y[fold != k])
        out[fold == k] = cal(raw[fold == k])
    return out


# ── pieces of the report ────────────────────────────────────────────────────
def operating_point(y_val, s_val, max_fpr: float = 0.01) -> float:
    return metrics.threshold_for_fpr(y_val, s_val, max_fpr)


def month_windows(df: pd.DataFrame) -> list[tuple[str, np.ndarray]]:
    key = df["date"].dt.to_period("M").astype(str).to_numpy()
    return [(m, key == m) for m in sorted(set(key))]


def decay_table(y, scores: dict[str, np.ndarray], thresholds: dict[str, float], df: pd.DataFrame) -> dict:
    out = {}
    for name, s in scores.items():
        rows = []
        for month, mask in month_windows(df):
            if mask.sum() < 200 or len(set(y[mask])) < 2:
                continue
            r = metrics.rates(y[mask], s[mask], thresholds[name])
            rows.append({"window": month, "n": int(mask.sum()), "pr_auc": metrics.pr_auc(y[mask], s[mask]), "recall": r["recall"], "fpr": r["fpr"], "f1": r["f1"]})
        out[name] = {"windows": rows, "aut_pr_auc": metrics.aut([r["pr_auc"] for r in rows]) if rows else None,
                     "aut_recall": metrics.aut([r["recall"] for r in rows]) if rows else None}
    return out


def base_rate_table(y, scores, thresholds) -> dict:
    table = {}
    for name, s in scores.items():
        r = metrics.rates(y, s, thresholds[name])
        table[name] = {"tpr": r["tpr"], "fpr": r["fpr"], "precision_at": {f"{p:.2%}": metrics.precision_at_base_rate(r["tpr"], r["fpr"], p) for p in PREVALENCES}}
    return table


def permutation_importance(models: dict, test: pd.DataFrame, n_rows: int = 30000, repeats: int = 3, seed: int = 0) -> dict:
    """Drop in PR-AUC when one feature (or one whole group) is shuffled — on test rows, with the shipped (calibrated) tree model."""
    rng = np.random.default_rng(seed)
    sample = test.sample(n=min(n_rows, len(test)), random_state=seed)
    X = sample[FEATURE_NAMES].to_numpy(np.float32)
    y = sample["label"].to_numpy()
    base = metrics.pr_auc(y, models["xgb"].predict_proba(X)[:, 1])

    def drop(cols: list[int]) -> tuple[float, float]:
        deltas = []
        for _ in range(repeats):
            Xp = X.copy()
            perm = rng.permutation(len(X))
            Xp[:, cols] = X[perm][:, cols]
            deltas.append(base - metrics.pr_auc(y, models["xgb"].predict_proba(Xp)[:, 1]))
        return float(np.mean(deltas)), float(np.std(deltas))

    per_feature = {}
    for i, name in enumerate(FEATURE_NAMES):
        mean, sd = drop([i])
        per_feature[name] = {"delta_pr_auc": mean, "sd": sd, "group": FEATURE_GROUPS[name]}
    per_group = {}
    for g in sorted(set(FEATURE_GROUPS.values())):
        mean, sd = drop([i for i, n in enumerate(FEATURE_NAMES) if FEATURE_GROUPS[n] == g])
        per_group[g] = {"delta_pr_auc": mean, "sd": sd}
    meaningful = [n for n, v in per_feature.items() if v["delta_pr_auc"] - 2 * v["sd"] > 0 and v["delta_pr_auc"] > 0.0005]
    return {"baseline_pr_auc": base, "per_feature": per_feature, "per_group": per_group, "n_meaningful": len(meaningful), "meaningful": meaningful}


def _perturbations() -> dict:
    def append_query(c: str) -> str:
        return c + ("&" if "?" in c else "?") + "utm_source=newsletter&ref=home"

    def extra_subdomain(c: str) -> str:
        return "blog." + c

    def benign_path(c: str) -> str:
        i = next((k for k, ch in enumerate(c) if ch in "/?#"), len(c))
        return c[:i] + "/blog/2024/travel-tips" + c[i:]

    def pad_path(c: str) -> str:
        i = next((k for k, ch in enumerate(c) if ch in "/?#"), len(c))
        return c[:i] + "/" + "a" * 24 + c[i:]

    return {"append_query": append_query, "extra_subdomain": extra_subdomain, "benign_path_prefix": benign_path, "pad_path": pad_path}


def robustness(models: dict, test: pd.DataFrame, cals: dict, thresholds: dict, n: int = 8000, seed: int = 0) -> dict:
    """Recall at the fixed operating points on real phishing URLs after a cheap, content-free edit (B9)."""
    phish = test[test["label"] == 1].sample(n=min(n, int((test["label"] == 1).sum())), random_state=seed)
    out = {}
    for pname, fn in _perturbations().items():
        edited = pd.DataFrame({"canon": phish["canon"].map(fn)})
        feats = pd.DataFrame([feature_row(c) for c in edited["canon"]], columns=FEATURE_NAMES)
        edited = pd.concat([edited.reset_index(drop=True), feats], axis=1)
        raw = raw_scores(models, edited)
        cal = calibrate_channels(raw, cals)
        before_raw = raw_scores(models, phish.reset_index(drop=True))
        before = calibrate_channels(before_raw, cals)
        out[pname] = {k: {"recall_before": float((before[k] >= thresholds[k]).mean()), "recall_after": float((cal[k] >= thresholds[k]).mean())}
                      for k in CHANNELS}
    return out


def b4_real_data(test: pd.DataFrame, limit: int = 120000, seed: int = 0) -> dict:
    """The B4 detector on real benign / phishing URLs (replaces the synthetic fixture as the headline B4 number)."""
    from app.ml.brands import CURATED_BRANDS, BrandIndex
    from app.ml.lookalike import assess_lookalike
    from app.ml.url_canon import hostname_of

    index = BrandIndex.build()
    sample = test.sample(n=min(limit, len(test)), random_state=seed)
    key_to_name: dict[str, str] = {}
    for b in CURATED_BRANDS:
        for lab in (b.key, b.name.lower().replace(" ", ""), *b.keywords):
            key_to_name[lab.lower()] = b.name
    benign = sample[sample["label"] == 0]
    phish = sample[sample["label"] == 1]

    def flagged_brand(canon: str):
        host = hostname_of(canon)
        if not host:
            return None
        res = assess_lookalike(host, index)
        return res.match.brand if res.status == "lookalike" and res.match else None

    benign_flags = [flagged_brand(c) for c in benign["canon"]]
    phish_flags = [flagged_brand(c) for c in phish["canon"]]
    targeted = phish["target"].fillna("other").str.lower().map(lambda t: key_to_name.get(t.replace(" ", "")))
    in_list = targeted.notna().to_numpy()
    flags_arr = np.array([f is not None for f in phish_flags])
    brand_ok = np.array([f is not None and t is not None and f == t for f, t in zip(phish_flags, targeted)])
    n_benign, n_phish = len(benign), len(phish)
    fp = sum(f is not None for f in benign_flags)
    return {
        "sample_rows": int(len(sample)), "benign_rows": n_benign, "phish_rows": n_phish,
        "benign_flagged": int(fp), "benign_flag_rate": fp / n_benign if n_benign else None,
        "phish_flagged": int(flags_arr.sum()), "phish_flag_rate": float(flags_arr.mean()) if n_phish else None,
        "phish_targeting_a_curated_brand": int(in_list.sum()),
        "recall_on_curated_brand_targets": float(flags_arr[in_list].mean()) if in_list.any() else None,
        "brand_match_accuracy_when_flagged_and_target_known": float(brand_ok[flags_arr & in_list].mean()) if (flags_arr & in_list).any() else None,
        "examples_benign_flagged": [c for c, f in zip(benign["canon"], benign_flags) if f][:8],
    }


LOGIN_WORDS = ("login", "signin", "sign-in", "logon", "checkout", "payment", "account", "verify", "password", "secure")


def benign_login_pages(test: pd.DataFrame, scores: dict[str, np.ndarray], thresholds: dict[str, float]) -> dict:
    """False-positive rate on *real benign pages that look like phishing targets* (login / checkout / account paths)."""
    path = test["canon"].map(lambda c: c.split("/", 1)[1].lower() if "/" in c else "")
    mask = (test["label"].to_numpy() == 0) & path.map(lambda p: any(w in p for w in LOGIN_WORDS)).to_numpy()
    out = {"n": int(mask.sum()), "examples": test.loc[mask, "canon"].head(5).tolist()}
    for k, s in scores.items():
        out[k] = float((s[mask] >= thresholds[k]).mean()) if mask.any() else None
    return out


def fusion_study(y_val, raw_val, y_test, raw_test, cals) -> dict:
    """B7: noisy-OR vs stacked LR (cross-fitted on validation), with and without channel outages on the test set."""
    names = CHANNELS
    oof = np.column_stack([oof_calibrated(raw_val[n], y_val, seed=i) for i, n in enumerate(names)])
    stacker = StackedFusion.fit(names, oof, y_val, seed=0)
    test_cal = np.column_stack([cals[n](raw_test[n]) for n in names])
    val_fused = stacker.predict_matrix(np.column_stack([cals[n](raw_val[n]) for n in names]))
    thr = metrics.threshold_for_fpr(y_val, val_fused, 0.01)

    def run(mask_cols: tuple[int, ...] = ()):
        S = test_cal.copy()
        S[:, list(mask_cols)] = np.nan
        stacked = stacker.predict_matrix(S)
        nor = np.array([noisy_or([None if np.isnan(v) else v for v in row]) if not np.all(np.isnan(row)) else np.nan for row in S])
        mean = np.nanmean(S, axis=1)
        out = {}
        for label, s in (("stacked", stacked), ("noisy_or", nor), ("mean", mean)):
            keep = ~np.isnan(s)
            out[label] = {"pr_auc": metrics.pr_auc(y_test[keep], s[keep]), "roc_auc": metrics.roc_auc(y_test[keep], s[keep]),
                          "brier": metrics.brier(y_test[keep], s[keep]), "ece": metrics.ece(y_test[keep], s[keep])}
        return out

    studies = {"all_channels": run(), "cnn_down": run((1,)), "xgb_down": run((0,)), "only_baseline": run((0, 1))}
    return {"stacker": stacker, "threshold": thr, "studies": studies, "weights": dict(zip(names, stacker.weights)),
            "missing_weights": dict(zip(names, stacker.missing_weights)), "intercept": stacker.intercept,
            "val_fused": val_fused, "test_fused": stacker.predict_matrix(test_cal)}


# ── figures ─────────────────────────────────────────────────────────────────
def figures(out: Path, y, scores: dict[str, np.ndarray], raw_xgb, decay: dict, imp: dict) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import precision_recall_curve

    files = []
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    for ax, (title, items) in zip(axes, (("Reliability (test)", {**scores, "xgb (uncalibrated)": raw_xgb}), ("Precision-recall (test)", scores))):
        if title.startswith("Reliability"):
            for name, s in items.items():
                rel = metrics.reliability_bins(y, s, 10)
                ax.plot([r["mean_pred"] for r in rel], [r["observed"] for r in rel], marker="o", label=name)
            ax.plot([0, 1], [0, 1], "k--", lw=1)
            ax.set_xlabel("predicted probability")
            ax.set_ylabel("observed phishing frequency")
        else:
            for name, s in items.items():
                p, r, _ = precision_recall_curve(y, s)
                ax.plot(r, p, label=name)
            ax.set_xlabel("recall")
            ax.set_ylabel("precision")
        ax.set_title(title)
        ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(out / "calibration_and_pr.png", dpi=130)
    plt.close(fig)
    files.append("calibration_and_pr.png")

    fig, ax = plt.subplots(figsize=(6.5, 4))
    for name, d in decay.items():
        rows = d["windows"]
        ax.plot([r["window"] for r in rows], [r["recall"] for r in rows], marker="o", label=f"{name} (AUT {d['aut_recall']:.3f})" if d["aut_recall"] is not None else name)
    ax.set_ylabel("recall at the validation operating point")
    ax.set_title("Decay over the test period")
    ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(out / "decay.png", dpi=130)
    plt.close(fig)
    files.append("decay.png")

    fig, ax = plt.subplots(figsize=(7, 8))
    top = sorted(imp["per_feature"].items(), key=lambda kv: kv[1]["delta_pr_auc"])[-20:]
    ax.barh([k for k, _ in top], [v["delta_pr_auc"] for _, v in top], xerr=[v["sd"] for _, v in top])
    ax.set_xlabel("drop in PR-AUC when the feature is shuffled")
    ax.set_title("Permutation importance (top 20)")
    fig.tight_layout()
    fig.savefig(out / "importance.png", dpi=130)
    plt.close(fig)
    files.append("importance.png")
    return files


# ── report ──────────────────────────────────────────────────────────────────
def fmt_ci(x: float, ci) -> str:
    return f"{x:.3f} [{ci[0]:.3f}, {ci[1]:.3f}]"


def run_report(n_boot: int = 200, models_dir: Path = MODELS_DIR, out: Path = RESULTS_DIR, write_cards: bool = True) -> dict:
    t_start = time.time()
    out.mkdir(parents=True, exist_ok=True)
    df = dataset.load()
    sp = dataset.make_splits(df)
    models = load_models(models_dir)
    prov = json.loads(dataset.PROVENANCE.read_text(encoding="utf-8"))

    raw_val, raw_test, raw_test_unf = (raw_scores(models, f) for f in (sp.val, sp.test, sp.test_raw))
    y_val, y_test, y_test_unf = (f["label"].to_numpy() for f in (sp.val, sp.test, sp.test_raw))
    cals = {"xgb": models["xgb_cal"], "cnn": models["cnn_cal"], "baseline": PiecewiseCalibrator.fit(raw_val["baseline"], y_val)}
    cal_val, cal_test, cal_test_unf = (calibrate_channels(r, cals) for r in (raw_val, raw_test, raw_test_unf))

    fus = fusion_study(y_val, raw_val, y_test, raw_test, cals)
    scores_test = {**cal_test, "fused": fus["test_fused"]}
    scores_val = {**cal_val, "fused": fus["val_fused"]}
    thresholds = {k: operating_point(y_val, scores_val[k]) for k in scores_test}
    groups = sp.test["domain"].to_numpy()

    table, table_unf, table_raw = {}, {}, {}
    fused_unf = fus["stacker"].predict_matrix(np.column_stack([cal_test_unf[n] for n in CHANNELS]))
    for name, s in scores_test.items():
        table[name] = metrics.summarize(y_test, s, threshold=thresholds[name], groups=groups, n_boot=n_boot)
    for name, s in {**cal_test_unf, "fused": fused_unf}.items():
        table_unf[name] = metrics.summarize(y_test_unf, s, threshold=thresholds[name], groups=sp.test_raw["domain"].to_numpy(), n_boot=max(50, n_boot // 4))
    table_raw["xgb_uncalibrated"] = metrics.summarize(y_test, raw_test["xgb"], threshold=cals["xgb"].x_knots[0] if False else 0.5, groups=groups, n_boot=max(50, n_boot // 4))
    table_raw["cnn_uncalibrated"] = metrics.summarize(y_test, raw_test["cnn"], threshold=0.5, groups=groups, n_boot=max(50, n_boot // 4))

    decay = decay_table(y_test, scores_test, thresholds, sp.test)
    base_rates = base_rate_table(y_test, scores_test, thresholds)
    imp = permutation_importance(models, sp.test)
    robust = robustness(models, sp.test, cals, thresholds)
    b4 = b4_real_data(sp.test)
    login = benign_login_pages(sp.test, scores_test, thresholds)
    files = figures(out, y_test, {k: scores_test[k] for k in ("xgb", "cnn", "baseline", "fused")}, raw_test["xgb"], decay, imp)

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": round(time.time() - t_start),
        "dataset": prov, "splits": sp.report, "thresholds_fpr_1pct_on_validation": thresholds, "test": table,
        "test_unfiltered_host_overlap": table_unf, "uncalibrated": table_raw, "decay": decay, "base_rate_precision": base_rates,
        "permutation_importance": imp, "robustness_recall_before_after": robust, "b4_real_data": b4, "benign_login_pages": login,
        "fusion": {k: v for k, v in fus.items() if k not in ("stacker", "val_fused", "test_fused")}, "figures": files,
        "feature_schema_version": URL_FEATURE_SCHEMA_VERSION, "n_boot": n_boot,
    }
    (out / "report.json").write_text(json.dumps(report, indent=2, default=float), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    if write_cards:
        write_artifacts(report, models, cals, fus, models_dir, sp)
    logger.info("report written to %s (%.0fs)", out, time.time() - t_start)
    return report


def render_markdown(r: dict) -> str:
    L: list[str] = []
    ds, sp = r["dataset"], r["splits"]
    L += ["# ThreatFusion — URL maliciousness evaluation", "",
          f"_Generated {r['generated_at']} by `python -m ml.evaluate --report` in {r['seconds']} s. Bootstrap: {r['n_boot']} resamples of registered domains._", "",
          "## Data and protocol", "",
          f"* Source: **{ds['source']}** — {ds['rows']:,} URLs ({ds['phish_rows']:,} phishing / {ds['benign_rows']:,} benign), {ds['date_min']} → {ds['date_max']}.",
          f"* Dataset sha256 `{ds['dataset_sha256'][:16]}…`, raw manifest sha256 `{ds['raw_manifest_sha256'][:16]}…`, feature schema v{r['feature_schema_version']} ({ds['n_features']} URL-string features).",
          "* Splits are **time-ordered and host-disjoint**: fit on the oldest period, tune/calibrate on the next, test once on the newest.", "",
          "| split | rows | phishing share | registered domains | period |", "|---|---:|---:|---:|---|"]
    for name in ("train", "val", "test", "test_unfiltered"):
        s = sp[name]
        L.append(f"| {name} | {s['rows']:,} | {s['phish_fraction']:.1%} | {s['domains']:,} | {s['date_min']} → {s['date_max']} |")
    L += ["", f"Host-overlap filter removed {sp['test_rows_removed_for_host_overlap']:,} test rows and {sp['val_rows_removed_for_host_overlap']:,} validation rows "
              f"whose registered domain was in the fitted data. The benchmark is ~45 % phishing; real traffic is far lower (see base rates below).", "",
          "## Headline comparison (test, host-disjoint; operating point = FPR ≤ 1 % on validation)", "",
          "| model | PR-AUC | ROC-AUC | F1 | recall @ FPR≤1 % | FPR @ recall 95 % | Brier | ECE |", "|---|---|---|---|---|---|---|---|"]
    label = {"xgb": "tree model (URL features)", "cnn": "character CNN", "baseline": "a-priori lexical baseline", "fused": "stacked fusion (B7)"}
    for k in ("baseline", "xgb", "cnn", "fused"):
        t = r["test"][k]
        c = t["ci95"]
        L.append(f"| {label[k]} | {fmt_ci(t['pr_auc'], c['pr_auc'])} | {fmt_ci(t['roc_auc'], c['roc_auc'])} | {fmt_ci(t['f1'], c['f1'])} | "
                 f"{fmt_ci(t['recall_at_fpr_1pct'], c['recall_at_fpr_1pct'])} | {fmt_ci(t['fpr_at_recall_95'], c['fpr_at_recall_95'])} | "
                 f"{fmt_ci(t['brier'], c['brier'])} | {fmt_ci(t['ece'], c['ece'])} |")
    L += ["", "No metric is 1.0. The baseline's weights were fixed before any model was trained; only its threshold is chosen on validation.", "",
          "### Same models on the *unfiltered* test set (host overlap allowed)", "", "| model | PR-AUC | ROC-AUC |", "|---|---|---|"]
    for k in ("baseline", "xgb", "cnn", "fused"):
        t = r["test_unfiltered_host_overlap"][k]
        L.append(f"| {label[k]} | {fmt_ci(t['pr_auc'], t['ci95']['pr_auc'])} | {fmt_ci(t['roc_auc'], t['ci95']['roc_auc'])} |")
    L += ["", "The difference between the two tables is the size of the host-overlap leak in a naive evaluation.", "",
          "### Calibration (test)", "", "| channel | ECE uncalibrated | ECE calibrated | Brier uncalibrated | Brier calibrated |", "|---|---|---|---|---|"]
    for k, ku in (("xgb", "xgb_uncalibrated"), ("cnn", "cnn_uncalibrated")):
        L.append(f"| {label[k]} | {r['uncalibrated'][ku]['ece']:.3f} | {r['test'][k]['ece']:.3f} | {r['uncalibrated'][ku]['brier']:.3f} | {r['test'][k]['brier']:.3f} |")
    L += ["", "![calibration and PR](calibration_and_pr.png)", "", "## B9 — time-aware evaluation", "",
          "Recall and false-positive rate at the fixed validation operating point, per month of the test period (the model was fitted on older data):", "",
          "| model | " + " | ".join(w["window"] for w in r["decay"]["xgb"]["windows"]) + " | AUT(recall) |", "|---|" + "---|" * (len(r["decay"]["xgb"]["windows"]) + 1)]
    for k in ("baseline", "xgb", "cnn", "fused"):
        d = r["decay"][k]
        L.append(f"| {label[k]} | " + " | ".join(f"{w['recall']:.3f} (FPR {w['fpr']:.3f})" for w in d["windows"]) + f" | {d['aut_recall']:.3f} |")
    L += ["", "![decay](decay.png)", "", "### Precision at realistic phishing prevalence (derived from the measured TPR / FPR)", "",
          "| model | TPR | FPR | " + " | ".join(f"π = {p}" for p in next(iter(r["base_rate_precision"].values()))["precision_at"]) + " |", "|---|---|---|" + "---|" * len(PREVALENCES)]
    for k in ("baseline", "xgb", "cnn", "fused"):
        b = r["base_rate_precision"][k]
        L.append(f"| {label[k]} | {b['tpr']:.3f} | {b['fpr']:.4f} | " + " | ".join(f"{v:.3f}" for v in b["precision_at"].values()) + " |")
    L += ["", "A detector that looks precise on a 45 %-phishing benchmark is mostly wrong at 0.1 % prevalence: this table is *derived* "
              "(`precision = TPR·π / (TPR·π + FPR·(1-π))`), not re-measured.", "",
          "### Which features carry the model? (permutation importance on test)", "", f"Features with a meaningful importance (mean drop − 2 sd > 0): **{r['permutation_importance']['n_meaningful']}** of {len(FEATURE_NAMES)}.", "",
          "| group | drop in PR-AUC when the whole group is shuffled |", "|---|---|"]
    for g, v in sorted(r["permutation_importance"]["per_group"].items(), key=lambda kv: -kv[1]["delta_pr_auc"]):
        L.append(f"| {g} | {v['delta_pr_auc']:.4f} ± {v['sd']:.4f} |")
    top = sorted(r["permutation_importance"]["per_feature"].items(), key=lambda kv: -kv[1]["delta_pr_auc"])[:10]
    L += ["", "Top features: " + ", ".join(f"`{k}` ({v['delta_pr_auc']:.4f})" for k, v in top), "", "![importance](importance.png)", "",
          "### Cheap evasions (recall on real phishing URLs at the fixed operating point)", "", "| edit | tree before → after | CNN before → after | baseline before → after |", "|---|---|---|---|"]
    for pname, v in r["robustness_recall_before_after"].items():
        L.append(f"| {pname} | " + " | ".join(f"{v[k]['recall_before']:.3f} → {v[k]['recall_after']:.3f}" for k in CHANNELS) + " |")
    L += ["", "Reading the table: the edits use tokens the models never saw in adversarial training. A drop is an evasion that works; a *rise* "
               "(e.g. appending a query string) means the model treats that edit as a phishing cue because of how this dataset was crawled — "
               "a dataset artefact, not a property of phishing. The URL channel is therefore one input among several, never a verdict on its own."]
    lg = r["benign_login_pages"]
    L += ["", f"### False positives on real benign login / checkout / account pages (n = {lg['n']:,})", "",
          "| model | FPR at the validation operating point |", "|---|---|"]
    for k in ("baseline", "xgb", "cnn", "fused"):
        L.append(f"| {label[k]} | {lg[k]:.4f} |" if lg[k] is not None else f"| {label[k]} | n/a |")
    L += ["", "## B4 — brand impersonation on real data", ""]
    b = r["b4_real_data"]
    L += [f"On a sample of {b['sample_rows']:,} test URLs ({b['benign_rows']:,} benign, {b['phish_rows']:,} phishing):", "",
          f"* **False-positive rate on real benign URLs: {b['benign_flag_rate']:.4f}** ({b['benign_flagged']} flagged).",
          f"* Share of all phishing URLs flagged as a look-alike: {b['phish_flag_rate']:.3f}.",
          f"* Of the {b['phish_targeting_a_curated_brand']:,} phishing pages whose targeted brand is in the curated list: **recall {b['recall_on_curated_brand_targets']:.3f}**; "
          f"when flagged, the matched brand equals the labelled target in {b['brand_match_accuracy_when_flagged_and_target_known']:.3f} of cases." if b["recall_on_curated_brand_targets"] is not None else "* (no phishing page in the sample targets a curated brand)",
          "* Most phishing in this dataset is hosted on free hosting / generated sub-domains rather than registered look-alike domains, which a look-alike *domain* detector cannot see by design.", ""]
    L += ["## B7 — fusion", "", "| scenario | method | PR-AUC | ROC-AUC | Brier | ECE |", "|---|---|---|---|---|---|"]
    for scen, m in r["fusion"]["studies"].items():
        for meth, v in m.items():
            L.append(f"| {scen} | {meth} | {v['pr_auc']:.3f} | {v['roc_auc']:.3f} | {v['brier']:.3f} | {v['ece']:.3f} |")
    L += ["", f"Stacker weights (log-odds per channel logit): {', '.join(f'{k} {v:.2f}' for k, v in r['fusion']['weights'].items())}; "
              f"missingness terms: {', '.join(f'{k} {v:.2f}' for k, v in r['fusion']['missing_weights'].items())}.", "",
          "The three channels all read the same URL, so they are *not* independent — noisy-OR's assumption does not hold and it "
          "over-states confidence when channels agree; the table measures the effect rather than assuming it.", "",
          "## Limits", "", "* The data is a research benchmark, not traffic. The score is about the URL **text** only.",
          "* No page content, DNS, TLS, registration or reputation features were available at scale (see `ml/collect.py`).",
          "* PhreshPhish URLs were crawled by one pipeline: some of what the model learns is the *dataset's* shape. The time-ordered, host-disjoint protocol limits, but cannot remove, this.",
          "* Thresholds and calibration are tied to the validation prevalence; use the base-rate table for deployment reasoning.", ""]
    return "\n".join(L)


def write_artifacts(report: dict, models: dict, cals: dict, fus: dict, models_dir: Path, sp) -> None:
    """Model cards (A2-6) + the baseline calibrator and fusion artifact (B7), from the numbers just computed."""
    prov = report["dataset"]
    created = report["generated_at"]
    common_data = {"source": prov["source"], "rows_train": report["splits"]["train"]["rows"], "rows_val": report["splits"]["val"]["rows"],
                   "rows_test": report["splits"]["test"]["rows"], "date_range": f"{prov['date_min']} → {prov['date_max']}",
                   "dataset_sha256": prov["dataset_sha256"], "raw_manifest_sha256": prov["raw_manifest_sha256"],
                   "splits": "time-ordered, host-disjoint (ml/dataset.py)", "leakage_controls": [
                       "no feature that a label feed also supplies (no popularity rank, no blocklist membership, no scheme)",
                       "evaluation rows removed when their registered domain is in the fitted data"]}
    schema = {"version": URL_FEATURE_SCHEMA_VERSION, "names": FEATURE_NAMES}
    limits = ["Scores the URL text only: not the page, the owner or the infrastructure.",
              "Trained on PhreshPhish (a benchmark, ~45 % phishing); calibrated probabilities overstate risk at real-world prevalence — use `at_prevalence`.",
              "Performance decays as phishing practice shifts (see the per-month table); retrain on fresh data periodically.",
              "Cannot see look-alike abuse of free hosting platforms except through hosting-pattern features it learned."]
    use = "Fast-tier triage of a URL string (B1) and one calibrated channel of the fusion (B7). Not a verdict; never a reason to block without corroboration."
    train_log = json.loads((models_dir / "url_xgb_training.json").read_text())
    cnn_log = json.loads((models_dir / "url_cnn_training.json").read_text())
    xgb_cal = json.loads((models_dir / "url_xgb_calibration.json").read_text())
    cnn_cal = json.loads((models_dir / "url_cnn_calibration.json").read_text())

    def card(name, task, version, test_key, calib, training):
        t = report["test"][test_key]
        return {"name": name, "version": version, "task": task, "created_at": created, "intended_use": use, "limitations": limits,
                "feature_schema": schema if name != "url_cnn" else {"version": URL_FEATURE_SCHEMA_VERSION, "names": FEATURE_NAMES,
                                                                       "note": "the CNN reads the canonical URL text, not these features; the schema is recorded for the shared data"},
                "data": common_data, "training": training,
                "calibration": {"kind": calib["calibrator"]["kind"], "fit_on": "validation", "validation_prevalence": calib["validation_prevalence"],
                                "threshold_fpr_1pct": calib["threshold_fpr_1pct"], "cv_brier": calib["cv_brier"]},
                "metrics": {"test": {**{k: t[k] for k in ("pr_auc", "roc_auc", "f1", "precision", "recall", "fpr", "fpr_at_recall_95",
                                                           "recall_at_fpr_1pct", "brier", "ece", "n", "positives", "threshold")},
                                     "ci95": {k: list(v) for k, v in t["ci95"].items()}},
                            "protocol": "time-ordered host-disjoint test; threshold FPR<=1% chosen on validation; cluster bootstrap CIs",
                            "decay_aut_recall": report["decay"][test_key]["aut_recall"]},
                "report": "ml/results/report.md"}

    cards = {
        "url_xgb": card("url_xgb", "URL-string phishing probability (gradient-boosted trees)", f"xgb-{prov['dataset_sha256'][:8]}", "xgb", xgb_cal,
                        {"chosen_params": train_log["chosen_params"], "trials": len(train_log["trials"]), "seed": train_log["seed"],
                         "xgboost": train_log["xgboost_version"]}),
        "url_cnn": card("url_cnn", "URL-string phishing probability (character CNN, text-only)", f"cnn-{prov['dataset_sha256'][:8]}", "cnn", cnn_cal,
                        {"epochs_run": cnn_log["epochs_run"], "seed": cnn_log["seed"], "torch": cnn_log["torch_version"]}),
    }
    for name, c in cards.items():
        (models_dir / f"{name}.card.json").write_text(json.dumps(c, indent=2, default=float), encoding="utf-8")
    (models_dir / "url_baseline_calibration.json").write_text(json.dumps({"calibrator": cals["baseline"].to_dict(), "fit_on": "validation"}, indent=2), encoding="utf-8")
    (models_dir / "url_fusion.json").write_text(fus["stacker"].to_json(), encoding="utf-8")
    fusion_card = card("url_fusion", "Stacked fusion of the calibrated URL channels (B7)", f"fusion-{prov['dataset_sha256'][:8]}", "fused",
                       {"calibrator": {"kind": "stacked-logistic-regression"}, "validation_prevalence": xgb_cal["validation_prevalence"],
                        "threshold_fpr_1pct": fus["threshold"], "cv_brier": None}, {"channels": CHANNELS, "cross_fitted_on": "validation", "dropout": 0.25})
    fusion_card["threshold"] = fus["threshold"]
    (models_dir / "url_fusion.card.json").write_text(json.dumps(fusion_card, indent=2, default=float), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m ml.evaluate")
    p.add_argument("--report", action="store_true", help="regenerate every number, figure and model card")
    p.add_argument("--boot", type=int, default=200, help="bootstrap resamples (default 200)")
    args = p.parse_args(argv)
    if not args.report:
        p.print_help()
        return 0
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    run_report(n_boot=args.boot)
    return 0


if __name__ == "__main__":
    sys.exit(main())
