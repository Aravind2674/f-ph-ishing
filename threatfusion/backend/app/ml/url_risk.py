"""
The URL-level maliciousness service (A2-1, A2-3, A2-5, A2-6, B7)
=================================================================

Bundles the shipped URL models behind one object the API calls:

* ``url_xgb``  — gradient-boosted trees over the 39 URL-string features (``url_features.py``), **calibrated**;
* ``url_cnn``  — a text-only character CNN over the canonical URL, **calibrated**;
* the a-priori lexical baseline (``url_baseline.py``), **calibrated** the same way so it can be compared and fused;
* ``url_fusion`` — the stacked fusion of the three (``fusion.py``), when its artifact is present.

Rules it enforces
-----------------
* **Model health is explicit.**  Each component loads only if its files match the SHA-256 manifest *and* its model card is
  present and its feature schema equals the code's (``model_cards.validate_card``).  A component that cannot load is reported
  with the reason (``problems``) and the assessment degrades to the remaining ones — never to a made-up score.
* **Explanations are exact TreeSHAP from XGBoost's own ``pred_contribs``** — additive by construction, nothing built per
  request (the old code rebuilt a ``shap.TreeExplainer`` for every scan; ``shap`` 0.52's explainer was also found to disagree with
  XGBoost's margin by ~0.02 log-odds on this model, so it is not used for the shipped tree model).
* **Units are stated.**  SHAP values are *log-odds* contributions to the raw model margin (``bias + Σ contributions = margin``,
  asserted by a test).  For each feature the card also gives how much the calibrated *probability* would change if that
  feature's contribution were removed (``probability_delta``) — a what-if, not an additive share.
* **Prevalence is stated.**  Calibrated probabilities are valid for the phishing share of the validation data (~half); the
  assessment adds what the same score means at 1-in-100 and 1-in-1000 phishing traffic (``prior_shift``).
* The score answers *"is this URL string phishing-like?"* — it is **not** a verdict on the site's content or owner.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Callable, Optional

import numpy as np
import xgboost as xgb

from app.core.artifacts import default_models_dir, verify_artifact
from app.ml import model_cards
from app.ml.calibration import calibrator_from_dict, prior_shift
from app.ml.fusion import StackedFusion
from app.ml.url_baseline import url_baseline_score, url_baseline_terms
from app.ml.url_cnn import UrlCnnModel
from app.ml.url_features import FEATURE_GROUPS, FEATURE_NAMES, URL_FEATURE_SCHEMA_VERSION, extract_url_features
from app.models.schemas import NeuralExplanation, RiskExplanation, UrlRiskAssessment, UrlRiskTerm

logger = logging.getLogger(__name__)

PREVALENCES = (0.01, 0.001)

# Plain-English label + formatter for each feature (evidence cards).
def _n(v: float) -> str:
    return f"{v:.0f}"


def _pct(v: float) -> str:
    return f"{v:.0%}"


FEATURE_TEXT: dict[str, tuple[str, Callable[[float], str]]] = {
    "url_len": ("URL length", lambda v: f"{_n(v)} characters"), "host_len": ("Host name length", lambda v: f"{_n(v)} characters"),
    "path_len": ("Path length", lambda v: f"{_n(v)} characters"), "query_len": ("Query-string length", lambda v: f"{_n(v)} characters"),
    "digit_ratio": ("Digits in the URL", _pct), "letter_ratio": ("Letters in the URL", _pct),
    "special_count": ("Special characters", _n), "upper_ratio": ("Upper-case characters", _pct), "url_entropy": ("URL randomness (entropy)", lambda v: f"{v:.2f} bits"),
    "host_dots": ("Dots in the host", _n), "host_hyphens": ("Hyphens in the host", _n), "host_digit_ratio": ("Digits in the host", _pct),
    "subdomain_depth": ("Sub-domain levels", _n), "registered_label_len": ("Length of the registered name", _n), "tld_len": ("Length of the domain ending", _n),
    "tld_is_common": ("Common domain ending", lambda v: "yes" if v else "no"), "host_is_ip": ("Host is a raw IP address", lambda v: "yes" if v else "no"),
    "host_has_port": ("Explicit port in the URL", lambda v: "yes" if v else "no"), "host_has_userinfo": ("user@ trick in the URL", lambda v: "yes" if v else "no"),
    "host_is_punycode": ("Internationalised (punycode) host", lambda v: "yes" if v else "no"),
    "host_mixed_script": ("Host mixes alphabets", lambda v: "yes" if v else "no"), "host_entropy": ("Host randomness (entropy)", lambda v: f"{v:.2f} bits"),
    "host_longest_label": ("Longest host label", lambda v: f"{_n(v)} characters"), "path_segments": ("Path segments", _n),
    "path_longest_segment": ("Longest path segment", lambda v: f"{_n(v)} characters"), "path_entropy": ("Path randomness (entropy)", lambda v: f"{v:.2f} bits"),
    "query_params": ("Query parameters", _n), "path_has_double_slash": ("'//' inside the path", lambda v: "yes" if v else "no"),
    "path_has_extension": ("File extension in the path", lambda v: "yes" if v else "no"), "path_digit_ratio": ("Digits in the path", _pct),
    "risk_words_host": ("Phishing-style words in the host", _n), "risk_words_path": ("Phishing-style words in the path", _n),
    "risk_words_query": ("Phishing-style words in the query", _n), "lookalike_score": ("Resemblance to a protected brand", lambda v: f"rule score {v:.2f}"),
    "lookalike_flagged": ("Imitates a protected brand", lambda v: "yes" if v else "no"), "is_official_domain": ("A protected brand's own domain", lambda v: "yes" if v else "no"),
    "brand_in_subdomain": ("Brand name in a sub-domain", lambda v: "yes" if v else "no"), "brand_in_path": ("Brand name in the path of another site", lambda v: "yes" if v else "no"),
    "brand_keyword": ("Brand + phishing keyword", lambda v: "yes" if v else "no"),
}
assert set(FEATURE_TEXT) == set(FEATURE_NAMES), "every feature needs a plain-English description"


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.asarray(z, dtype=np.float64)))


class UrlRiskService:
    def __init__(self) -> None:
        self._booster: Optional[xgb.XGBClassifier] = None
        self._xgb_cal = None
        self._thresholds: dict[str, float] = {}
        self._baseline_cal = None
        self._fusion: Optional[StackedFusion] = None
        self._cnn = UrlCnnModel()
        self._lock = threading.Lock()
        self.cards: dict[str, Optional[dict]] = {}
        self.problems: dict[str, str] = {}
        self.models_dir = default_models_dir()

    # ── lifecycle ──────────────────────────────────────────────────────
    @property
    def loaded(self) -> bool:
        return self._booster is not None

    def _card(self, name: str) -> Optional[dict]:
        try:
            card = model_cards.load_card(name, self.models_dir)
        except Exception as exc:                                       # unreadable / not in the manifest
            self.problems[name] = f"model card unreadable: {type(exc).__name__}"
            return None
        problem = model_cards.validate_card(card, expected_version=URL_FEATURE_SCHEMA_VERSION, expected_names=FEATURE_NAMES)
        self.cards[name] = card
        if problem:
            self.problems[name] = problem
            return None
        return card

    def load(self, models_dir: Optional[Path] = None) -> None:
        """Load every component that is intact and consistent; record why any other one was left out."""
        self.models_dir = Path(models_dir) if models_dir else default_models_dir()
        self.problems.clear()
        self.cards.clear()
        base = self.models_dir
        # ── trees ──
        try:
            if self._card("url_xgb") is not None:
                for f in ("url_xgb.ubj", "url_xgb_calibration.json"):
                    verify_artifact(base / f)
                model = xgb.XGBClassifier()
                model.load_model(str(base / "url_xgb.ubj"))
                cal = json.loads((base / "url_xgb_calibration.json").read_text(encoding="utf-8"))
                self._xgb_cal = calibrator_from_dict(cal["calibrator"])
                self._thresholds = {"fpr_1pct": float(cal["threshold_fpr_1pct"]), "recall_95": float(cal["threshold_recall_95"])}
                self._booster = model
        except Exception as exc:
            self._booster = None
            self.problems.setdefault("url_xgb", f"{type(exc).__name__}: {exc}")
        # ── CNN ──
        try:
            if (base / "url_cnn.pt").exists() and self._card("url_cnn") is not None:
                self._cnn.load(base / "url_cnn.pt", base / "url_cnn_calibration.json")
        except Exception as exc:
            self.problems.setdefault("url_cnn", f"{type(exc).__name__}: {exc}")
        # ── baseline calibrator + fusion ──
        try:
            if (base / "url_fusion.json").exists():
                verify_artifact(base / "url_fusion.json")
                verify_artifact(base / "url_baseline_calibration.json")
                self._fusion = StackedFusion.from_dict(json.loads((base / "url_fusion.json").read_text(encoding="utf-8")))
                self._baseline_cal = calibrator_from_dict(json.loads((base / "url_baseline_calibration.json").read_text(encoding="utf-8"))["calibrator"])
        except Exception as exc:
            self._fusion = self._baseline_cal = None
            self.problems["url_fusion"] = f"{type(exc).__name__}: {exc}"
        if self.problems:
            logger.warning("URL risk components left out: %s", self.problems)

    @property
    def cnn_loaded(self) -> bool:
        return self._cnn.is_loaded

    @property
    def fusion_loaded(self) -> bool:
        return self._fusion is not None

    def band(self, score: Optional[float]) -> str:
        """Low / Medium / High / Critical from the tree model's *operating points* (not arbitrary quartiles):
        below the score that still catches 95 % of phishing → Low; up to the score that keeps false positives ≤ 1 % →
        Medium; above that → High; ≥ 0.9 → Critical. ``Unknown`` for no score."""
        if score is None:
            return "Unknown"
        lo, hi = sorted((self._thresholds.get("recall_95", 0.25), self._thresholds.get("fpr_1pct", 0.5)))
        if score < lo:
            return "Low"
        if score < hi:
            return "Medium"
        return "Critical" if score >= 0.9 else "High"

    def health(self) -> dict:
        return {
            "url_xgb": model_cards.summary(self.cards.get("url_xgb"), self.problems.get("url_xgb")) if self.loaded or "url_xgb" in self.problems else {"status": "disabled", "reason": "not loaded"},
            "url_cnn": ({"status": "ok", **{k: v for k, v in model_cards.summary(self.cards.get("url_cnn"), None).items() if k != "status"}}
                        if self._cnn.is_loaded else {"status": "disabled", "reason": self.problems.get("url_cnn", "not loaded")}),
            "url_fusion": {"status": "ok" if self._fusion else "disabled", "reason": self.problems.get("url_fusion")},
        }

    # ── scoring ────────────────────────────────────────────────────────
    def assess(self, url: str, explain: bool = True) -> tuple[UrlRiskAssessment, list[RiskExplanation], list[NeuralExplanation]]:
        """Score one URL. Raises ``RuntimeError`` if the tree model is not loaded (callers report ``model_not_loaded``).

        ``explain=False`` (the fast tier) skips the SHAP evidence and the CNN saliency spans: scores only."""
        if not self.loaded:
            raise RuntimeError("URL model is not loaded")
        feats = extract_url_features(url)
        row = np.array([[feats[n] for n in FEATURE_NAMES]], dtype=np.float32)
        with self._lock:
            # TreeSHAP computed by XGBoost itself (``pred_contribs``): the same exact algorithm as ``shap.TreeExplainer`` but
            # additive *by construction* (sum of contributions + bias = the raw margin), with nothing to build per request.
            contribs = self._booster.get_booster().predict(xgb.DMatrix(row, feature_names=list(FEATURE_NAMES)), pred_contribs=True)[0]
        contrib, base = np.asarray(contribs[:-1], dtype=np.float64), float(contribs[-1])
        margin = float(base + contrib.sum())
        raw = float(_sigmoid(margin))
        calibrated = float(self._xgb_cal(np.array([raw]))[0])
        explanations = self._evidence(feats, contrib, margin, calibrated) if explain else []

        cnn_raw = cnn_cal = None
        neural: list[NeuralExplanation] = []
        if self._cnn.is_loaded:
            cnn_raw = self._cnn.predict_proba(url)
            cnn_cal = self._cnn.predict_calibrated(url)
            neural = self._cnn.explain_url(url) if explain else []
        base_raw = url_baseline_score(feats)
        base_cal = float(self._baseline_cal(np.array([base_raw]))[0]) if self._baseline_cal is not None else None
        fused = self._fusion.predict({"xgb": calibrated, "cnn": cnn_cal, "baseline": base_cal}) if self._fusion else None
        fused_contrib = ({k: round(v, 4) for k, v in self._fusion.contributions({"xgb": calibrated, "cnn": cnn_cal, "baseline": base_cal}).items()}
                         if self._fusion else {})

        headline = fused if fused is not None else calibrated
        notes = [
            "This scores the URL text only — not the page, its owner or its reputation.",
            "Probabilities are calibrated on data that is about half phishing; real traffic has far less, so the same score "
            "means less. See at_prevalence.",
        ]
        card = self.cards.get("url_xgb") or {}
        assessment = UrlRiskAssessment(
            applicable=True, score=calibrated, raw_score=raw, cnn_score=cnn_cal, baseline_score=base_cal, fused_score=fused,
            fusion_contributions=fused_contrib, headline_score=headline, flagged=headline >= self._flag_threshold(fused is not None),
            threshold=self._flag_threshold(fused is not None), threshold_basis="false-positive rate ≤ 1 % on validation data",
            at_prevalence={f"{p * 100:g}%": round(float(prior_shift([headline], self._val_prevalence(), p)[0]), 5) for p in PREVALENCES},
            baseline_terms=[UrlRiskTerm(text=t, weight=w) for t, w in url_baseline_terms(feats)],
            model_name="url_xgb", model_version=str(card.get("version", "unknown")), notes=notes)
        return assessment, explanations, neural

    def _flag_threshold(self, fused: bool) -> float:
        card = self.cards.get("url_fusion") or {}
        if fused and isinstance(card.get("threshold"), (int, float)):
            return float(card["threshold"])
        return self._thresholds.get("fpr_1pct", 0.5)

    def _val_prevalence(self) -> float:
        card = self.cards.get("url_xgb") or {}
        return float((card.get("calibration") or {}).get("validation_prevalence", 0.5))

    def _evidence(self, feats: dict, contrib: np.ndarray, margin: float, calibrated: float) -> list[RiskExplanation]:
        out = []
        for name, phi in zip(FEATURE_NAMES, contrib):
            label, fmt = FEATURE_TEXT[name]
            value = feats[name]
            without = float(self._xgb_cal(np.array([_sigmoid(margin - float(phi))]))[0])
            delta = calibrated - without
            direction = "raises" if phi > 0 else "lowers"
            out.append(RiskExplanation(
                feature_name=name, feature_value=float(value), shap_value=float(phi), unit="log-odds",
                probability_delta=round(delta, 5), group=FEATURE_GROUPS[name],
                human_readable=f"{label}: {fmt(value)} — {direction} the score by {abs(phi):.2f} log-odds"))
        out.sort(key=lambda e: abs(e.shap_value), reverse=True)
        return out
