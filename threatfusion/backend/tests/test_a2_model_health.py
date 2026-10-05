"""A2-2 / A2-3 / A2-5 / A2-6 — the shipped URL models are healthy, invariant, explainable and carded.

The audit's model gave **one output value over 20,000 inputs**, used 3 of 19 features and flipped from 0.13 to 0.99 when only
``https://`` was prepended.  These tests run against the *shipped* artifacts in ``ml/models`` and would fail on that model:

* output variance over a grid of URLs is far above a threshold, and the outputs are many distinct values;
* a minimum number of features is actually used in the trees;
* the model card's feature schema equals the code's (a mismatch **disables** the model);
* monotone sanity: more evidence of impersonation never lowers the score (enforced in the trees via ``monotone_constraints``);
* scheme / ``www`` invariance within 0.02 for every learned channel;
* SHAP: additivity (``bias + Σ contributions = margin``), units stated, no explainer constructed per request;
* the calibrator is monotone and in [0, 1]; the card carries metrics with confidence intervals and none of them is exactly 1.0.
"""

from __future__ import annotations

import itertools
import json
import shutil

import numpy as np
import pytest
import xgboost as xgb

from app.core.artifacts import default_models_dir
from app.ml import model_cards
from app.ml.url_features import FEATURE_NAMES, URL_FEATURE_SCHEMA_VERSION, extract_url_features
from app.ml.url_risk import UrlRiskService

HOSTS = ["example.com", "secure-login.account-verify.top", "paypa1-secure.com", "paypal.com.signin-update.info", "hdfcbank-netbanking.in",
         "my-blog.wordpress.com", "xk3j9d2.vercel.app", "203.0.113.9", "login.microsoftonline.com", "en.wikipedia.org", "shop.example.co.uk",
         "a.b.c.d.example.net", "uidai-aadhaar-verify.com", "github.com", "news.bbc.co.uk", "irctc-refund.in"]
PATHS = ["", "/", "/login", "/verify/account?id=42", "/wiki/Cat", "/a/b/c/d/e/f", "/signin.php?redirect=http://evil.example/x", "/checkout/cart"]


@pytest.fixture(scope="module")
def service() -> UrlRiskService:
    svc = UrlRiskService()
    svc.load()
    return svc


def grid_urls() -> list[str]:
    return [f"https://{h}{p}" for h, p in itertools.product(HOSTS, PATHS)]


def test_the_shipped_models_load_with_valid_cards(service) -> None:
    assert service.loaded, service.problems
    assert not service.problems, service.problems
    health = service.health()
    assert health["url_xgb"]["status"] == "ok" and health["url_cnn"]["status"] == "ok" and health["url_fusion"]["status"] == "ok"


def test_the_output_varies_over_a_grid_of_inputs(service) -> None:
    """The audited model returned a single value for 20,000 inputs; this one must spread its answers."""
    assessments = [service.assess(u)[0] for u in grid_urls()]
    scores = np.array([a.score for a in assessments])
    raw = np.array([a.raw_score for a in assessments])
    assert len(scores) == len(HOSTS) * len(PATHS)
    assert scores.std() > 0.15, f"std {scores.std():.3f}"
    # (the calibrated score is a monotone step-like map, so distinctness is checked on the raw model output)
    assert len(np.unique(raw.round(6))) > 80, "the model collapsed onto a handful of values"
    assert scores.min() < 0.3 and scores.max() > 0.9, "both ends of the range are used"


def test_enough_features_are_used_in_the_trees(service) -> None:
    used = service._booster.get_booster().get_score(importance_type="gain")
    assert len(used) >= 20, f"only {len(used)} of {len(FEATURE_NAMES)} features are used"


def test_the_card_schema_matches_the_code_and_a_mismatch_disables_the_model(service, tmp_path) -> None:
    card = service.cards["url_xgb"]
    assert card["feature_schema"]["version"] == URL_FEATURE_SCHEMA_VERSION and card["feature_schema"]["names"] == FEATURE_NAMES
    assert model_cards.validate_card(card, expected_version=URL_FEATURE_SCHEMA_VERSION, expected_names=FEATURE_NAMES) is None
    assert "schema version" in model_cards.validate_card(card, expected_version=URL_FEATURE_SCHEMA_VERSION + 1, expected_names=FEATURE_NAMES)
    assert "names" in model_cards.validate_card(card, expected_version=URL_FEATURE_SCHEMA_VERSION, expected_names=FEATURE_NAMES[::-1])
    assert model_cards.validate_card(None, expected_version=1, expected_names=[]) == "no model card"
    assert "missing" in model_cards.validate_card({"name": "x"}, expected_version=1, expected_names=[])
    # a tampered card in a copy of the model directory: the SHA-256 manifest refuses it and the model stays disabled
    copy = tmp_path / "models"
    shutil.copytree(default_models_dir(), copy)
    tampered = json.loads((copy / "url_xgb.card.json").read_text())
    tampered["feature_schema"]["version"] = 99
    (copy / "url_xgb.card.json").write_text(json.dumps(tampered))
    svc = UrlRiskService()
    svc.load(copy)
    assert not svc.loaded and "url_xgb" in svc.problems
    with pytest.raises(RuntimeError):
        svc.assess("https://example.com")


def test_monotone_sanity_more_impersonation_evidence_never_lowers_the_score(service) -> None:
    """Enforced inside the trees by monotone_constraints, so this must hold for every base row."""
    rows = np.array([[extract_url_features(u)[n] for n in FEATURE_NAMES] for u in grid_urls()], dtype=np.float32)
    booster = service._booster
    for name, direction in (("lookalike_flagged", 1), ("lookalike_score", 1), ("brand_keyword", 1), ("brand_in_subdomain", 1),
                            ("host_has_userinfo", 1), ("host_mixed_script", 1), ("is_official_domain", -1)):
        i = FEATURE_NAMES.index(name)
        lo, hi = rows.copy(), rows.copy()
        lo[:, i], hi[:, i] = 0.0, 1.0
        diff = booster.predict_proba(hi)[:, 1] - booster.predict_proba(lo)[:, 1]
        assert (direction * diff >= -1e-6).all(), f"{name} is not monotone ({direction * diff.min():.4f})"
    # and the whole point: look-alikes score higher than their genuine counterparts
    assert service.assess("https://paypa1-secure.com/signin")[0].score > service.assess("https://www.paypal.com/signin")[0].score


@pytest.mark.parametrize("url", ["https://www.secure-login.account-verify.top/verify/account?id=42", "https://example.com/wiki/Cat",
                                 "https://paypa1-secure.com/signin", "https://xk3j9d2.vercel.app/", "http://203.0.113.9/login.php",
                                 "https://github.com/python/cpython", "https://irctc-refund.in/claim"])
def test_scores_are_scheme_and_www_invariant_within_two_points(service, url) -> None:
    """The audit saw 0.13 -> 0.99 from a prepended https://. Canonicalisation makes every channel blind to it."""
    bare = url.split("://", 1)[1].removeprefix("www.")
    variants = [url, "http://" + bare, "https://www." + bare, bare, "HTTPS://" + bare.upper().split("/", 1)[0] + (("/" + bare.split("/", 1)[1]) if "/" in bare else "")]
    results = [service.assess(v)[0] for v in variants]
    for field in ("score", "cnn_score", "fused_score", "headline_score"):
        vals = [getattr(r, field) for r in results]
        assert max(vals) - min(vals) <= 0.02, (field, vals)


def test_shap_contributions_are_additive_in_log_odds(service) -> None:
    for url in grid_urls()[::9]:
        _, explanations, _ = service.assess(url)
        feats = extract_url_features(url)
        row = np.array([[feats[n] for n in FEATURE_NAMES]], dtype=np.float32)
        booster = service._booster.get_booster()
        dm = xgb.DMatrix(row, feature_names=list(FEATURE_NAMES))
        margin = float(booster.predict(dm, output_margin=True)[0])
        bias = float(booster.predict(dm, pred_contribs=True)[0][-1])
        assert bias + sum(e.shap_value for e in explanations) == pytest.approx(margin, abs=1e-4), url
        assert all(e.unit == "log-odds" and "log-odds" in e.human_readable for e in explanations)
        assert [abs(e.shap_value) for e in explanations] == sorted((abs(e.shap_value) for e in explanations), reverse=True)


def test_no_explainer_is_constructed_per_request(service, monkeypatch) -> None:
    import shap

    def boom(*a, **k):
        raise AssertionError("a SHAP explainer was constructed during a request")

    monkeypatch.setattr(shap, "TreeExplainer", boom)
    service.assess("https://example.com/a")
    service.assess("https://paypa1-secure.com/b")


def test_evidence_cards_state_the_probability_effect_and_the_group(service) -> None:
    _, explanations, _ = service.assess("https://paypa1-secure.com/signin")
    top = explanations[0]
    assert top.probability_delta is not None and top.group in {"surface", "host", "path", "risk", "brand"}
    assert any(e.group == "brand" and e.shap_value > 0 for e in explanations), "the look-alike evidence raises the score"


def test_probabilities_are_in_range_and_the_prevalence_caveat_is_present(service) -> None:
    a, _, _ = service.assess("https://paypa1-secure.com/signin")
    for v in (a.score, a.cnn_score, a.fused_score, a.baseline_score, a.headline_score):
        assert v is not None and 0.0 <= v <= 1.0
    assert a.at_prevalence["1%"] < a.headline_score and a.at_prevalence["0.1%"] < a.at_prevalence["1%"]
    assert any("only" in n or "text" in n for n in a.notes) and a.threshold_basis


def test_the_cards_carry_honest_metrics_with_intervals(service) -> None:
    for name in ("url_xgb", "url_cnn", "url_fusion"):
        card = service.cards.get(name) or model_cards.load_card(name)
        test = card["metrics"]["test"]
        for metric in ("pr_auc", "roc_auc", "f1", "brier", "ece"):
            assert metric in test and metric in test["ci95"], (name, metric)
            lo, hi = test["ci95"][metric]
            assert lo <= test[metric] <= hi or metric in ("ece", "f1"), (name, metric)
        assert test["pr_auc"] < 1.0 and test["roc_auc"] < 1.0 and test["f1"] < 1.0, "a perfect metric is a leak, not a result"
        assert card["limitations"] and card["data"]["dataset_sha256"] and "host-disjoint" in card["data"]["splits"]
