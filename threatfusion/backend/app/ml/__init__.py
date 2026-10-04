"""
ThreatFusion – Machine Learning Layer
======================================

This package contains the **ML pipeline** that transforms raw,
multi‑source threat‑intelligence data into a single risk score with
SHAP‑based explanations.

Sub‑modules
-----------
* ``features``      – Provider evidence → the 19‑column ``FeatureVector`` (unknown stays ``None``).
* ``baseline``      – Deterministic rule‑based scorer over those provider features (the headline severity).
* ``url_features`` / ``url_canon`` – URL‑string features and the one canonical URL form (scheme/``www`` blind) shared by
                      training and serving.
* ``url_risk``      – The calibrated URL‑text models (tree model + character CNN + transparent lexical baseline) and their
                      stacked fusion, with SHAP evidence; ``runtime`` holds the process‑wide instance, ``model_cards`` the
                      model‑card checks (a schema mismatch disables a model).
* ``calibration`` / ``fusion`` – Isotonic / Platt calibration, noisy‑OR and stacked‑logistic fusion with missingness flags.
* ``brands`` / ``lookalike`` / ``confusables`` – Brand impersonation (B4).  ``exposure`` – exploit‑informed exposure (B11).
* ``vuln_classifier`` / ``payload_norm`` – HTTP attack classifier and its payload normaliser.

Pipeline flow
-------------
::

    providers ──→ extract_features() ──→ FeatureVector ──→ baseline_score()          (maliciousness headline)
    URL text ───→ url_risk.assess()  ──→ calibrated tree / CNN / fusion + SHAP        (URL‑text channel)
    CVEs ───────→ exposure.assess_exposure()                                          (kept apart: exposure)
                                   ↓
                              ScanResult
"""
