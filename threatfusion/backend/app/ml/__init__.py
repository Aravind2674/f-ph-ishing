"""
ThreatFusion – Machine Learning Layer
======================================

This package contains the **ML pipeline** that transforms raw,
multi‑source threat‑intelligence data into a single risk score with
SHAP‑based explanations.

Sub‑modules
-----------
* ``features``      – Feature engineering: raw source data → ``FeatureVector``.
* ``baseline``      – Deterministic rule‑based scorer (no training needed).
                      Serves as a sanity‑check baseline and a fallback when
                      the trained model is unavailable.
* ``fusion_model``  – Gradient‑boosted (XGBoost) fusion model that learns
                      non‑linear interactions across data sources.
* ``explain``       – SHAP TreeExplainer wrapper that produces per‑feature
                      risk attributions for the fusion model's predictions.

Pipeline flow
-------------
::

    VirusTotalResult ─┐
    ShodanResult ─────┤
    CVEResult ────────┼─→ extract_features() ─→ FeatureVector
    TechFingerprintResult ┘                           │
                                                      ├─→ baseline_score()
                                                      │
                                                      ├─→ FusionModel.predict_proba()
                                                      │         │
                                                      │         └─→ explain_prediction()
                                                      │                    │
                                                      └────────────────────┘
                                                               ↓
                                                         ScanResult
"""
