"""
ThreatFusion – SHAP Explainability Module
==========================================

Generates **per‑feature risk attributions** for the fusion model's
predictions using `SHAP (SHapley Additive exPlanations)
<https://shap.readthedocs.io/>`_.

Why SHAP?
---------
1. **Theoretically grounded** – SHAP values are the unique solution
   satisfying local accuracy, missingness, and consistency (the three
   Shapley axioms).  This is strong ground to stand on in a viva.
2. **Model‑agnostic API, tree‑optimised backend** – we use
   ``shap.TreeExplainer`` which computes *exact* Shapley values for
   tree ensembles in polynomial time (vs. exponential for the general
   case).
3. **Human‑readable output** – each SHAP value maps directly to a
   named feature, so we can generate explanations like "Open RDP port
   increased risk by +0.31".

The output is a list of ``RiskExplanation`` objects, sorted by absolute
SHAP value (most influential feature first), ready for the frontend's
waterfall chart.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import shap

from app.models.schemas import FeatureVector, RiskExplanation

if TYPE_CHECKING:
    from app.ml.fusion_model import FusionModel

logger = logging.getLogger(__name__)


def explain_prediction(
    model: FusionModel,
    features: FeatureVector,
) -> list[RiskExplanation]:
    """Generate SHAP‑based explanations for a single prediction.

    Parameters
    ----------
    model : FusionModel
        A loaded ``FusionModel`` instance (must have ``is_loaded == True``).
    features : FeatureVector
        The 13‑dimensional feature vector that was scored.

    Returns
    -------
    list[RiskExplanation]
        One entry per feature, sorted by absolute SHAP value descending.
        Positive ``shap_value`` means the feature **increased** the
        predicted risk; negative means it **decreased** the risk.

    Raises
    ------
    RuntimeError
        If ``model.is_loaded`` is ``False``.
    """
    if not model.is_loaded:
        raise RuntimeError("Model is not loaded. Cannot generate SHAP explanations.")

    # TreeExplainer is extremely fast for XGBoost
    explainer = shap.TreeExplainer(model._model)
    feature_array = model.feature_vector_to_array(features)
    
    # Compute SHAP values. 
    # For a binary XGBoost classifier, SHAP values typically represent the log-odds margin.
    shap_vals = explainer.shap_values(feature_array)
    
    # Handle SHAP versions where it returns a list of arrays (one per class)
    if isinstance(shap_vals, list):
        shap_vals = shap_vals[1]  # Get values for the positive (malicious) class
        
    # We are explaining a single instance
    local_shap = shap_vals[0]
    
    explanations = []
    for name, shap_val in zip(type(features).model_fields.keys(), local_shap):
        feat_val = getattr(features, name)
        explanations.append(RiskExplanation(
            feature_name=name,
            feature_value=None if feat_val is None else float(feat_val),
            shap_value=float(shap_val),
            human_readable=_format_explanation(name, feat_val, shap_val),
        ))

    # Sort by absolute impact (most influential first)
    explanations.sort(key=lambda e: abs(e.shap_value), reverse=True)
    return explanations


def _format_explanation(
    feature_name: str,
    feature_value: float,
    shap_value: float,
) -> str:
    """Convert a raw SHAP attribution into a human‑readable sentence."""
    templates = {
        "vt_malicious_ratio": "AV engine malicious detection ratio is {val:.0%}",
        "vt_suspicious_ratio": "AV engine suspicious detection ratio is {val:.0%}",
        "vt_reputation_score": "VirusTotal community reputation score is {val:.2f} (0=bad, 1=good)",
        "vt_last_seen_days_ago": "Last scanned by VirusTotal {val:.0f} days ago",
        "shodan_open_port_count": "{val:.0f} open ports exposed to the internet",
        "shodan_has_high_risk_port": "High-risk port (RDP/SMB/Telnet) is open",
        "shodan_cve_count": "{val:.0f} known vulnerabilities (CVEs) found",
        "shodan_max_cvss_score": "Highest vulnerability CVSS score is {val:.1f}",
        "tech_count": "{val:.0f} web technologies identified",
        "tech_has_known_eol_component": "End-of-Life (unsupported) technology component detected",
        "tech_avg_confidence": "Average technology detection confidence is {val:.0%}",
        "ssl_cert_valid": "SSL/TLS certificate is valid",
        "domain_age_days": "Domain age is {val:.0f} days",
    }
    
    if feature_value is None:  # provider did not answer / no real signal: say so, don't invent
        sign = "+" if shap_value > 0 else ""
        return f"{feature_name.replace('_', ' ')} is unavailable (unknown) ({sign}{shap_value:.2f} risk)"

    # For binary flags, we can make the language more natural if they are false (0.0)
    if feature_value == 0.0:
        if feature_name == "shodan_has_high_risk_port":
            base_text = "No high-risk ports exposed"
        elif feature_name == "tech_has_known_eol_component":
            base_text = "No end-of-life technologies detected"
        elif feature_name == "ssl_cert_valid":
            base_text = "SSL/TLS certificate is invalid or missing"
        else:
            template = templates.get(feature_name, f"Feature {feature_name} has value {{val}}")
            base_text = template.format(val=feature_value)
    else:
        template = templates.get(feature_name, f"Feature {feature_name} has value {{val}}")
        base_text = template.format(val=feature_value)

    # Append the directional impact
    if shap_value > 0:
        impact = f"(+{shap_value:.2f} risk)"
    else:
        impact = f"({shap_value:.2f} risk)"
        
    return f"{base_text} {impact}"
