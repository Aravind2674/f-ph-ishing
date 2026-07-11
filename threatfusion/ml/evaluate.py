"""ThreatFusion Model Evaluation Script

Benchmarks the ML fusion model against the old v1 model and the rule-based baseline heuristic
on a test set. This script produces the core research result
that answers the project's research question.

Outputs:
- Precision, Recall, F1, ROC-AUC for both models side by side
- Comparison chart saved to ml/results/comparison_chart.png
- Metrics table saved to ml/results/evaluation_metrics.json

Usage:
    python -m ml.evaluate
"""

import json
import logging
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve
)

from ml.train import generate_synthetic_data
from app.ml.baseline import baseline_score
from app.models.schemas import FeatureVector
from app.ml.fusion_model import FusionModel

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

RESULTS_DIR = Path("ml/results")
CHART_PATH = RESULTS_DIR / "comparison_chart.png"
METRICS_PATH = RESULTS_DIR / "evaluation_metrics.json"
MODEL_V2_PATH = Path("ml/models/fusion_model.json")
MODEL_V1_PATH = Path("ml/models/fusion_model_v1_baseline.json")


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    
    logger.info("Loading ML Fusion Models...")
    
    # Load V2
    model_v2 = FusionModel()
    try:
        model_v2.load(MODEL_V2_PATH)
    except FileNotFoundError:
        logger.error(f"Model not found at {MODEL_V2_PATH}")
        return
        
    # Load V1 directly via XGBoost to avoid schema mismatches
    model_v1 = None
    if MODEL_V1_PATH.exists():
        model_v1 = xgb.XGBClassifier()
        model_v1.load_model(str(MODEL_V1_PATH))
    else:
        logger.warning(f"V1 Model not found at {MODEL_V1_PATH}")
        
    logger.info("Generating evaluation dataset...")
    df = generate_synthetic_data(2000)
    y_true = df["label"].values
    
    # Define old feature list
    old_features = [
        "vt_malicious_ratio", "vt_suspicious_ratio", "vt_reputation_score",
        "vt_last_seen_days_ago", "shodan_open_port_count", "shodan_has_high_risk_port",
        "shodan_cve_count", "shodan_max_cvss_score", "tech_count",
        "tech_has_known_eol_component", "tech_avg_confidence", "ssl_cert_valid",
        "domain_age_days"
    ]
    
    logger.info("Running inference...")
    
    ml_preds_v2 = []
    ml_probs_v2 = []
    
    ml_preds_v1 = []
    ml_probs_v1 = []
    
    baseline_probs = []
    
    feature_cols = [c for c in df.columns if c != "label"]
    
    # For V1 inference
    X_v1 = df[old_features].values if model_v1 else None
    if model_v1:
        ml_preds_v1 = model_v1.predict(X_v1)
        ml_probs_v1 = model_v1.predict_proba(X_v1)[:, 1]
    
    for _, row in df.iterrows():
        row_dict = row[feature_cols].to_dict()
        vec = FeatureVector(**row_dict)
        
        # ML Inference V2
        ml_preds_v2.append(model_v2.predict(vec))
        ml_probs_v2.append(model_v2.predict_proba(vec))
        
        # Baseline Heuristic
        baseline_probs.append(baseline_score(vec))
        
    ml_preds_v2 = np.array(ml_preds_v2)
    ml_probs_v2 = np.array(ml_probs_v2)
    baseline_probs = np.array(baseline_probs)
    
    # Calibrated threshold based on empirical malicious score averages
    baseline_preds = (baseline_probs >= 0.3).astype(int)
    
    logger.info("Calculating comparative metrics...")
    metrics = {
        "ML_Model_V2": {
            "accuracy": float(accuracy_score(y_true, ml_preds_v2)),
            "precision": float(precision_score(y_true, ml_preds_v2)),
            "recall": float(recall_score(y_true, ml_preds_v2)),
            "f1": float(f1_score(y_true, ml_preds_v2)),
            "roc_auc": float(roc_auc_score(y_true, ml_probs_v2))
        }
    }
    
    if model_v1:
        metrics["ML_Model_V1"] = {
            "accuracy": float(accuracy_score(y_true, ml_preds_v1)),
            "precision": float(precision_score(y_true, ml_preds_v1)),
            "recall": float(recall_score(y_true, ml_preds_v1)),
            "f1": float(f1_score(y_true, ml_preds_v1)),
            "roc_auc": float(roc_auc_score(y_true, ml_probs_v1))
        }
        
    metrics["Baseline_Heuristic"] = {
        "accuracy": float(accuracy_score(y_true, baseline_preds)),
        "precision": float(precision_score(y_true, baseline_preds)),
        "recall": float(recall_score(y_true, baseline_preds)),
        "f1": float(f1_score(y_true, baseline_preds)),
        "roc_auc": float(roc_auc_score(y_true, baseline_probs))
    }
    
    logger.info("Metrics:\n%s", json.dumps(metrics, indent=2))
    
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    logger.info("Metrics saved to %s", METRICS_PATH)
        
    logger.info("Plotting ROC curve comparison...")
    
    fpr_ml2, tpr_ml2, _ = roc_curve(y_true, ml_probs_v2)
    fpr_bl, tpr_bl, _ = roc_curve(y_true, baseline_probs)
    
    plt.figure(figsize=(8, 6))
    
    plt.plot(
        fpr_ml2, tpr_ml2, 
        label=f"ML V2 (AUC = {metrics['ML_Model_V2']['roc_auc']:.3f})", 
        color="#2563eb",  
        linewidth=2.5
    )
    
    if model_v1:
        fpr_ml1, tpr_ml1, _ = roc_curve(y_true, ml_probs_v1)
        plt.plot(
            fpr_ml1, tpr_ml1, 
            label=f"ML V1 (AUC = {metrics['ML_Model_V1']['roc_auc']:.3f})", 
            color="#059669",  # green
            linewidth=2.5
        )
        
    plt.plot(
        fpr_bl, tpr_bl, 
        label=f"Baseline (AUC = {metrics['Baseline_Heuristic']['roc_auc']:.3f})", 
        color="#dc2626",  
        linestyle="--", 
        linewidth=2.5
    )
    
    plt.plot([0, 1], [0, 1], color="#9ca3af", linestyle=":", linewidth=2)
    
    plt.title("ROC Curve: ML Fusion vs. Baseline Heuristic", fontsize=14, pad=15)
    plt.xlabel("False Positive Rate", fontsize=12)
    plt.ylabel("True Positive Rate", fontsize=12)
    plt.legend(loc="lower right", fontsize=11, frameon=True)
    plt.grid(True, alpha=0.3, linestyle="--")
    plt.tight_layout()
    
    plt.savefig(CHART_PATH, dpi=300)
    logger.info("Comparison chart saved to %s", CHART_PATH)
    logger.info("Evaluation complete!")


if __name__ == "__main__":
    main()
