"""ThreatFusion ML Model Training Script

Trains the XGBoost fusion model on synthesized labeled data and saves
the trained model artifact. This script is designed to be run once
(or periodically retrained) and produces:
- ml/models/fusion_model.json — the serialized trained model
- ml/models/training_metrics.json — training performance metrics

Usage:
    python -m ml.train

The training data is synthesized from:
- Known-malicious domains (URLhaus, PhishTank open lists)
- Known-benign domains (top Tranco list entries)

This is documented as a limitation — see docs/ARCHITECTURE.md.
"""

import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Output paths
MODELS_DIR = Path("ml/models")
MODEL_PATH = MODELS_DIR / "fusion_model.json"
METRICS_PATH = MODELS_DIR / "training_metrics.json"

def generate_synthetic_data(n_samples: int = 10000) -> pd.DataFrame:
    """Generate synthetic feature vectors for training.
    Half benign (label=0), half malicious (label=1).
    """
    logger.info("Generating %d synthetic samples...", n_samples)
    np.random.seed(42)
    
    n_malicious = n_samples // 2
    n_benign = n_samples - n_malicious
    
    # Feature columns matching FeatureVector in schemas.py precisely
    columns = [
        "vt_malicious_ratio", "vt_suspicious_ratio", "vt_reputation_score",
        "vt_last_seen_days_ago", "shodan_open_port_count", "shodan_has_high_risk_port",
        "shodan_cve_count", "shodan_max_cvss_score", "shodan_has_iot_tag",
        "shodan_has_compromised_tag", "shodan_service_diversity_score",
        "shodan_high_risk_cpe_count", "tech_count",
        "tech_has_known_eol_component", "tech_avg_confidence",
        "tech_stack_diversity_count", "tech_has_eol_cms_version",
        "ssl_cert_valid", "domain_age_days"
    ]
    
    # Benign Profile (with overlap)
    benign = pd.DataFrame(index=range(n_benign), columns=columns)
    benign["vt_malicious_ratio"] = np.random.uniform(0.0, 0.3, n_benign)
    benign["vt_suspicious_ratio"] = np.random.uniform(0.0, 0.4, n_benign)
    benign["vt_reputation_score"] = np.random.uniform(0.2, 1.0, n_benign)
    benign["vt_last_seen_days_ago"] = np.random.uniform(0.0, 100.0, n_benign)
    benign["shodan_open_port_count"] = np.random.poisson(3.0, n_benign).astype(float)
    benign["shodan_has_high_risk_port"] = np.random.choice([0.0, 1.0], p=[0.8, 0.2], size=n_benign)
    benign["shodan_cve_count"] = np.random.poisson(1.0, n_benign).astype(float)
    benign["shodan_max_cvss_score"] = np.where(benign["shodan_cve_count"] > 0, np.random.uniform(2.0, 8.0, n_benign), 0.0)
    benign["shodan_has_iot_tag"] = np.random.choice([0.0, 1.0], p=[0.8, 0.2], size=n_benign)
    benign["shodan_has_compromised_tag"] = np.random.choice([0.0, 1.0], p=[0.9, 0.1], size=n_benign)
    benign["shodan_service_diversity_score"] = np.random.poisson(2.0, n_benign).astype(float)
    benign["shodan_high_risk_cpe_count"] = np.random.poisson(0.5, n_benign).astype(float)
    benign["tech_count"] = np.random.poisson(6.0, n_benign).astype(float)
    benign["tech_has_known_eol_component"] = np.random.choice([0.0, 1.0], p=[0.7, 0.3], size=n_benign)
    benign["tech_avg_confidence"] = np.random.uniform(0.6, 1.0, n_benign)
    benign["tech_stack_diversity_count"] = np.random.poisson(3.0, n_benign).astype(float)
    benign["tech_has_eol_cms_version"] = np.random.choice([0.0, 1.0], p=[0.85, 0.15], size=n_benign)
    benign["ssl_cert_valid"] = np.random.choice([1.0, 0.0], p=[0.8, 0.2], size=n_benign)
    benign["domain_age_days"] = np.random.uniform(100, 3650, n_benign)
    benign["label"] = 0
    
    # Malicious Profile (with overlap)
    mal = pd.DataFrame(index=range(n_malicious), columns=columns)
    mal["vt_malicious_ratio"] = np.random.uniform(0.0, 0.8, n_malicious)
    mal["vt_suspicious_ratio"] = np.random.uniform(0.0, 0.6, n_malicious)
    mal["vt_reputation_score"] = np.random.uniform(0.0, 0.8, n_malicious)
    mal["vt_last_seen_days_ago"] = np.random.uniform(0.0, 365.0, n_malicious)
    mal["shodan_open_port_count"] = np.random.poisson(4.0, n_malicious).astype(float)
    mal["shodan_has_high_risk_port"] = np.random.choice([0.0, 1.0], p=[0.6, 0.4], size=n_malicious)
    mal["shodan_cve_count"] = np.random.poisson(2.0, n_malicious).astype(float)
    mal["shodan_max_cvss_score"] = np.where(mal["shodan_cve_count"] > 0, np.random.uniform(4.0, 10.0, n_malicious), 0.0)
    mal["shodan_has_iot_tag"] = np.random.choice([0.0, 1.0], p=[0.6, 0.4], size=n_malicious)
    mal["shodan_has_compromised_tag"] = np.random.choice([0.0, 1.0], p=[0.7, 0.3], size=n_malicious)
    mal["shodan_service_diversity_score"] = np.random.poisson(3.0, n_malicious).astype(float)
    mal["shodan_high_risk_cpe_count"] = np.random.poisson(1.0, n_malicious).astype(float)
    mal["tech_count"] = np.random.poisson(8.0, n_malicious).astype(float)
    mal["tech_has_known_eol_component"] = np.random.choice([0.0, 1.0], p=[0.6, 0.4], size=n_malicious)
    mal["tech_avg_confidence"] = np.random.uniform(0.4, 0.9, n_malicious)
    mal["tech_stack_diversity_count"] = np.random.poisson(3.0, n_malicious).astype(float)
    mal["tech_has_eol_cms_version"] = np.random.choice([0.0, 1.0], p=[0.7, 0.3], size=n_malicious)
    mal["ssl_cert_valid"] = np.random.choice([1.0, 0.0], p=[0.6, 0.4], size=n_malicious)
    mal["domain_age_days"] = np.random.uniform(1.0, 1000.0, n_malicious)
    mal["label"] = 1
    
    # Introduce explicit label noise (flip 15% of labels)
    flip_idx_benign = np.random.choice(benign.index, size=int(n_benign * 0.15), replace=False)
    benign.loc[flip_idx_benign, "label"] = 1
    
    flip_idx_mal = np.random.choice(mal.index, size=int(n_malicious * 0.15), replace=False)
    mal.loc[flip_idx_mal, "label"] = 0

    
    # Combine and shuffle
    df = pd.concat([benign, mal]).sample(frac=1, random_state=42).reset_index(drop=True)
    return df

def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    df = generate_synthetic_data(10000)
    X = df.drop(columns=["label"])
    y = df["label"]
    
    # Ensure column order matches the Pydantic schema precisely
    feature_names = list(X.columns)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    logger.info("Training XGBoost classifier...")
    # Fast, small model for real-time inference
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        objective="binary:logistic",
        random_state=42,
        eval_metric="logloss"
    )
    
    model.fit(X_train, y_train)
    
    # Evaluation
    logger.info("Evaluating model...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
        "feature_names": feature_names
    }
    
    logger.info("Metrics: %s", metrics)
    
    # Save model and metrics
    model.save_model(str(MODEL_PATH))
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
        
    logger.info("Model saved to %s", MODEL_PATH)
    logger.info("Metrics saved to %s", METRICS_PATH)

if __name__ == "__main__":
    main()
