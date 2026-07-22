"""ThreatFusion – HTTP Attack Classifier Training  (Phase 2)

Trains the character-level :class:`~app.ml.vuln_classifier.PayloadCNN` on the
**real** Morzeux HttpParamsDataset (CSIC-2010 normal request parameters + real
SQLi / XSS / path-traversal / cmdi attack payloads).

Produces:
- ml/models/vuln_classifier.pt              — trained weights
- ml/models/vuln_classifier_config.json     — architecture + vocab + class names
- ml/models/vuln_classifier_metrics.json    — honest per-class metrics + confusion

Usage:
    python -m ml.train_vuln
    python -m ml.train_vuln --epochs 15

The class distribution is genuinely imbalanced (benign and sqli dominate; xss /
path-traversal / cmdi are rare). We do NOT rebalance by fabricating samples —
instead we weight the loss by inverse class frequency and report per-class
precision/recall/F1 so weak minority-class numbers are visible, not hidden.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, TensorDataset

# Make ``app`` importable when run as ``python -m ml.train_vuln`` from threatfusion/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.ml.vuln_classifier import (  # noqa: E402
    PayloadCNN,
    PayloadCNNConfig,
    build_vocab,
    encode_payload,
    save_checkpoint,
)
from ml.data_sources import build_http_attack_dataset  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = Path("ml/models")
WEIGHTS_PATH = MODELS_DIR / "vuln_classifier.pt"
METRICS_PATH = MODELS_DIR / "vuln_classifier_metrics.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the HTTP attack classifier")
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Data (real) ─────────────────────────────────────────────────────
    payloads, labels, class_names, provenance = build_http_attack_dataset(seed=args.seed)
    y = np.array(labels, dtype=np.int64)
    logger.info("Loaded %d real payloads across %s", len(payloads), class_names)

    config = PayloadCNNConfig(vocab=build_vocab(), class_names=class_names)
    X = np.array(
        [encode_payload(p, config.vocab, config.max_len) for p in payloads], dtype=np.int64
    )

    # Stratified split so rare classes appear in both train and test.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y
    )

    train_loader = DataLoader(
        TensorDataset(torch.tensor(X_train), torch.tensor(y_train)),
        batch_size=args.batch_size, shuffle=True,
    )

    # ── Class weights (inverse frequency) — no fabricated resampling ────
    counts = Counter(y_train.tolist())
    n_classes = len(class_names)
    total = sum(counts.values())
    weights = torch.tensor(
        [total / (n_classes * max(counts.get(i, 0), 1)) for i in range(n_classes)],
        dtype=torch.float32,
    )
    logger.info("Class weights: %s", {class_names[i]: round(weights[i].item(), 2) for i in range(n_classes)})

    # ── Model / optimiser ───────────────────────────────────────────────
    model = PayloadCNN(config)
    optim = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = nn.CrossEntropyLoss(weight=weights)
    n_params = sum(p.numel() for p in model.parameters())
    logger.info("PayloadCNN: %d trainable parameters", n_params)

    # ── Training ────────────────────────────────────────────────────────
    for epoch in range(1, args.epochs + 1):
        model.train()
        running = 0.0
        for xb, yb in train_loader:
            optim.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            optim.step()
            running += loss.item() * xb.size(0)
        logger.info("epoch %2d/%d  loss=%.4f", epoch, args.epochs, running / len(X_train))

    # ── Evaluation (honest, per-class) ──────────────────────────────────
    model.eval()
    with torch.no_grad():
        logits = model(torch.tensor(X_test))
        y_pred = torch.argmax(logits, dim=1).numpy()

    report = classification_report(
        y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred).tolist()
    logger.info("\n%s", classification_report(y_test, y_pred, target_names=class_names, zero_division=0))

    # ── Persist ─────────────────────────────────────────────────────────
    save_checkpoint(model, config, WEIGHTS_PATH)
    metrics = {
        "model": "PayloadCNN (char-level TextCNN, multi-class)",
        "framework": "pytorch",
        "data_source": provenance,
        "n_parameters": n_params,
        "classes": class_names,
        "test_size": int(len(y_test)),
        "accuracy": float(report["accuracy"]),
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "weighted_f1": float(report["weighted avg"]["f1-score"]),
        "per_class": {
            c: {k: float(report[c][k]) for k in ("precision", "recall", "f1-score", "support")}
            for c in class_names
        },
        "confusion_matrix": cm,
        "confusion_matrix_labels": class_names,
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    logger.info("Saved weights  → %s", WEIGHTS_PATH)
    logger.info("Saved metrics  → %s", METRICS_PATH)


if __name__ == "__main__":
    main()
