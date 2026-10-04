"""
Train the text-only character CNN on real URLs (A2-3)
=====================================================

``python -m ml.train_url_cnn``

Same data, splits, protocol and calibration as the tree model (``ml/train_url_xgb.py``): fit on the oldest period, early-stop and
calibrate on the newest part of the training period, and leave the test period to ``ml/evaluate.py``.  Inputs are the canonical
URL strings (``app/ml/url_canon.py``), so the network is blind to the scheme and a leading ``www.`` by construction.  The audited
two-branch network's dead tabular branch (trained on a constant vector) is not part of this model.
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
import torch.nn as nn

from app.ml.url_canon import canonical_url_text
from app.ml.url_cnn import UrlCnn, UrlCnnConfig, encode
from ml import dataset, metrics
from ml.train_url_xgb import choose_calibrator

logger = logging.getLogger("ml.train_url_cnn")
MODELS_DIR = Path(__file__).resolve().parent / "models"


def encode_all(urls, config: UrlCnnConfig) -> torch.Tensor:
    return torch.tensor(np.array([encode(u, config) for u in urls], dtype=np.int64))


@torch.no_grad()
def predict(net: UrlCnn, ids: torch.Tensor, batch: int = 4096) -> np.ndarray:
    net.eval()
    return np.concatenate([torch.sigmoid(net(ids[i:i + batch])).squeeze(1).numpy() for i in range(0, len(ids), batch)])


def train(epochs: int = 8, batch_size: int = 256, lr: float = 2e-3, patience: int = 2, seed: int = 0, limit: Optional[int] = None,
          models_dir: Path = MODELS_DIR, augment: float = 0.3) -> dict:
    torch.manual_seed(seed)
    np.random.seed(seed)
    torch.set_num_threads(max(1, (torch.get_num_threads())))
    df = dataset.load()
    if limit:
        df = df.sample(n=min(limit, len(df)), random_state=seed)
    sp = dataset.make_splits(df)
    config = UrlCnnConfig()
    train_frame = sp.train
    if augment > 0:
        train_frame = pd.concat([sp.train, dataset.augmented(sp.train, augment, seed)], ignore_index=True)      # adversarial training
    X_tr, y_tr = encode_all(train_frame["canon"], config), torch.tensor(train_frame["label"].to_numpy(), dtype=torch.float32)
    X_va, y_va = encode_all(sp.val["canon"], config), sp.val["label"].to_numpy()
    net = UrlCnn(config)
    opt = torch.optim.AdamW(net.parameters(), lr=lr, weight_decay=1e-4)
    loss_fn = nn.BCEWithLogitsLoss()
    best, best_state, bad, history = -1.0, None, 0, []
    for epoch in range(epochs):
        net.train()
        t0 = time.time()
        perm = torch.randperm(len(X_tr))
        total = 0.0
        for i in range(0, len(perm), batch_size):
            idx = perm[i:i + batch_size]
            opt.zero_grad()
            loss = loss_fn(net(X_tr[idx]).squeeze(1), y_tr[idx])
            loss.backward()
            opt.step()
            total += float(loss) * len(idx)
        scores = predict(net, X_va)
        pr = metrics.pr_auc(y_va, scores)
        history.append({"epoch": epoch, "train_loss": total / len(perm), "val_pr_auc": pr, "val_roc_auc": metrics.roc_auc(y_va, scores),
                        "seconds": round(time.time() - t0, 1)})
        logger.info("epoch %d: loss %.4f, val PR-AUC %.4f (%.0fs)", epoch, total / len(perm), pr, time.time() - t0)
        if pr > best:
            best, bad = pr, 0
            best_state = {k: v.clone() for k, v in net.state_dict().items()}
        else:
            bad += 1
            if bad >= patience:
                break
    net.load_state_dict(best_state)
    raw_val = predict(net, X_va)
    calibrator, cv_brier = choose_calibrator(raw_val, y_va, seed)
    cal_val = calibrator(raw_val)
    models_dir.mkdir(parents=True, exist_ok=True)
    torch.save(net.state_dict(), models_dir / "url_cnn.pt")
    config.to_json(models_dir / "url_cnn_config.json")
    calibration = {"calibrator": calibrator.to_dict(), "fit_on": "validation", "validation_rows": int(len(y_va)),
                   "validation_prevalence": float(y_va.mean()), "train_prevalence": float(y_tr.mean()), "cv_brier": cv_brier,
                   "threshold_fpr_1pct": metrics.threshold_for_fpr(y_va, cal_val, 0.01),
                   "threshold_recall_95": metrics.threshold_for_recall(y_va, cal_val, 0.95)}
    (models_dir / "url_cnn_calibration.json").write_text(json.dumps(calibration, indent=2), encoding="utf-8")
    training = {"seed": seed, "epochs_run": len(history), "history": history, "lr": lr, "batch_size": batch_size,
                "best_val_pr_auc": best, "augment_fraction": augment, "torch_version": torch.__version__, "split_report": sp.report,
                "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    (models_dir / "url_cnn_training.json").write_text(json.dumps(training, indent=2), encoding="utf-8")
    return training


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m ml.train_url_cnn")
    p.add_argument("--epochs", type=int, default=8)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--augment", type=float, default=0.3, help="fraction of training URLs given a perturbed copy (0 = off)")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    train(epochs=args.epochs, seed=args.seed, limit=args.limit, augment=args.augment)
    return 0


if __name__ == "__main__":
    sys.exit(main())
