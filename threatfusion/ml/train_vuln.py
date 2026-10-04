"""ThreatFusion – HTTP attack classifier training (A2-4, B10)

``python -m ml.train_vuln``

Trains the character-level :class:`~app.ml.vuln_classifier.PayloadCNN` (benign · sqli · xss · path-traversal · cmdi).  What
changed after the audit (which found 99.9 % accuracy on a random split of one corpus, 89 cmdi training samples, no handling of
encodings, and a hard 256-character window):

* **More, and more varied, real data** — the Morzeux HttpParamsDataset (CSIC-2010 + attack payloads) *plus* the public SecLists
  attack lists (cmdi / path-traversal / XSS / SQLi) *plus* real benign text (path segments and parameter values of benign URLs
  in the PhreshPhish data).  Per-class counts are capped so one verbose list cannot dominate.
* **Adversarial augmentation** (the approach of ModSec-AdvLearn, arXiv 2308.04964): obfuscated copies of *training* payloads in
  the ``TRAIN_FAMILIES`` encodings, for attacks **and** benign text (so an encoding alone is never the signal), plus the
  normalised form of every payload (the inference path scores raw and normalised text — ``app/ml/payload_norm.py``).
* **Group-aware splits** — a payload and all of its variants stay in one split; validation and test contain only plain payloads.
* **Temperature scaling** fitted on validation logits, so the confidences mean something.
* **Evaluation on corpora the model never saw** (``ml/payload_eval.py``): PayloadsAllTheThings attacks (overlap with training
  removed), real benign text held out by hash bucket, and obfuscations in *held-out* encoding families.  One exception, chosen after
  the first evaluation showed cmdi at 14 % recall because the only real cmdi training data was one templated ``echo`` list: 3/4 of the
  PayloadsAllTheThings *command-injection* lines (by hash) now train the model and 1/4 stays held-out; lines with fewer than two
  alphanumerics (lone ``|``, `` ` ``) are not examples and are dropped everywhere.  The cmdi held-out number is therefore optimistic.

No synthetic rows are fabricated; class imbalance is handled with loss weights and per-class metrics are reported.
"""

from __future__ import annotations

import argparse
import itertools
import json
import logging
import random
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.ml.payload_norm import normalize_payload  # noqa: E402
from app.ml.vuln_classifier import (  # noqa: E402
    PayloadCNN,
    PayloadCNNConfig,
    VulnClassifier,
    build_vocab,
    encode_payload,
    save_checkpoint,
)
from ml import payload_data, payload_eval  # noqa: E402
from ml.data_sources import build_http_attack_dataset  # noqa: E402

logger = logging.getLogger("ml.train_vuln")

MODELS_DIR = Path(__file__).resolve().parent / "models"
WEIGHTS_PATH = MODELS_DIR / "vuln_classifier.pt"
METRICS_PATH = MODELS_DIR / "vuln_classifier_metrics.json"
CLASS_CAP = 6000
AUGMENT_FRACTION = 0.3
N_BENIGN_TRAIN = 8000


def build_bases(seed: int) -> tuple[list[str], list[int], list[str], dict]:
    """The plain payloads and their class ids: Morzeux + SecLists attacks + real benign text, each class capped."""
    texts, labels, class_names, prov = build_http_attack_dataset(seed=seed)
    rows = list(zip(texts, labels))
    index = {c: i for i, c in enumerate(class_names)}
    for cls, items in payload_data.read_corpus(role="train").items():
        rows += [(p, index[cls]) for p in items]
    rows += [(v, 0) for v in payload_data.benign_values(limit=N_BENIGN_TRAIN, seed=seed, role="train")]
    rng = random.Random(seed)
    rng.shuffle(rows)
    seen, per_class, out = set(), Counter(), []
    for text, cid in rows:
        if (text, cid) in seen or per_class[cid] >= CLASS_CAP:
            continue
        seen.add((text, cid))
        per_class[cid] += 1
        out.append((text, cid))
    prov = {**prov, "extended_with": "SecLists attack lists (MIT) + real benign path segments / parameter values (PhreshPhish benign URLs)",
            "class_cap": CLASS_CAP, "final_distribution": {class_names[i]: per_class[i] for i in range(len(class_names))}}
    return [t for t, _ in out], [c for _, c in out], class_names, prov


def augment(texts: list[str], labels: list[int], seed: int) -> tuple[list[str], list[int]]:
    """Training-only copies: the normalised form of every payload, and obfuscated (TRAIN_FAMILIES) copies of a random 30 %."""
    rng = random.Random(seed)
    out_t, out_y = list(texts), list(labels)
    seen = set(zip(texts, labels))
    for text, y in zip(texts, labels):
        candidates = [normalize_payload(text)]
        if rng.random() < AUGMENT_FRACTION:
            family = payload_data.OBFUSCATORS[rng.choice(payload_data.TRAIN_FAMILIES)]
            candidates.append(family(text))
        for c in candidates:
            if c and (c, y) not in seen and len(c) <= 2000:
                seen.add((c, y))
                out_t.append(c)
                out_y.append(y)
    return out_t, out_y


def fit_temperature(logits: torch.Tensor, labels: torch.Tensor) -> float:
    """The scalar T minimising the validation NLL of softmax(logits / T)."""
    log_t = torch.zeros(1, requires_grad=True)
    opt = torch.optim.LBFGS([log_t], lr=0.1, max_iter=100)

    def closure():
        opt.zero_grad()
        loss = nn.functional.cross_entropy(logits / log_t.exp(), labels)
        loss.backward()
        return loss

    opt.step(closure)
    return float(log_t.exp().clamp(0.05, 20.0).item())


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Train the HTTP attack classifier")
    parser.add_argument("--epochs", type=int, default=14)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--patience", type=int, default=3)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    texts, labels, class_names, provenance = build_bases(args.seed)
    logger.info("base payloads: %d %s", len(texts), provenance["final_distribution"])
    idx = np.arange(len(texts))
    y_all = np.array(labels)
    tr_i, rest_i = train_test_split(idx, test_size=0.2, random_state=args.seed, stratify=y_all)
    va_i, te_i = train_test_split(rest_i, test_size=0.5, random_state=args.seed, stratify=y_all[rest_i])
    train_t, train_y = augment([texts[i] for i in tr_i], [labels[i] for i in tr_i], args.seed)
    val_t, val_y = [texts[i] for i in va_i], [labels[i] for i in va_i]
    test_t, test_y = [texts[i] for i in te_i], [labels[i] for i in te_i]
    logger.info("train %d (after augmentation), validation %d, test %d", len(train_t), len(val_t), len(test_t))

    config = PayloadCNNConfig(vocab=build_vocab(), class_names=class_names)

    def enc(items):
        return torch.tensor(np.array([encode_payload(t, config.vocab, config.max_len) for t in items], dtype=np.int64))

    X_tr, X_va, X_te = enc(train_t), enc(val_t), enc(test_t)
    y_tr, y_va, y_te = (torch.tensor(v, dtype=torch.long) for v in (train_y, val_y, test_y))
    counts = Counter(train_y)
    weights = torch.tensor([len(train_y) / (len(class_names) * max(counts.get(i, 0), 1)) for i in range(len(class_names))], dtype=torch.float32)
    model = PayloadCNN(config)
    optim = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = nn.CrossEntropyLoss(weight=weights)
    loader = DataLoader(TensorDataset(X_tr, y_tr), batch_size=args.batch_size, shuffle=True)

    best, best_state, bad, history = -1.0, None, 0, []
    for epoch in range(1, args.epochs + 1):
        model.train()
        running = 0.0
        for xb, yb in loader:
            optim.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            optim.step()
            running += float(loss.detach()) * xb.size(0)
        model.eval()
        with torch.no_grad():
            pred = model(X_va).argmax(1).numpy()
        rep = classification_report(y_va.numpy(), pred, target_names=class_names, output_dict=True, zero_division=0)
        macro = float(rep["macro avg"]["f1-score"])
        history.append({"epoch": epoch, "loss": running / len(X_tr), "val_macro_f1": macro})
        logger.info("epoch %2d: loss %.4f, val macro-F1 %.4f", epoch, running / len(X_tr), macro)
        if macro > best:
            best, bad, best_state = macro, 0, {k: v.clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= args.patience:
                break
    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        val_logits = model(X_va)
        test_logits = model(X_te)
    config.temperature = fit_temperature(val_logits, y_va)
    logger.info("fitted temperature T = %.3f", config.temperature)
    probs = torch.softmax(test_logits / config.temperature, dim=1)
    pred = probs.argmax(1).numpy()
    report = classification_report(y_te.numpy(), pred, target_names=class_names, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_te.numpy(), pred).tolist()
    save_checkpoint(model, config, WEIGHTS_PATH)

    # ── held-out evaluation with the shipped inference path (before the manifest is refreshed: load without the check) ──
    clf = VulnClassifier()
    clf._model, clf._config = model, config
    sets = payload_eval.heldout_sets(exclude_train=texts)
    heldout = payload_eval.compare(clf, sets)
    metrics = {
        "model": "PayloadCNN (char-level TextCNN, multi-class)", "framework": "pytorch", "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "data_source": provenance, "n_parameters": sum(p.numel() for p in model.parameters()), "classes": class_names,
        "temperature": config.temperature, "epochs_run": len(history), "history": history, "seed": args.seed,
        "in_distribution_test": {
            "note": "random split of the TRAINING corpora: an optimistic upper bound, not a generalisation estimate",
            "n": len(test_y), "accuracy": float(report["accuracy"]), "macro_f1": float(report["macro avg"]["f1-score"]),
            "per_class": {c: {k: float(report[c][k]) for k in ("precision", "recall", "f1-score", "support")} for c in class_names},
            "confusion_matrix": cm, "confusion_matrix_labels": class_names},
        "held_out": {"note": "PayloadsAllTheThings attacks (training overlap removed), real benign text held out by hash bucket, "
                             "obfuscation families never used in training",
                     "sets": {"attacks": {k: len(v) for k, v in sets["attacks"].items()}, "benign": len(sets["benign"]),
                              "overlap_removed": sets["overlap_removed"]}, **heldout},
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2, default=float), encoding="utf-8")
    write_card(metrics)
    cur = heldout["current_inference"]
    logger.info("held-out recall (correct class): %s | benign FPR %.4f | ECE %.3f", {c: round(v["recall_correct_class"], 3) for c, v in cur["per_class"].items()},
                cur["benign"]["false_positive_rate"], cur["confidence_ece"])
    return 0


def write_card(m: dict) -> None:
    cur = m["held_out"]["current_inference"]
    card = {
        "name": "vuln_classifier", "version": f"payload-{m['trained_at'][:10]}", "task": "HTTP request-parameter attack classification (benign / sqli / xss / path-traversal / cmdi)",
        "created_at": m["trained_at"],
        "intended_use": "Passive triage of request text handed to /analyze and the traffic analyser. Not a WAF; an alarm to look at, never proof of exploitation.",
        "limitations": ["Trained on public corpora (CSIC-2010-derived data, SecLists); real-world traffic differs.",
                        "Only five classes; novel attack types are mapped to the nearest one or to benign.",
                        "Obfuscation outside the normaliser's repertoire (custom encodings, multi-layer ciphers) can evade it.",
                        "The in-distribution accuracy is optimistic; use the held-out table.",
                        "Command injection has little varied public data: 3/4 of the PayloadsAllTheThings cmdi lines (by hash) are in training, the rest "
                        "held out, and those lines are variations of a few templates — the held-out cmdi recall is optimistic (n≈110).",
                        "XSS is the weakest class on held-out data (recall ≈ 0.64): most misses are scored as another attack class, not as benign.",
                        "Single words that happen to be commands (a bare `whoami`) are treated as benign text; the signal is the injection syntax around them."],
        "feature_schema": {"version": 1, "names": ["char-level text (see config)"]},
        "data": m["data_source"],
        "training": {"epochs_run": m["epochs_run"], "seed": m["seed"], "temperature": m["temperature"],
                     "augmentation": "normalised copies + obfuscated copies (train families) of 30 % of training payloads"},
        "calibration": {"kind": "temperature", "T": m["temperature"], "fit_on": "validation"},
        "metrics": {"test": {"pr_auc": None, "roc_auc": None, "f1": m["in_distribution_test"]["macro_f1"], "ci95": {},
                             "in_distribution_accuracy": m["in_distribution_test"]["accuracy"]},
                    "held_out_recall_correct_class": {c: v["recall_correct_class"] for c, v in cur["per_class"].items()},
                    "held_out_benign_false_positive_rate": cur["benign"]["false_positive_rate"],
                    "confidence_ece": cur["confidence_ece"],
                    "obfuscation_not_benign_rate": {f: v["mean"] for f, v in cur["families"].items()}},
        "report": "ml/models/vuln_classifier_metrics.json",
    }
    (MODELS_DIR / "vuln_classifier.card.json").write_text(json.dumps(card, indent=2, default=float), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
