"""
Held-out evaluation of the HTTP attack classifier (A2-4, B10)
=============================================================

The audited number (99.9 % accuracy, 18 cmdi test samples) came from a random split of the *training corpus*.  This module
measures what matters: attacks from **another publisher's corpus** (PayloadsAllTheThings, with every payload that also occurs
in the training data removed), **real benign parameter values** (from benign URLs in the PhreshPhish data), and **obfuscated
variants** of the held-out attacks in encoding families the model never saw in training.

``legacy_label`` reproduces the audited inference path (raw text + one round of percent-decoding, truncated at the model's input
length) so before/after numbers are measured on the same data with the same model-loading code.

Metrics: per-class recall of the *correct* class, the not-benign rate (did it at least raise an alarm), false-positive rate on
benign values, robustness per obfuscation family, and the expected calibration error of the reported confidence.
"""

from __future__ import annotations

import itertools
import random
from collections import defaultdict
from typing import Callable, Optional
from urllib.parse import unquote_plus

import numpy as np

from app.ml.vuln_classifier import VulnClassifier
from ml import metrics, payload_data

CLASSES = ["benign", "sqli", "xss", "path-traversal", "cmdi"]


def legacy_label(clf: VulnClassifier, text: str) -> tuple[str, float]:
    """The audited inference path: raw + one percent-decode, first ``max_len`` characters only, no windows, no temperature."""
    assert clf._config is not None
    cfg = clf._config
    results = []
    for form in {text, unquote_plus(text)}:
        probs = clf._probs_one(form[: cfg.max_len])
        k = int(probs.argmax())
        results.append((k != 0, float(probs[k]), cfg.class_names[k]))
    results.sort(reverse=True)
    return results[0][2], results[0][1]


def current_label(clf: VulnClassifier, text: str) -> tuple[str, float]:
    r = clf.classify(text)
    return r["label"], r["confidence"]


def heldout_sets(max_per_class: int = 1500, n_benign: int = 6000, seed: int = 0, exclude_train: Optional[list[str]] = None) -> dict:
    train = payload_data.read_corpus(role="train")
    heldout = payload_data.read_corpus(role="heldout")
    pool = list(itertools.chain.from_iterable(train.values())) + (exclude_train or [])
    heldout, removed = payload_data.remove_overlap(heldout, pool)
    rng = random.Random(seed)
    attacks = {c: rng.sample(v, min(max_per_class, len(v))) for c, v in heldout.items()}
    benign = payload_data.benign_values(limit=n_benign, seed=seed, role="eval")      # hash-bucketed: disjoint from training
    return {"attacks": attacks, "benign": benign, "overlap_removed": removed}


def evaluate(label_fn: Callable[[str], tuple[str, float]], sets: dict) -> dict:
    out: dict = {"per_class": {}, "benign": {}, "families": {}}
    confidences, correct = [], []
    for cls, items in sets["attacks"].items():
        preds = [label_fn(x) for x in items]
        out["per_class"][cls] = {
            "n": len(items), "recall_correct_class": float(np.mean([p[0] == cls for p in preds])),
            "not_benign_rate": float(np.mean([p[0] != "benign" for p in preds])),
        }
        confidences += [p[1] for p in preds]
        correct += [p[0] == cls for p in preds]
    bpred = [label_fn(x) for x in sets["benign"]]
    out["benign"] = {"n": len(bpred), "false_positive_rate": float(np.mean([p[0] != "benign" for p in bpred]))}
    confidences += [p[1] for p in bpred]
    correct += [p[0] == "benign" for p in bpred]
    out["confidence_ece"] = metrics.ece(np.array(correct, float), np.array(confidences))
    for fam in payload_data.TRAIN_FAMILIES + payload_data.HELDOUT_FAMILIES:
        fn = payload_data.OBFUSCATORS[fam]
        per = {}
        for cls, items in sets["attacks"].items():
            sample = items[:500]
            per[cls] = float(np.mean([label_fn(fn(x))[0] != "benign" for x in sample]))
        out["families"][fam] = {"role": "train" if fam in payload_data.TRAIN_FAMILIES else "held-out", "not_benign_rate": per,
                                "mean": float(np.mean(list(per.values())))}
    return out


def compare(clf: VulnClassifier, sets: dict) -> dict:
    """Legacy inference vs the current inference path, on the same model and data."""
    return {"legacy_inference": evaluate(lambda x: legacy_label(clf, x), sets),
            "current_inference": evaluate(lambda x: current_label(clf, x), sets)}
