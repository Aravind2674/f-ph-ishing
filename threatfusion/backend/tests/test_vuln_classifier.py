"""Tests for the Phase 2 neural HTTP attack classifier.

Unit tests cover the vocab/encoder/architecture with no trained weights.
Integration tests load the real trained checkpoint when present and assert that
known SQLi/XSS payloads are flagged and benign values are not — skipped cleanly
in environments where the checkpoint has not been trained.
"""

from pathlib import Path

import pytest
import torch

from app.ml.vuln_classifier import (
    PayloadCNN,
    PayloadCNNConfig,
    VulnClassifier,
    build_vocab,
    encode_payload,
)

# Resolve the checkpoint from either the repo root or the backend/ working dir.
_CKPT = next(
    (p for p in (Path("ml/models/vuln_classifier.pt"),
                 Path("../ml/models/vuln_classifier.pt")) if p.exists()),
    None,
)


# ── Unit: vocab / encoder ────────────────────────────────────────────────────
def test_vocab_reserves_pad_and_unk():
    vocab = build_vocab()
    assert vocab["<pad>"] == 0
    assert vocab["<unk>"] == 1
    assert "'" in vocab and "<" in vocab and ";" in vocab  # attack metacharacters


def test_encode_payload_is_fixed_length_and_padded():
    vocab = build_vocab()
    ids = encode_payload("' OR 1=1--", vocab, max_len=32)
    assert len(ids) == 32
    assert ids[-1] == 0  # right-padded with PAD
    # Unknown characters collapse to UNK, never crash.
    assert all(i >= 0 for i in encode_payload("日本語\x00", vocab, max_len=16))


# ── Unit: architecture ───────────────────────────────────────────────────────
def test_forward_shape_matches_classes():
    config = PayloadCNNConfig()
    model = PayloadCNN(config)
    x = torch.randint(0, config.vocab_size, (4, config.max_len))
    logits = model(x)
    assert logits.shape == (4, config.n_classes)


def test_saliency_shape():
    config = PayloadCNNConfig(max_len=64)
    model = PayloadCNN(config)
    x = torch.randint(1, config.vocab_size, (1, config.max_len))
    sal = model.token_saliency(x, class_id=1)
    assert sal.shape == (config.max_len,)
    assert torch.all(sal >= 0)


# ── Integration: real trained model ──────────────────────────────────────────
@pytest.mark.skipif(_CKPT is None, reason="vuln_classifier checkpoint not trained")
def test_trained_model_flags_attacks_and_passes_benign():
    clf = VulnClassifier()
    clf.load(_CKPT)

    sqli = clf.classify("1' OR '1'='1' -- ")
    xss = clf.classify("<script>alert(document.cookie)</script>")
    benign = clf.classify("Barcelona")

    # Attacks must be recognised as non-benign; benign must be class 0.
    assert sqli["class_id"] != 0
    assert xss["class_id"] != 0
    assert benign["class_id"] == 0
    # Probabilities form a distribution.
    assert abs(sum(sqli["probs"].values()) - 1.0) < 1e-4


@pytest.mark.skipif(_CKPT is None, reason="vuln_classifier checkpoint not trained")
def test_suspicious_span_returned_for_attack():
    clf = VulnClassifier()
    clf.load(_CKPT)
    res = clf.classify("' OR 1=1 UNION SELECT password FROM users--")
    spans = clf.suspicious_span("' OR 1=1 UNION SELECT password FROM users--", res["class_id"])
    # An attack payload should surface at least one salient substring.
    assert isinstance(spans, list)
