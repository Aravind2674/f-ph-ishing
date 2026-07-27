"""
ThreatFusion – Neural HTTP Attack Classifier  (Phase 2)
========================================================

A character-level convolutional neural network that reads a raw HTTP
request-parameter value (or any request text) and classifies the *attack type*:

    benign · sqli · xss · path-traversal · cmdi

Why this exists
---------------
Phase 1 taught the platform to read a URL string. Phase 2 teaches it to read the
*contents* of a request — the part a pentester actually inspects for injection.
A signature/regex WAF matches fixed patterns and is trivially bypassed by
obfuscation; a learned character model generalises to unseen mutations
(``' OR 1=1--`` vs ``'/**/oR/**/1=1-- -``) because it learns the lexical shape of
an attack, not a literal string.

Design mirrors the proven :class:`~app.ml.url_model.UrlFusionNet` text branch:
a TextCNN (Kim, 2014) with parallel kernel widths acting as learned n-gram
detectors, global max-pooling, then a linear multi-class head. Pure PyTorch,
CPU-friendly, sub-millisecond per payload.

The model is *passive*: it classifies text handed to it. It performs no network
requests itself — active probing of a live target is a later, scope-gated phase.
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.parse import unquote_plus

import torch
import torch.nn as nn
import torch.nn.functional as F

# ---------------------------------------------------------------------------
# Vocabulary — printable ASCII covers SQL/HTML/shell metacharacters
# ---------------------------------------------------------------------------
PAD_TOKEN = "<pad>"
UNK_TOKEN = "<unk>"

# Payloads are case-sensitive in spirit (``<Script>`` vs ``<script>``) but we
# lower-case for a compact vocab; the structural metacharacters that matter
# (' " < > ; ( ) / \ = -- ) are preserved regardless of case.
DEFAULT_ALPHABET: str = string.ascii_lowercase + string.digits + string.punctuation + " "


def build_vocab(alphabet: str = DEFAULT_ALPHABET) -> dict[str, int]:
    """Deterministic ``char -> index`` map (0=PAD, 1=UNK)."""
    vocab = {PAD_TOKEN: 0, UNK_TOKEN: 1}
    for ch in alphabet:
        if ch not in vocab:
            vocab[ch] = len(vocab)
    return vocab


def encode_payload(text: str, vocab: dict[str, int], max_len: int) -> List[int]:
    """Encode a payload string into a fixed-length list of char indices."""
    text = (text or "").lower()
    unk = vocab[UNK_TOKEN]
    idxs = [vocab.get(ch, unk) for ch in text[:max_len]]
    if len(idxs) < max_len:
        idxs.extend([vocab[PAD_TOKEN]] * (max_len - len(idxs)))
    return idxs


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
@dataclass
class PayloadCNNConfig:
    """Architecture + fitted constants, serialised next to the weights."""

    vocab: dict[str, int] = field(default_factory=build_vocab)
    class_names: List[str] = field(
        default_factory=lambda: ["benign", "sqli", "xss", "path-traversal", "cmdi"]
    )
    max_len: int = 256
    emb_dim: int = 32
    num_filters: int = 96
    kernel_sizes: List[int] = field(default_factory=lambda: [3, 4, 5])
    dropout: float = 0.3

    @property
    def vocab_size(self) -> int:
        return len(self.vocab)

    @property
    def n_classes(self) -> int:
        return len(self.class_names)

    def to_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__, indent=2), encoding="utf-8")

    @classmethod
    def from_json(cls, path: str | Path) -> "PayloadCNNConfig":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
class PayloadCNN(nn.Module):
    """Char-level TextCNN multi-class classifier for HTTP payloads."""

    def __init__(self, config: PayloadCNNConfig) -> None:
        super().__init__()
        self.config = config
        self.embedding = nn.Embedding(config.vocab_size, config.emb_dim, padding_idx=0)
        self.convs = nn.ModuleList(
            [nn.Conv1d(config.emb_dim, config.num_filters, kernel_size=k)
             for k in config.kernel_sizes]
        )
        self.dropout = nn.Dropout(config.dropout)
        self.head = nn.Linear(config.num_filters * len(config.kernel_sizes), config.n_classes)

    def encode_text(self, char_ids: torch.Tensor) -> torch.Tensor:
        emb = self.embedding(char_ids).transpose(1, 2)  # (B, E, L)
        pooled = []
        for conv in self.convs:
            feat = F.relu(conv(emb))
            pooled.append(F.max_pool1d(feat, feat.shape[2]).squeeze(2))
        return torch.cat(pooled, dim=1)

    def forward(self, char_ids: torch.Tensor) -> torch.Tensor:
        """Return class logits, shape ``(batch, n_classes)``."""
        return self.head(self.dropout(self.encode_text(char_ids)))

    # ------------------------------------------------------------------
    def token_saliency(self, char_ids: torch.Tensor, class_id: int) -> torch.Tensor:
        """Per-character saliency for ``class_id`` (gradient L2 over embeddings).

        Highlights which characters pushed the predicted attack class — e.g. the
        ``' or 1=1`` span in a SQLi payload. Returns shape ``(L,)``.
        """
        self.eval()
        emb = self.embedding(char_ids).transpose(1, 2)
        emb.requires_grad_(True)
        emb.retain_grad()
        pooled = []
        for conv in self.convs:
            feat = F.relu(conv(emb))
            pooled.append(F.max_pool1d(feat, feat.shape[2]).squeeze(2))
        logits = self.head(torch.cat(pooled, dim=1))
        self.zero_grad(set_to_none=True)
        logits[0, class_id].backward()
        grad = emb.grad.detach()[0]  # (E, L)
        return grad.pow(2).sum(dim=0).sqrt()


# ---------------------------------------------------------------------------
# Checkpoint helpers
# ---------------------------------------------------------------------------
def save_checkpoint(model: PayloadCNN, config: PayloadCNNConfig, weights_path: str | Path) -> None:
    weights_path = Path(weights_path)
    torch.save(model.state_dict(), weights_path)
    config.to_json(weights_path.with_name(weights_path.stem + "_config.json"))


def load_checkpoint(weights_path: str | Path, map_location: str = "cpu"):
    weights_path = Path(weights_path)
    config = PayloadCNNConfig.from_json(
        weights_path.with_name(weights_path.stem + "_config.json")
    )
    model = PayloadCNN(config)
    model.load_state_dict(torch.load(weights_path, map_location=map_location))
    model.eval()
    return model, config


# ---------------------------------------------------------------------------
# Inference wrapper
# ---------------------------------------------------------------------------
class VulnClassifier:
    """Runtime wrapper: ``load`` then ``classify`` an HTTP payload string."""

    def __init__(self) -> None:
        self._model: Optional[PayloadCNN] = None
        self._config: Optional[PayloadCNNConfig] = None

    def load(self, weights_path: str | Path) -> None:
        path = Path(weights_path)
        if not path.exists():
            raise FileNotFoundError(f"Vuln classifier not found at {path}")
        self._model, self._config = load_checkpoint(path)

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._config is not None

    def _char_tensor(self, text: str) -> torch.Tensor:
        assert self._config is not None
        ids = encode_payload(text, self._config.vocab, self._config.max_len)
        return torch.tensor([ids], dtype=torch.long)

    @torch.no_grad()
    def _classify_one(self, text: str) -> dict:
        assert self._model is not None and self._config is not None
        self._model.eval()
        logits = self._model(self._char_tensor(text))
        probs = torch.softmax(logits, dim=1)[0]
        class_id = int(torch.argmax(probs).item())
        return {
            "label": self._config.class_names[class_id],
            "class_id": class_id,
            "confidence": float(probs[class_id].item()),
            "probs": {n: float(probs[i].item()) for i, n in enumerate(self._config.class_names)},
        }

    def classify(self, text: str) -> dict:
        """Classify one payload → ``{label, class_id, confidence, probs}``.

        The value is also **percent-decoded** and classified: attackers encode
        payloads (``%27%20OR`` → ``' OR``) precisely to slip past pattern
        matchers, so a real analyser must normalise first. When the raw and
        decoded forms disagree, the more severe (non-benign) verdict wins — a
        conservative, defensive choice.
        """
        if not self.is_loaded:
            raise RuntimeError("Model is not loaded. Call load() first.")
        results = [self._classify_one(text)]
        decoded = unquote_plus(text)
        if decoded != text:
            results.append(self._classify_one(decoded))
        # Prefer an attack verdict over benign, then higher confidence.
        results.sort(key=lambda r: (r["class_id"] != 0, r["confidence"]), reverse=True)
        return results[0]

    def suspicious_span(self, text: str, class_id: int, top_k: int = 1) -> List[str]:
        """Return the highest-saliency substring(s) for the given class."""
        if not self.is_loaded or class_id == 0:  # no span for benign
            return []
        assert self._model is not None and self._config is not None
        clean = (text or "").lower()
        n = min(len(clean), self._config.max_len)
        if n == 0:
            return []
        sal = self._model.token_saliency(self._char_tensor(text), class_id)[:n].cpu().numpy()
        s_max = float(sal.max()) if sal.size else 0.0
        if s_max <= 0:
            return []
        norm = sal / s_max
        threshold = max(float(norm.mean()), 0.4)
        spans: list[tuple[int, int]] = []
        start = None
        gap = 0
        for i in range(n):
            if norm[i] >= threshold:
                if start is None:
                    start = i
                gap = 0
            elif start is not None:
                gap += 1
                if gap > 2:
                    spans.append((start, i - gap + 1))
                    start = None
        if start is not None:
            spans.append((start, n))
        scored = sorted(
            ((clean[a:b], float(norm[a:b].mean())) for a, b in spans if b - a >= 2),
            key=lambda t: t[1], reverse=True,
        )
        return [s for s, _ in scored[:top_k]]
