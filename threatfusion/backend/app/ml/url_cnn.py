"""
Character-level CNN over the canonical URL string (A2-3)
========================================================

A learned model that reads a URL character by character, so it can pick up lexical patterns no hand-written feature names
(``paypa1``-style tokens, generated hosting sub-domains, random path tokens) — and can score a URL that no feed has ever seen.

What changed from the audited two-branch ``UrlFusionNet`` (removed):

* **The dead tabular branch is gone.**  It had been trained on a constant 19-float vector, so it learned nothing and the
  "fused" score equalled the text-only score; keeping it only made the model look richer than it was.  This is a *text-only*
  network (embedding → parallel Conv1d k=3/5/7 → global max-pool → MLP), exactly the part that did the work.
* **Input canonicalisation is identical at training and inference** (``url_canon.canonical_url_text``): scheme and a leading
  ``www.`` are dropped and the host lower-cased, so ``https://x``, ``http://x`` and ``www.x`` score the same (the audit saw
  0.13 → 0.99 from a prepended ``https://``).  Path case is kept (the vocabulary is case-sensitive printable ASCII).
* **Calibrated output.**  The raw sigmoid is mapped to a probability with a calibrator fitted on validation data
  (``calibration.py``); the card records the prevalence it is valid for.
* The hand-maintained ``top_domains.txt`` allow-list cap is not applied here: it hid the model's real behaviour on benign
  pages and is superseded by the host-disjoint evaluation (an allow-list, if wanted, belongs in the *product* layer where it is
  visible, not inside a score).

Everything is plain PyTorch on CPU; one URL scores in about a millisecond.  Weights are a ``state_dict`` loaded with
``weights_only=True`` after the SHA-256 manifest check (A0-7).
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from app.core.artifacts import verify_artifact
from app.ml.calibration import calibrator_from_dict
from app.ml.url_canon import canonical_url_text
from app.models.schemas import NeuralExplanation

logger = logging.getLogger(__name__)

PAD, UNK = 0, 1
ALPHABET = "".join(chr(c) for c in range(33, 127))                 # printable ASCII without the space: 94 characters
_VOCAB = {ch: i + 2 for i, ch in enumerate(ALPHABET)}


@dataclass
class UrlCnnConfig:
    max_len: int = 200
    emb_dim: int = 32
    num_filters: int = 64
    kernel_sizes: List[int] = field(default_factory=lambda: [3, 5, 7])
    hidden: int = 64
    dropout: float = 0.3
    alphabet: str = ALPHABET
    canonicalisation: str = "url_canon.canonical_url_text v1"

    @property
    def vocab_size(self) -> int:
        return len(self.alphabet) + 2

    def to_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def from_json(cls, path: str | Path) -> "UrlCnnConfig":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


def encode(text: str, config: UrlCnnConfig) -> List[int]:
    """Character ids of an already-canonical string, truncated / padded to ``max_len`` (unknown characters → UNK)."""
    vocab = _VOCAB if config.alphabet == ALPHABET else {ch: i + 2 for i, ch in enumerate(config.alphabet)}
    ids = [vocab.get(ch, UNK) for ch in text[: config.max_len]]
    return ids + [PAD] * (config.max_len - len(ids))


class UrlCnn(nn.Module):
    def __init__(self, config: UrlCnnConfig) -> None:
        super().__init__()
        self.config = config
        self.embedding = nn.Embedding(config.vocab_size, config.emb_dim, padding_idx=PAD)
        self.convs = nn.ModuleList([nn.Conv1d(config.emb_dim, config.num_filters, k) for k in config.kernel_sizes])
        width = config.num_filters * len(config.kernel_sizes)
        self.head = nn.Sequential(nn.Dropout(config.dropout), nn.Linear(width, config.hidden), nn.ReLU(),
                                  nn.Dropout(config.dropout), nn.Linear(config.hidden, 1))

    def forward(self, ids: torch.Tensor) -> torch.Tensor:
        return self.head(self._pooled(self.embedding(ids)))

    def _pooled(self, emb: torch.Tensor) -> torch.Tensor:
        x = emb.transpose(1, 2)
        feats = []
        for conv in self.convs:
            h = F.relu(conv(x))
            feats.append(F.max_pool1d(h, h.shape[2]).squeeze(2))
        return torch.cat(feats, dim=1)

    def saliency(self, ids: torch.Tensor) -> torch.Tensor:
        """L2 norm of d(logit)/d(embedding) per character (Simonyan et al. 2013) — where the model "looked"."""
        emb = self.embedding(ids).detach().requires_grad_(True)
        self.zero_grad()
        self.head(self._pooled(emb)).sum().backward()
        return emb.grad.norm(dim=2).squeeze(0).detach()


class UrlCnnModel:
    """Inference wrapper: ``load`` → ``predict_proba`` (raw) / ``predict_calibrated`` / ``explain_url``."""

    def __init__(self) -> None:
        self._net: Optional[UrlCnn] = None
        self._config: Optional[UrlCnnConfig] = None
        self._calibrator = None
        self._lock = threading.Lock()                # saliency back-propagates through shared parameters

    @property
    def is_loaded(self) -> bool:
        return self._net is not None

    def load(self, weights_path: str | Path, calibration_path: Optional[str | Path] = None) -> None:
        path = Path(weights_path)
        if not path.exists():
            raise FileNotFoundError(f"URL CNN weights not found at {path}")
        config_path = path.with_name(path.stem + "_config.json")
        verify_artifact(path)
        verify_artifact(config_path)
        config = UrlCnnConfig.from_json(config_path)
        net = UrlCnn(config)
        net.load_state_dict(torch.load(path, map_location="cpu", weights_only=True))
        net.eval()
        self._net, self._config, self._path = net, config, path
        cal = Path(calibration_path) if calibration_path else path.with_name(path.stem + "_calibration.json")
        if cal.exists():
            verify_artifact(cal)
            self._calibrator = calibrator_from_dict(json.loads(cal.read_text(encoding="utf-8"))["calibrator"])
        logger.info("URL CNN loaded from %s (calibrated: %s)", path, self._calibrator is not None)

    def _ids(self, url: str) -> torch.Tensor:
        assert self._config is not None
        return torch.tensor([encode(canonical_url_text(url), self._config)], dtype=torch.long)

    @torch.no_grad()
    def predict_proba(self, url: str) -> float:
        """The raw sigmoid score in [0, 1] (a ranking, not yet a probability)."""
        if not self.is_loaded:
            raise RuntimeError("URL CNN is not loaded")
        assert self._net is not None
        return float(torch.sigmoid(self._net(self._ids(url))).item())

    def predict_calibrated(self, url: str) -> float:
        """The calibrated probability (falls back to the raw score if no calibrator was shipped — the card says which)."""
        raw = self.predict_proba(url)
        return float(self._calibrator(np.array([raw]))[0]) if self._calibrator is not None else raw

    @property
    def calibrated(self) -> bool:
        return self._calibrator is not None

    def explain_url(self, url: str, top_k: int = 3, min_span_len: int = 2) -> List[NeuralExplanation]:
        """The most influential substrings of the canonical string (character saliency, merged into spans)."""
        if not self.is_loaded:
            raise RuntimeError("URL CNN is not loaded")
        assert self._net is not None and self._config is not None
        text = canonical_url_text(url)
        n = min(len(text), self._config.max_len)
        if n == 0:
            return []
        with self._lock:
            sal = self._net.saliency(self._ids(url))[:n].cpu().numpy()
        peak = float(sal.max()) if sal.size else 0.0
        if peak <= 0:
            return []
        norm = sal / peak
        threshold = max(float(norm.mean()), 0.35)
        spans: list[tuple[int, int]] = []
        start: Optional[int] = None
        gap = 0
        for i in range(n):
            if norm[i] >= threshold:
                start, gap = (i if start is None else start), 0
            elif start is not None:
                gap += 1
                if gap > 1:
                    spans.append((start, i - gap + 1))
                    start = None
        if start is not None:
            spans.append((start, n))
        out = [NeuralExplanation(substring=text[a:b], start=a, end=b, importance=round(float(norm[a:b].mean()), 4),
                                 human_readable=f"Influential token '{text[a:b]}' in the URL text")
               for a, b in spans if b - a >= min_span_len]
        return sorted(out, key=lambda e: e.importance, reverse=True)[:top_k]
