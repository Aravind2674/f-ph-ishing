"""
ThreatFusion – Character-Level Neural URL Model
================================================

This module introduces the project's first **deep-learning** component: a
two-branch neural network that reads a raw URL/domain *string* character by
character and fuses that learned representation with the existing
19-dimensional tabular ``FeatureVector``.

Why a neural net (and why now)?
-------------------------------
The original pipeline scored a target purely from *third-party reputation*
(VirusTotal / Shodan / NVD). That signal is blind on day zero: a freshly
registered phishing domain such as ``paypa1-secure-login.tk`` has no vendor
detections yet, so a reputation-only model rates it *safe*. A character-level
model learns the **lexical fingerprints** of phishing directly from the string
— brand impersonation, homoglyphs, excessive hyphens/sub-domains, suspicious
TLDs, high-entropy tokens — and therefore flags novel domains that no feed has
seen. This is exactly the capability the project name ("ph-ishing") implies but
the tree model never had.

Architecture (``UrlFusionNet``)
-------------------------------
::

    raw URL string ──► char embedding ──► parallel Conv1d (k=3,4,5)
                                              │  ReLU + global max-pool
                                              ▼
                                        text representation ─┐
                                                             ├─► fusion MLP ─► fused logit
    19-dim FeatureVector ──► tabular MLP ──► tab representation ─┘
                                                             │
                                        text representation ─┴─► text-only head ─► url-only logit

* **Text branch** – a TextCNN (Kim, 2014) over character embeddings. Multiple
  kernel widths act as learned n-gram detectors (tri-/four-/five-gram char
  patterns), each reduced by global max-pooling to its most salient activation.
* **Tabular branch** – a small MLP over the standardised reputation features.
* **Fusion head** – concatenates both representations and predicts the final
  risk probability. Trained end-to-end with back-propagation.
* **Text-only head** – a second head trained on the text representation alone,
  so the model can score a bare URL with *no* API enrichment available. This is
  the offline, zero-day differentiator surfaced in the API as ``neural_url_score``.

Everything here is pure PyTorch and CPU-friendly (inference is sub-millisecond
for a single URL), keeping within the project's real-time latency budget.
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import torch
import torch.nn as nn
import torch.nn.functional as F

# ---------------------------------------------------------------------------
# Character vocabulary
# ---------------------------------------------------------------------------
# We restrict the alphabet to characters that actually occur in URLs/domains.
# Index 0 is reserved for PAD, index 1 for any out-of-vocabulary character
# (e.g. unicode homoglyphs, which are themselves a phishing signal).
PAD_TOKEN = "<pad>"
UNK_TOKEN = "<unk>"

# Printable, URL-relevant characters. ``string.printable`` minus whitespace we
# do not care about keeps this deterministic and reproducible across machines.
DEFAULT_ALPHABET: str = (
    string.ascii_lowercase
    + string.digits
    + "-._~:/?#[]@!$&'()*+,;=%"  # RFC-3986 reserved/unreserved punctuation
)


def build_vocab(alphabet: str = DEFAULT_ALPHABET) -> dict[str, int]:
    """Build a deterministic ``char -> index`` mapping.

    ``PAD`` is 0 (also the embedding ``padding_idx``) and ``UNK`` is 1 so that
    unseen characters — including unicode look-alikes used in homoglyph attacks
    — collapse to a single learnable "unknown" embedding.
    """
    vocab = {PAD_TOKEN: 0, UNK_TOKEN: 1}
    for ch in alphabet:
        if ch not in vocab:
            vocab[ch] = len(vocab)
    return vocab


def encode_url(url: str, vocab: dict[str, int], max_len: int) -> List[int]:
    """Encode a URL string into a fixed-length list of character indices.

    The string is lower-cased (URLs are largely case-insensitive and this
    shrinks the vocabulary), truncated to ``max_len``, and right-padded with the
    PAD index. Unknown characters map to the UNK index.
    """
    url = (url or "").strip().lower()
    unk = vocab[UNK_TOKEN]
    idxs = [vocab.get(ch, unk) for ch in url[:max_len]]
    if len(idxs) < max_len:
        idxs.extend([vocab[PAD_TOKEN]] * (max_len - len(idxs)))
    return idxs


# ---------------------------------------------------------------------------
# Model configuration
# ---------------------------------------------------------------------------

@dataclass
class UrlFusionConfig:
    """Hyper-parameters and fitted constants for :class:`UrlFusionNet`.

    Everything needed to *reconstruct and run* the model (short of the learned
    weights) lives here and is serialised to JSON next to the checkpoint, so
    inference never has to guess an architecture or a normalisation constant.
    """

    vocab: dict[str, int] = field(default_factory=build_vocab)
    max_len: int = 200
    emb_dim: int = 32
    num_filters: int = 64
    kernel_sizes: List[int] = field(default_factory=lambda: [3, 4, 5])
    n_tabular_features: int = 19
    tab_hidden: int = 32
    tab_out: int = 16
    fusion_hidden: int = 64
    dropout: float = 0.3
    # Names of the tabular features, in the exact column order used at train
    # time. Mirrors FeatureVector field order — the single implicit contract.
    feature_names: List[str] = field(default_factory=list)
    # Standardisation constants (z-score) for the tabular branch. Neural nets,
    # unlike trees, are sensitive to feature scale, so we normalise.
    tab_mean: List[float] = field(default_factory=list)
    tab_std: List[float] = field(default_factory=list)

    @property
    def vocab_size(self) -> int:
        return len(self.vocab)

    def to_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__, indent=2), encoding="utf-8")

    @classmethod
    def from_json(cls, path: str | Path) -> "UrlFusionConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**data)


# ---------------------------------------------------------------------------
# The network
# ---------------------------------------------------------------------------

class UrlFusionNet(nn.Module):
    """Two-branch (text + tabular) neural fusion classifier.

    Produces two logits per forward pass:

    * ``fused`` – the primary risk logit combining URL lexicon + reputation.
    * ``text`` – a URL-only risk logit from the character branch alone, usable
      when tabular enrichment is unavailable.
    """

    def __init__(self, config: UrlFusionConfig) -> None:
        super().__init__()
        self.config = config

        # ── Text branch: char embedding + multi-kernel Conv1d (TextCNN) ──
        self.embedding = nn.Embedding(
            config.vocab_size, config.emb_dim, padding_idx=0
        )
        self.convs = nn.ModuleList(
            [
                nn.Conv1d(config.emb_dim, config.num_filters, kernel_size=k)
                for k in config.kernel_sizes
            ]
        )
        text_repr_dim = config.num_filters * len(config.kernel_sizes)
        self.text_dropout = nn.Dropout(config.dropout)

        # Text-only head — lets the char branch stand alone (zero-day URL score)
        self.text_head = nn.Linear(text_repr_dim, 1)

        # ── Tabular branch: small MLP over standardised features ─────────
        self.tab_mlp = nn.Sequential(
            nn.Linear(config.n_tabular_features, config.tab_hidden),
            nn.ReLU(),
            nn.Linear(config.tab_hidden, config.tab_out),
            nn.ReLU(),
        )
        # Tabular-only head — used for the training-time ablation (text-only vs
        # tabular-only vs fused) that shows fusion beats either modality alone.
        self.tab_head = nn.Linear(config.tab_out, 1)

        # ── Fusion head: concat(text, tabular) → risk logit ──────────────
        self.fusion = nn.Sequential(
            nn.Linear(text_repr_dim + config.tab_out, config.fusion_hidden),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.fusion_hidden, 1),
        )

    # ------------------------------------------------------------------
    def encode_text(self, char_ids: torch.Tensor) -> torch.Tensor:
        """Map a batch of char-id sequences to a text representation.

        Parameters
        ----------
        char_ids : LongTensor ``(batch, max_len)``

        Returns
        -------
        FloatTensor ``(batch, num_filters * n_kernels)``
        """
        # (B, L, E) → (B, E, L) for Conv1d which expects channels-first.
        emb = self.embedding(char_ids).transpose(1, 2)
        pooled = []
        for conv in self.convs:
            # (B, F, L') → ReLU → global max over time → (B, F)
            feat = F.relu(conv(emb))
            pooled.append(F.max_pool1d(feat, feat.shape[2]).squeeze(2))
        return torch.cat(pooled, dim=1)

    def forward(
        self, char_ids: torch.Tensor, tab: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Return ``(fused_logit, text_logit)``, both shape ``(batch, 1)``."""
        fused_logit, text_logit, _ = self.forward_all(char_ids, tab)
        return fused_logit, text_logit

    def forward_all(
        self, char_ids: torch.Tensor, tab: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Return ``(fused_logit, text_logit, tab_logit)``.

        The three logits back the ablation study: ``text_logit`` uses only the
        character branch, ``tab_logit`` only the tabular branch, and
        ``fused_logit`` both. All shape ``(batch, 1)``.
        """
        text_repr = self.text_dropout(self.encode_text(char_ids))
        text_logit = self.text_head(text_repr)

        tab_repr = self.tab_mlp(tab)
        tab_logit = self.tab_head(tab_repr)

        fused_logit = self.fusion(torch.cat([text_repr, tab_repr], dim=1))
        return fused_logit, text_logit, tab_logit

    # ------------------------------------------------------------------
    def text_saliency(self, char_ids: torch.Tensor) -> torch.Tensor:
        """Per-character saliency for the URL-only score (explainability).

        Computes the gradient of the text logit with respect to the character
        embeddings and takes its L2 norm per position — a standard saliency map
        (Simonyan et al., 2013). Higher = that character pushed the phishing
        score more. Used to highlight the *suspicious substring* in the UI.

        Parameters
        ----------
        char_ids : LongTensor ``(1, max_len)`` — a single URL.

        Returns
        -------
        FloatTensor ``(max_len,)`` of non-negative importances.
        """
        self.eval()
        emb = self.embedding(char_ids).transpose(1, 2)  # (1, E, L)
        emb.requires_grad_(True)
        emb.retain_grad()

        pooled = []
        for conv in self.convs:
            feat = F.relu(conv(emb))
            pooled.append(F.max_pool1d(feat, feat.shape[2]).squeeze(2))
        text_repr = torch.cat(pooled, dim=1)
        logit = self.text_head(text_repr)

        self.zero_grad(set_to_none=True)
        logit.sum().backward()

        # grad: (1, E, L) → L2 over embedding dim → (L,)
        grad = emb.grad.detach()[0]  # (E, L)
        return grad.pow(2).sum(dim=0).sqrt()


# ---------------------------------------------------------------------------
# Checkpoint helpers
# ---------------------------------------------------------------------------

def save_checkpoint(
    model: UrlFusionNet, config: UrlFusionConfig, weights_path: str | Path
) -> None:
    """Persist model weights (``.pt``) plus its config (``*_config.json``)."""
    weights_path = Path(weights_path)
    torch.save(model.state_dict(), weights_path)
    config.to_json(weights_path.with_name(weights_path.stem + "_config.json"))


def load_checkpoint(
    weights_path: str | Path, map_location: str = "cpu"
) -> tuple[UrlFusionNet, UrlFusionConfig]:
    """Reconstruct a :class:`UrlFusionNet` and its config from disk."""
    weights_path = Path(weights_path)
    config_path = weights_path.with_name(weights_path.stem + "_config.json")
    config = UrlFusionConfig.from_json(config_path)
    model = UrlFusionNet(config)
    state = torch.load(weights_path, map_location=map_location)
    model.load_state_dict(state)
    model.eval()
    return model, config
