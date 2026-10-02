"""
ThreatFusion – Neural Fusion Model (inference wrapper)
=======================================================

Runtime wrapper around :class:`~app.ml.url_model.UrlFusionNet`, mirroring the
``load → predict`` lifecycle of the XGBoost :class:`~app.ml.fusion_model.FusionModel`
so the two can sit side-by-side in the API without special-casing.

It exposes three things the tree model cannot:

* ``predict_proba(url, features)`` – the fused (lexical + reputation) risk.
* ``predict_url_only(url)`` – a risk score from the **URL string alone**, with
  no third-party enrichment. This is what catches a brand-new phishing domain
  that VirusTotal has never seen.
* ``explain_url(url)`` – the most suspicious substrings, via character saliency,
  so the UI can point at *why* (e.g. the ``paypa1`` look-alike token).

The wrapper degrades gracefully: if the checkpoint is missing it simply reports
``is_loaded == False`` and the API falls back to the existing scores.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import numpy as np
import torch

from app.core.artifacts import verify_artifact
from app.models.schemas import FeatureVector, NeuralExplanation
from app.ml.url_model import (
    UrlFusionConfig,
    UrlFusionNet,
    encode_url,
    load_checkpoint,
)

logger = logging.getLogger(__name__)

# Registered-domain allowlist (real Tranco top-list). A character-level model
# cannot distinguish a brand in the *registered domain* (legitimate, e.g.
# ``paypal.com/us/signin``) from a brand used as a *token* (phishing, e.g.
# ``paypal-verify.tk``) — the two look almost identical lexically. Suppressing
# the URL-lexical risk when the registered domain is itself a well-known site is
# the standard anti-phishing correction and eliminates that false-positive class.
_ALLOWLIST_PATH = Path(__file__).with_name("top_domains.txt")
# Score ceiling applied to an allowlisted apex domain (keeps it in the "Low"
# band without zeroing it — a top domain can still, rarely, be compromised).
_ALLOWLIST_CAP = 0.15


def _load_allowlist(path: Path = _ALLOWLIST_PATH) -> frozenset:
    """Load the registered-domain allowlist; empty (disabled) if unavailable."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        return frozenset(
            ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")
        )
    except Exception:  # missing file → feature simply disabled
        return frozenset()


def _registered_domain_candidates(url: str) -> set[str]:
    """Return the last-2 and last-3 label groupings of a URL's host.

    Comparing these against the allowlist matches both ``amazon.com`` (2 labels)
    and multi-part suffixes like ``bbc.co.uk`` (3 labels), while a spoof such as
    ``paypal.com.evil.tk`` yields only ``evil.tk`` / ``com.evil.tk`` — neither of
    which is allowlisted, so the spoof is *not* suppressed.
    """
    u = (url or "").strip().lower()
    netloc = urlparse(u if "://" in u else f"http://{u}").netloc
    host = netloc.split("@")[-1].split(":")[0]
    if not host or all(c.isdigit() or c == "." for c in host):  # empty or raw IPv4
        return set()
    labels = host.split(".")
    cands: set[str] = set()
    if len(labels) >= 2:
        cands.add(".".join(labels[-2:]))
    if len(labels) >= 3:
        cands.add(".".join(labels[-3:]))
    return cands


class NeuralFusionModel:
    """Inference wrapper around a trained :class:`UrlFusionNet`."""

    def __init__(self) -> None:
        self._model: Optional[UrlFusionNet] = None
        self._config: Optional[UrlFusionConfig] = None
        self._model_path: Optional[Path] = None
        self._allowlist: frozenset = _load_allowlist()
        logger.info(
            "NeuralFusionModel instance created (model not yet loaded; "
            "%d allowlisted domains)",
            len(self._allowlist),
        )

    def _is_allowlisted(self, url: str) -> bool:
        """True if the URL's registered domain is a known-legitimate top site."""
        if not self._allowlist:
            return False
        return any(c in self._allowlist for c in _registered_domain_candidates(url))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def load(self, weights_path: str | Path) -> None:
        """Load a trained checkpoint (``.pt`` + ``*_config.json``) from disk."""
        path = Path(weights_path)
        if not path.exists():
            raise FileNotFoundError(f"Neural model file not found at {path}")
        # Verify the weights *and* their config (vocab/normalisation constants) against the
        # SHA-256 manifest before anything is deserialised (A0-7).
        verify_artifact(path)
        verify_artifact(path.with_name(path.stem + "_config.json"))
        self._model, self._config = load_checkpoint(path)
        self._model_path = path
        logger.info("Neural fusion model successfully loaded from %s", path)

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._config is not None

    # ------------------------------------------------------------------
    # Tensor preparation
    # ------------------------------------------------------------------
    def _char_tensor(self, url: str) -> torch.Tensor:
        assert self._config is not None
        ids = encode_url(url, self._config.vocab, self._config.max_len)
        return torch.tensor([ids], dtype=torch.long)

    def _tab_tensor(self, features: FeatureVector) -> torch.Tensor:
        """Convert a FeatureVector to a *standardised* tabular tensor.

        Column order and the z-score constants come from the training config,
        so inference reproduces training pre-processing exactly.
        """
        assert self._config is not None
        names = self._config.feature_names or list(features.model_fields)
        values = np.array(
            [float(getattr(features, n)) for n in names], dtype=np.float64
        )
        mean = np.array(self._config.tab_mean, dtype=np.float64)
        std = np.array(self._config.tab_std, dtype=np.float64)
        if mean.size == values.size and std.size == values.size:
            # Guard against divide-by-zero for constant columns.
            std = np.where(std < 1e-8, 1.0, std)
            values = (values - mean) / std
        return torch.from_numpy(values.astype(np.float32)).unsqueeze(0)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    @torch.no_grad()
    def predict_proba(self, url: str, features: FeatureVector) -> float:
        """Fused risk probability in [0, 1] from URL string + tabular features."""
        if not self.is_loaded:
            raise RuntimeError("Model is not loaded. Call load() first.")
        assert self._model is not None
        self._model.eval()
        fused_logit, _ = self._model(
            self._char_tensor(url), self._tab_tensor(features)
        )
        score = float(torch.sigmoid(fused_logit).item())
        if self._is_allowlisted(url):
            score = min(score, _ALLOWLIST_CAP)
        return score

    @torch.no_grad()
    def predict_url_only(self, url: str) -> float:
        """Risk probability from the URL string alone (no enrichment needed).

        This is the zero-day signal: it works even when every external API
        returns nothing, because it reads the lexical structure of the string.
        """
        if not self.is_loaded:
            raise RuntimeError("Model is not loaded. Call load() first.")
        assert self._model is not None
        self._model.eval()
        _, text_logit = self._model(
            self._char_tensor(url),
            torch.zeros(1, self._config.n_tabular_features),  # type: ignore[union-attr]
        )
        score = float(torch.sigmoid(text_logit).item())
        if self._is_allowlisted(url):
            score = min(score, _ALLOWLIST_CAP)
        return score

    def predict(self, url: str, features: FeatureVector) -> int:
        """Binary label (0 = benign, 1 = malicious) at a 0.5 threshold."""
        return int(self.predict_proba(url, features) >= 0.5)

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------
    def explain_url(
        self, url: str, top_k: int = 3, min_span_len: int = 2
    ) -> List[NeuralExplanation]:
        """Return the most suspicious substrings driving the URL-only score.

        Uses per-character saliency (gradient of the text logit w.r.t. the
        character embeddings), then merges high-saliency neighbours into
        contiguous spans and returns the strongest ``top_k``.
        """
        if not self.is_loaded:
            raise RuntimeError("Model is not loaded. Call load() first.")
        assert self._model is not None and self._config is not None

        clean = (url or "").strip().lower()
        n = min(len(clean), self._config.max_len)
        if n == 0:
            return []

        char_ids = self._char_tensor(url)
        saliency = self._model.text_saliency(char_ids)[:n].cpu().numpy()

        # Normalise to [0, 1] for a stable, comparable importance scale.
        s_max = float(saliency.max()) if saliency.size else 0.0
        if s_max <= 0:
            return []
        norm = saliency / s_max

        # A character is "hot" if it clears the mean importance. Merge runs of
        # hot characters (allowing a 1-char gap) into candidate substrings.
        threshold = max(float(norm.mean()), 0.35)
        spans: list[tuple[int, int]] = []
        start: Optional[int] = None
        gap = 0
        for i in range(n):
            if norm[i] >= threshold:
                if start is None:
                    start = i
                gap = 0
            elif start is not None:
                gap += 1
                if gap > 1:
                    spans.append((start, i - gap + 1))
                    start = None
        if start is not None:
            spans.append((start, n))

        results: list[NeuralExplanation] = []
        for a, b in spans:
            if b - a < min_span_len:
                continue
            substring = clean[a:b]
            importance = float(norm[a:b].mean())
            results.append(
                NeuralExplanation(
                    substring=substring,
                    start=a,
                    end=b,
                    importance=round(importance, 4),
                    human_readable=(
                        f"High-attention token '{substring}' "
                        f"({importance:+.0%} lexical phishing signal)"
                    ),
                )
            )

        results.sort(key=lambda e: e.importance, reverse=True)
        return results[:top_k]
