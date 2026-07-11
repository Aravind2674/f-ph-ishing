"""
ThreatFusion – ML Fusion Model
================================

Wraps a **gradient‑boosted decision tree** (XGBoost) that fuses the
13‑dimensional ``FeatureVector`` into a single risk probability.

Why XGBoost?
------------
1. **Tabular data champion** – XGBoost consistently wins Kaggle
   competitions on structured/tabular datasets, which is exactly what
   our feature vector is.
2. **Fast inference** – a trained XGBoost model predicts in microseconds,
   well within our 2‑second API latency budget.
3. **Native SHAP support** – the ``shap.TreeExplainer`` is optimised for
   tree ensembles and produces exact (not approximate) Shapley values.
4. **Small model file** – the serialised ``.json`` model is typically
   < 1 MB, easy to version‑control and deploy.

The class follows a **load → predict** lifecycle:

1. ``load(path)`` deserialises a pre‑trained XGBoost model from disk.
2. ``predict(features)`` returns a binary label (0 or 1).
3. ``predict_proba(features)`` returns a continuous probability in [0, 1].
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import numpy as np
import xgboost as xgb

from app.models.schemas import FeatureVector

logger = logging.getLogger(__name__)


class FusionModel:
    """Inference wrapper around a pre‑trained XGBoost classifier.

    Attributes
    ----------
    _model : object | None
        The loaded XGBoost ``Booster`` or ``XGBClassifier`` instance.
        ``None`` until ``load()`` is called.
    _model_path : Path | None
        Path to the serialised model file on disk.
    """

    def __init__(self) -> None:
        self._model: Optional[xgb.XGBClassifier] = None
        self._model_path: Optional[Path] = None
        logger.info("FusionModel instance created (model not yet loaded)")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self, model_path: str | Path) -> None:
        """Load a pre‑trained XGBoost model from disk.

        Parameters
        ----------
        model_path : str | Path
            Path to a serialised XGBoost model file (``.json`` or
            ``.ubj``).

        Raises
        ------
        FileNotFoundError
            If ``model_path`` does not exist.
        """
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found at {path}")
            
        self._model = xgb.XGBClassifier()
        self._model.load_model(str(path))
        self._model_path = path
        
        logger.info("Fusion model successfully loaded from %s", path)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, features: FeatureVector) -> int:
        """Return a binary risk label (0 = benign, 1 = malicious).

        Parameters
        ----------
        features : FeatureVector
            The 13‑dimensional feature vector for a single scan.

        Returns
        -------
        int
            Binary prediction: 0 or 1.
        """
        if not self.is_loaded:
            raise RuntimeError("Model is not loaded. Call load() first.")
            
        arr = self.feature_vector_to_array(features)
        pred = self._model.predict(arr)
        return int(pred[0])

    def predict_proba(self, features: FeatureVector) -> float:
        """Return the predicted probability of the target being malicious.

        This probability is used as the ``ml_score`` in the API response
        and is the value explained by the SHAP module.

        Parameters
        ----------
        features : FeatureVector
            The 13‑dimensional feature vector for a single scan.

        Returns
        -------
        float
            Probability in [0.0, 1.0] where higher = more likely malicious.
        """
        if not self.is_loaded:
            raise RuntimeError("Model is not loaded. Call load() first.")
            
        arr = self.feature_vector_to_array(features)
        proba = self._model.predict_proba(arr)
        return float(proba[0][1])

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @property
    def is_loaded(self) -> bool:
        """Check whether a model has been loaded into memory."""
        return self._model is not None

    def feature_vector_to_array(self, features: FeatureVector) -> np.ndarray:
        """Convert a ``FeatureVector`` Pydantic model to a NumPy array.

        The column order is determined by iterating over the model's
        fields in declaration order, which matches the order used
        during training.

        Parameters
        ----------
        features : FeatureVector
            Feature vector to convert.

        Returns
        -------
        np.ndarray
            Shape ``(1, 13)`` float64 array.
        """
        # Ensure ordering matches exactly what XGBoost expects based on schemas.py
        values = [getattr(features, name) for name in features.model_fields]
        return np.array([values], dtype=np.float64)
