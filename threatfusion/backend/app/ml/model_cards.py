"""
Model cards (A2-6)
==================

Every shipped model has ``ml/models/<name>.card.json`` — what it was trained on (sources, hashes, date range), the exact feature
schema, how it was evaluated (metrics **with 95 % confidence intervals**), how it was calibrated, and what it must not be used
for.  The API loads the card at start-up and shows a summary in ``/health``; a card that is missing, malformed, or whose feature
schema does not match the code **disables the model** (``problem`` says why) instead of letting a mismatched model score
silently.  ``ml/evaluate.py --report`` writes the cards, so the numbers in a card are the numbers of the last evaluation run.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional, Sequence

from app.core.artifacts import default_models_dir, verify_artifact

logger = logging.getLogger(__name__)

REQUIRED = ("name", "version", "task", "created_at", "feature_schema", "data", "metrics", "limitations", "intended_use")


def card_path(name: str, models_dir: Optional[Path] = None) -> Path:
    return (models_dir or default_models_dir()) / f"{name}.card.json"


def load_card(name: str, models_dir: Optional[Path] = None) -> Optional[dict]:
    """The parsed, integrity-checked card, or ``None`` if there is none (callers report that as a reason, never hide it)."""
    path = card_path(name, models_dir)
    if not path.exists():
        return None
    verify_artifact(path)
    return json.loads(path.read_text(encoding="utf-8"))


def validate_card(card: Optional[dict], *, expected_version: int, expected_names: Sequence[str]) -> Optional[str]:
    """``None`` if the card is complete and its schema matches the code, else a one-line reason to disable the model."""
    if card is None:
        return "no model card"
    missing = [k for k in REQUIRED if k not in card]
    if missing:
        return f"model card is missing {', '.join(missing)}"
    schema = card["feature_schema"]
    if schema.get("version") != expected_version:
        return f"feature schema version {schema.get('version')} != code {expected_version}"
    if list(schema.get("names", [])) != list(expected_names):
        return "feature names/order differ from the code"
    return None


def summary(card: Optional[dict], problem: Optional[str]) -> dict:
    """The compact view shown in ``/health``."""
    if card is None:
        return {"status": "disabled", "reason": problem}
    test = (card.get("metrics") or {}).get("test") or {}
    return {
        "status": "ok" if problem is None else "disabled", "reason": problem, "name": card.get("name"), "version": card.get("version"),
        "trained_on": (card.get("data") or {}).get("source"), "date_range": (card.get("data") or {}).get("date_range"),
        "test_pr_auc": test.get("pr_auc"), "test_roc_auc": test.get("roc_auc"), "calibrated": bool((card.get("calibration") or {}).get("kind")),
        "limitations": card.get("limitations", [])[:3],
    }
