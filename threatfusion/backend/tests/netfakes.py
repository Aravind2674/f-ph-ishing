"""Small fakes for the network-layer tests: a URL model that flags (or clears) every name, so the gate's stages can be driven exactly."""

from __future__ import annotations

from contextlib import contextmanager

from app.ml.runtime import set_url_risk_service
from app.models.schemas import RiskExplanation, UrlRiskAssessment


class FakeUrlModel:
    loaded = True
    cnn_loaded = False
    fusion_loaded = False

    def __init__(self, score: float = 0.97, flagged: bool = True) -> None:
        self.score, self.flagged, self.calls = score, flagged, 0

    def assess(self, url: str, explain: bool = True):
        self.calls += 1
        expl = ([RiskExplanation(feature_name="lookalike_score", feature_value=0.95, shap_value=2.7, unit="log-odds", probability_delta=0.3,
                                 group="brand", human_readable="Resemblance to a protected brand — raises the score by 2.70 log-odds")]
                if explain else [])
        return UrlRiskAssessment(score=self.score, headline_score=self.score, flagged=self.flagged), expl, []

    def band(self, score):
        return "Unknown" if score is None else ("Critical" if score >= 0.9 else "High" if score >= 0.6 else "Medium" if score >= 0.3 else "Low")


@contextmanager
def url_model(score: float = 0.97, flagged: bool = True):
    model = FakeUrlModel(score, flagged)
    set_url_risk_service(model)                      # type: ignore[arg-type]
    try:
        yield model
    finally:
        set_url_risk_service(None)
