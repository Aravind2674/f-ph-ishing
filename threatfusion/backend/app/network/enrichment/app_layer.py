"""
ThreatFusion – App-Layer Reuse Adapter (Cross-Layer Correlation)
=================================================================

This is the concrete realisation of **differentiator #1**: when a device on
the monitored network contacts a domain/IP, we route that observed target
through the *exact same* App-Layer scoring pipeline the domain scanner uses
and fold the real result into the network alert's score.

Crucially, this module **imports and reuses** the existing scoring code —
it does not reimplement any of it:

* ``app.ingestion.virustotal.VirusTotalClient``  – real VT reputation
* ``app.ingestion.shodan.ShodanClient``          – real port/CVE exposure (IPs)
* ``app.ml.features.extract_features``           – the 19-dim feature builder
* ``app.ml.baseline.baseline_score``             – rule heuristic
* ``app.ml.fusion_model.FusionModel``            – XGBoost fusion
* ``app.ml.explain.explain_prediction``          – SHAP drivers

Honesty contract
----------------
If VirusTotal cannot be reached (network error, missing key) the returned
``AppLayerSubScore`` is marked ``available=False`` with the real reason and
**no fabricated score is produced**. In that case the correlation engine
will not raise a cross-layer "malicious domain" alert out of thin air — the
DNS observation still feeds the behavioural baseline, but the cross-layer
claim degrades honestly.

``live`` reflects whether the VT lookup used real data: if the App Layer is
running in ``USE_MOCK_DATA=true`` mode we surface that explicitly so a
viewer is never misled into thinking a mock verdict is a live one.
"""

from __future__ import annotations

import logging
import socket
from pathlib import Path
from typing import Optional

from app.core.artifacts import model_path
from app.core.config import get_settings
from app.ingestion.virustotal import VirusTotalClient
from app.ingestion.shodan import ShodanClient
from app.ml.baseline import baseline_score
from app.ml.features import extract_features
from app.ml.fusion_model import FusionModel
from app.ml.explain import explain_prediction
from app.network.models import AppLayerSubScore

logger = logging.getLogger(__name__)


def _load_model() -> FusionModel:
    """Load the shared XGBoost fusion model.

    Mirrors the path-resolution used in ``app.api.scan`` so the network
    layer scores with the identical model artefact.
    """
    model = FusionModel()
    path = model_path("fusion_model.json")  # configured model dir (absolute), not the CWD
    if path is not None:
        try:
            model.load(path)
        except Exception as e:  # incl. ArtifactIntegrityError: refuse the file, keep the API up
            logger.error("XGBoost fusion model NOT loaded from %s: %s", path, e)
    return model


# Loaded once at import — same lifecycle as the App-Layer scan router.
_model = _load_model()


def _ml_label(score: float) -> str:
    """Identical banding to ``app.api.scan._get_ml_label``."""
    if score < 0.25:
        return "Low"
    if score < 0.50:
        return "Medium"
    if score < 0.75:
        return "High"
    return "Critical"


def _unavailable_reason(name: str, res) -> str:
    """Human-readable 'why there is no score' from a non-ok ProviderResult."""
    if res.status.value == "not_found":
        return f"{name} has no record of this target"
    detail = res.reason or res.status.value
    http = f" (HTTP {res.http_status})" if res.http_status else ""
    return f"{name} lookup unavailable: {detail}{http}"


def _looks_like_ip(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return True
    except OSError:
        return False


class AppLayerScorer:
    """Scores an observed domain/IP via the existing App-Layer pipeline."""

    async def score(self, target: str, target_type: Optional[str] = None) -> AppLayerSubScore:
        """Run the real App-Layer pipeline for ``target``.

        Parameters
        ----------
        target : str
            The observed domain or IP address (e.g. from a DNS query).
        target_type : str | None
            'domain' or 'ip'. Inferred from the value when omitted.
        """
        settings = get_settings()
        use_mock = settings.USE_MOCK_DATA
        if target_type is None:
            target_type = "ip" if _looks_like_ip(target) else "domain"

        # A0-5: without a real VirusTotal credential there is nothing honest to score.
        # Report "unavailable" with the reason instead of calling VT with a placeholder.
        if not settings.provider_statuses()["virustotal"].configured:
            return AppLayerSubScore(
                available=False,
                reason="VirusTotal is not configured (set VIRUSTOTAL_API_KEY)",
                target=target,
                target_type=target_type,
                live=not use_mock,
            )

        vt_client = VirusTotalClient(
            api_key=settings.VIRUSTOTAL_API_KEY, use_mock=use_mock
        )
        shodan_client = ShodanClient(
            api_key=settings.SHODAN_API_KEY, use_mock=use_mock
        )

        try:
            shodan = None
            # Domains and IPs both go through lookup_domain in the existing client contract
            # (mock handles IP-as-domain, and live VT resolves domains directly).
            # The client never raises: it returns a ProviderResult whose status says what
            # happened. Only an `ok` answer is scored — a failed lookup used to arrive here as
            # an empty result and was reported as "0/0 engines (live)".
            vt_res = await vt_client.lookup_domain(target)
            if not vt_res.ok:
                return AppLayerSubScore(
                    available=False,
                    reason=_unavailable_reason("VirusTotal", vt_res),
                    target=target,
                    target_type=target_type,
                    live=not use_mock,
                )
            vt = vt_res.data

            # For IPs we can additionally consult Shodan/InternetDB for real
            # exposure context (free, no key needed).
            if target_type == "ip":
                sh_res = await shodan_client.lookup_ip(target)
                shodan = sh_res.data if sh_res.ok else None

            features = extract_features(vt, shodan, None, None)
            b_score = baseline_score(features)

            if _model.is_loaded:
                m_score = _model.predict_proba(features)
                explanations = explain_prediction(_model, features)
                top = [e.human_readable for e in explanations[:4]]
            else:
                # Fallback path identical to the App-Layer scan router.
                m_score = b_score
                top = []

            malicious = getattr(vt, "malicious_count", 0) or 0
            suspicious = getattr(vt, "suspicious_count", 0) or 0
            total = getattr(vt, "total_engines", 0) or 0
            # "flagged" mirrors the App-Layer's own notion of a bad verdict:
            # any AV engine flags it, or the fused ML score crosses High.
            flagged = malicious > 0 or suspicious > 0 or m_score >= 0.5

            return AppLayerSubScore(
                available=True,
                target=target,
                target_type=target_type,
                baseline_score=round(float(b_score), 4),
                ml_score=round(float(m_score), 4),
                ml_label=_ml_label(m_score),
                vt_malicious_count=malicious,
                vt_total_engines=total,
                flagged=flagged,
                top_explanations=top,
                live=not use_mock,
            )
        finally:
            await vt_client.close()
            await shodan_client.close()
