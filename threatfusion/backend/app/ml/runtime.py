"""
Process-wide ML runtime (A2)
============================

One :class:`~app.ml.url_risk.UrlRiskService` for the whole process — the scan router and the network layer's app-layer scorer
share it, so the SHAP explainer and the networks are built once.  Loading is best-effort and *reported*: a component that
fails its integrity / model-card check is left out and the reason is available from ``service.problems`` (shown in
``/health``), never swallowed.

Tests swap the service with :func:`set_url_risk_service`.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from app.ml.url_risk import UrlRiskService

logger = logging.getLogger(__name__)

_service: Optional[UrlRiskService] = None
_lock = threading.Lock()


def url_risk_service() -> UrlRiskService:
    global _service
    if _service is None:
        with _lock:
            if _service is None:
                svc = UrlRiskService()
                try:
                    svc.load()
                except Exception as exc:                       # never take the API down because a model failed
                    logger.error("URL risk service failed to load: %s", exc)
                _service = svc
    return _service


def set_url_risk_service(service: Optional[UrlRiskService]) -> None:
    """Replace (or, with ``None``, reset) the shared service — for tests."""
    global _service
    with _lock:
        _service = service
