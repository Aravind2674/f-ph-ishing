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
* ``app.ml.runtime.url_risk_service``            – the calibrated URL-text models (tree + CNN + fusion) and their SHAP drivers

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

from app.core import privacy
from app.core.config import get_settings
from app.core.hub import hub
from app.ingestion.shodan import ShodanClient
from app.ml.baseline import baseline_score
from app.ml.features import extract_features
from app.ml.runtime import url_risk_service
from app.network.models import AppLayerSubScore

logger = logging.getLogger(__name__)

MIN_CORROBORATING_ENGINES = 2


def _ml_label(score: float) -> str:
    """Severity band of a score: the URL models' operating-point bands; the plain quartiles for the baseline fallback."""
    svc = url_risk_service()
    if svc.loaded:
        return svc.band(score)
    if score < 0.25:
        return "Low"
    if score < 0.50:
        return "Medium"
    if score < 0.75:
        return "High"
    return "Critical"


_PRIVACY_REASON = {
    "private_name": "Private/local name",
    "single_label": "Single-label (local) name",
    "private_address": "Private IP address",
    "invalid_name": "Malformed name",
}


def _unavailable_reason(name: str, res) -> str:
    """Human-readable 'why there is no score' from a non-ok ProviderResult."""
    if res.status.value == "not_found":
        return f"{name} has no record of this target"
    detail = res.reason or res.status.value
    http = f" (HTTP {res.http_status})" if res.http_status else ""
    retry = f", retry in {int(res.retry_after)}s" if getattr(res, "retry_after", None) else ""
    return f"{name} lookup unavailable: {detail}{http}{retry}"


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

        # DNS names seen on the LAN may be internal hostnames (printer.local, nas, reverse-DNS) or contain
        # arbitrary attacker-chosen bytes. They are still learned locally by the baseline store, but are
        # NEVER sent to a third-party service nor interpolated into a provider URL (A0-10).
        blocked = privacy.provider_block_reason(target)
        if blocked:
            return AppLayerSubScore(
                available=False,
                reason=f"{_PRIVACY_REASON.get(blocked, blocked)} — not sent to third-party services",
                target=target[:255],
                target_type=target_type,
                live=not use_mock,
            )

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

        vt_client = hub.virustotal()        # the SAME client (quota + cache) the scans use; never closed here
        shodan_client = ShodanClient(
            api_key=settings.SHODAN_API_KEY, use_mock=use_mock
        )

        try:
            shodan = None
            # IPs go to VT's /ip_addresses endpoint, domains to /domains (A1-1).
            # The client never raises: it returns a ProviderResult whose status says what
            # happened. Only an `ok` answer is scored — a failed lookup used to arrive here as
            # an empty result and was reported as "0/0 engines (live)".
            vt_res = await (vt_client.lookup_ip(target) if target_type == "ip" else vt_client.lookup_domain(target))
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

            ml = url_risk_service()
            url_flagged = False
            if target_type != "ip" and ml.loaded:
                # The URL-text models read the observed domain itself (a calibrated probability, SHAP evidence).
                assessment, explanations, _ = ml.assess(target)
                m_score = assessment.headline_score
                url_flagged = assessment.flagged
                top = [e.human_readable for e in explanations[:4]]
            else:
                # An IP has no URL text to read (or the model is not loaded): the baseline stands in, labelled as such by
                # ``top_explanations`` being empty — it is never presented as an ML opinion.
                m_score = b_score
                top = []

            malicious = getattr(vt, "malicious_count", 0) or 0
            suspicious = getattr(vt, "suspicious_count", 0) or 0
            total = getattr(vt, "total_engines", 0) or 0
            # A3: one engine out of ~70 flagging a domain is the commonest kind of false positive, and a URL-text score alone is
            # weak (FPR ≈ 1 % per name, on thousands of names a day).  A cross-layer claim needs corroboration: at least TWO
            # engines (malicious + suspicious).  The URL-text score is still reported, and still adds points when corroborated.
            flagged = (malicious + suspicious) >= MIN_CORROBORATING_ENGINES

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
                source="virustotal",
                corroborated=flagged,
            )
        finally:
            await shodan_client.close()
