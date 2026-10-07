"""
ThreatFusion – App-Layer Reuse Adapter (Cross-Layer Correlation)
=================================================================

The concrete realisation of **differentiator #1**: when a device on the monitored network contacts a name (a DNS query, a TLS
SNI), that name goes through the same local models, lists and providers the domain scanner uses, and the answer is folded into the
network alert's score.

What changed in revamp T2c: this adapter used to send **every** observed name straight to VirusTotal (4 a minute on the free tier,
shared with the user's own scans).  It is now a thin wrapper over :class:`~app.network.reputation_gate.ReputationGate`, which decides
per name — filter, cache, de-duplicate, popular list, blocklists, the local URL model — and spends a VirusTotal lookup only on a name
the model flags, within the network's own small budget.  See that module for the order and the guarantees.

Honesty contract
----------------
If a stage cannot answer, the returned :class:`AppLayerSubScore` is ``available=False`` with the real reason and **no fabricated score**.
A cross-layer claim needs corroboration (``corroborated``): a blocklist hit or at least two VirusTotal engines.  A URL-text score alone
is reported and never raises an alert.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from app.network.models import AppLayerSubScore
from app.network.reputation_gate import MIN_CORROBORATING_ENGINES, ReputationGate  # noqa: F401  (re-exported)

logger = logging.getLogger(__name__)


def _looks_like_ip(target: str) -> bool:
    try:
        ipaddress.ip_address((target or "").strip("[]"))
        return True
    except ValueError:
        return False


class AppLayerScorer:
    """Scores an observed domain through the reputation gate."""

    def __init__(self, gate: Optional[ReputationGate] = None) -> None:
        self.gate = gate or ReputationGate()

    async def score(self, target: str, target_type: Optional[str] = None) -> AppLayerSubScore:
        """Assess ``target`` (an observed host name).  IP addresses are not looked up passively: every address a laptop talks to would
        cost a third-party call, and the name that led to it is already assessed."""
        if (target_type or ("ip" if _looks_like_ip(target) else "domain")) == "ip":
            return AppLayerSubScore(available=False, source="private", target=target[:255], target_type="ip",
                                    reason="IP addresses are not looked up passively")
        return await self.gate.assess(target)
