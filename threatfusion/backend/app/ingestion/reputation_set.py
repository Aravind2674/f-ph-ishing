"""
ThreatFusion – the set of independent reputation channels, and how a scan uses them (B2)
=======================================================================================

``ReputationSet`` owns one client per source (the API channels in ``reputation.py`` and the local feeds in ``blocklists.py``),
decides which of them apply to a target (:meth:`applicable_sources`), builds the per-scan call list (:meth:`plan`) and folds
the answers into one :class:`~app.models.schemas.ReputationSummary` (:func:`summarize`) for the UI.

The summary is deliberately *not* a score.  It lists who said what, how fresh the local lists are and how many channels
could not answer — turning those into a calibrated probability is the job of the fusion layer (B7), not of a hand-picked
average here.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from typing import Awaitable, Callable, Optional

from app.core.safe_http import blocked_reason
from app.ingestion.blocklists import BulkFeed, OpenPhishFeed, PhishTankFeed, TrancoFeed
from app.ingestion.reputation import Channel, Subject
from app.models.schemas import ProviderResult, ProviderStatus, ReputationSummary

# The order channels are shown in (also the stable order of ``provider_results``).
SOURCES = ["openphish", "phishtank", "urlhaus", "threatfox", "safebrowsing", "urlscan", "otx", "abuseipdb", "greynoise", "tranco"]
LOCAL_FEEDS = ("openphish", "phishtank", "tranco")
# Sources whose answer is *evidence about maliciousness* (Tranco is a popularity prior, GreyNoise is scanner context).
EVIDENCE_SOURCES = frozenset({"openphish", "phishtank", "urlhaus", "threatfox", "safebrowsing", "urlscan", "otx", "abuseipdb"})
NEEDS_IP = frozenset({"abuseipdb", "greynoise"})

_BY_KIND = {
    "url": set(SOURCES),
    "domain": set(SOURCES),
    "ip": set(SOURCES) - {"tranco"},
    "hash": {"threatfox", "otx"},
}


@dataclass(frozen=True)
class Planned:
    source: str
    enabled: bool
    needs_ip: bool
    call: Callable[[Subject], Awaitable[ProviderResult]]


class ReputationSet:
    def __init__(self, clients: dict[str, Channel | BulkFeed]) -> None:
        self.clients = clients

    @staticmethod
    def applicable_sources(kind: str) -> list[str]:
        """The channels that can say anything about a target of this kind (before availability / keys / switches)."""
        return [s for s in SOURCES if s in _BY_KIND.get(kind, set())]

    def plan(self, kind: str, switches: dict[str, bool]) -> list[Planned]:
        return [Planned(source=src, enabled=switches.get(src, True), needs_ip=src in NEEDS_IP,
                        call=self.clients[src].lookup)
                for src in self.applicable_sources(kind) if src in self.clients]

    def feeds(self) -> list[BulkFeed]:
        return [c for c in self.clients.values() if isinstance(c, BulkFeed)]

    def tranco(self) -> Optional[TrancoFeed]:
        c = self.clients.get("tranco")
        return c if isinstance(c, TrancoFeed) else None

    async def close(self) -> None:
        for c in self.clients.values():
            await c.close()


def pick_public_ip(addresses: list[str] | None) -> Optional[str]:
    """The first globally routable address, or ``None`` (an internal answer is never sent to a third party)."""
    for raw in addresses or []:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if blocked_reason(ip) is None:
            return str(ip)
    return None


def with_ip(s: Subject, ip: Optional[str]) -> Subject:
    return replace(s, ip=ip)


def summarize(results: list[ProviderResult], feed_ages: dict[str, Optional[float]]) -> Optional[ReputationSummary]:
    """Fold the per-channel outcomes into one summary; ``None`` if no channel applied to the target at all."""
    counted = [r for r in results if r.status in (ProviderStatus.OK, ProviderStatus.NOT_FOUND, ProviderStatus.ERROR,
                                                  ProviderStatus.NOT_CONFIGURED)]
    if not counted:
        return None
    answered = [r for r in counted if r.status in (ProviderStatus.OK, ProviderStatus.NOT_FOUND)]
    verdicts = [r.data for r in results if r.ok and r.data is not None]
    listed_by = [v.source for v in verdicts if v.listed]
    rank = next((int(v.extra["rank"]) for v in verdicts if v.source == "tranco" and v.extra.get("rank") is not None), None)
    notes: list[str] = []
    gaps = [r.source for r in counted if r.status in (ProviderStatus.ERROR, ProviderStatus.NOT_CONFIGURED)]
    if gaps:
        notes.append(f"{len(gaps)} of {len(counted)} channels gave no answer ({', '.join(gaps)}): unknown, not clean.")
    if not listed_by:
        notes.append("Not being listed is absence of evidence: blocklists are always behind the attackers.")
    if any(v.stale for v in verdicts):
        notes.append("At least one local list is out of date; the last downloaded copy was used.")
    return ReputationSummary(
        channels_applicable=len(counted), channels_answered=len(answered), listed_by=listed_by, verdicts=verdicts,
        popularity_rank=rank, feed_ages={k: (None if v is None else round(v, 3)) for k, v in feed_ages.items()}, notes=notes)
