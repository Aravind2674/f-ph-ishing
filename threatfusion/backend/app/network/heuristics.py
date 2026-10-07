"""
Measurable network heuristics (revamp T2c)
==========================================

Three detectors that need no labelled data and no third party.  Each one returns the **evidence that triggered it**, so an alert can
show exactly what was seen; each has fixed, documented thresholds (``config.py``) — nothing is tuned on a hidden set — and each is
silent below its threshold.  What they can and cannot tell:

``NxdomainBurst``      a device receiving many *no such domain* answers in a minute.  That is what a domain-generation algorithm
                       looks like from the resolver's side (a bot walking through generated names until one exists) — but so is a
                       mistyped config file or a misbehaving app, so the alert says "burst", not "malware".
``name_anomaly``       a name whose label is very long, or long *and* high in entropy, on a registered domain that is not popular.
                       Unsupervised: it measures how random a label looks (Shannon entropy over its characters), not intent.  CDN
                       and hash-named hosts look random too; the popularity check upstream (Tranco) removes most of them.
``BeaconDetector``     a device contacting the same destination at near-regular intervals.  Malware check-ins are periodic; so are
                       mail clients, NTP and telemetry.  Only low-jitter, many-times, long-lived series are reported, and popular
                       destinations are skipped upstream.

All clocks are injected so the tests are deterministic.
"""

from __future__ import annotations

import math
import statistics
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from typing import Callable, Optional


def shannon_entropy(text: str) -> float:
    """Bits per character of ``text`` (0 for empty)."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


# ── NXDOMAIN burst ───────────────────────────────────────────────────────────
@dataclass
class BurstFinding:
    count: int
    window_seconds: float
    names: list[str] = field(default_factory=list)


class NxdomainBurst:
    """Counts *NXDOMAIN* answers per device in a sliding window; reports once per window when ``threshold`` is reached."""

    def __init__(self, threshold: int = 20, window_seconds: float = 60.0, max_devices: int = 2048, sample: int = 10) -> None:
        self.threshold, self.window, self.sample = max(2, threshold), float(window_seconds), sample
        self._hits: "OrderedDict[str, deque[tuple[float, str]]]" = OrderedDict()
        self._last_report: dict[str, float] = {}
        self._max_devices = max_devices

    def observe(self, device: str, name: str, at: float) -> Optional[BurstFinding]:
        dq = self._hits.get(device)
        if dq is None:
            dq = self._hits[device] = deque()
            while len(self._hits) > self._max_devices:
                evicted, _ = self._hits.popitem(last=False)
                self._last_report.pop(evicted, None)
        self._hits.move_to_end(device)
        dq.append((at, name))
        while dq and dq[0][0] < at - self.window:
            dq.popleft()
        if len(dq) < self.threshold or at - self._last_report.get(device, float("-inf")) < self.window:
            return None
        self._last_report[device] = at
        distinct = list(dict.fromkeys(n for _, n in dq))
        return BurstFinding(count=len(dq), window_seconds=self.window, names=distinct[: self.sample])


# ── name anomaly ─────────────────────────────────────────────────────────────
@dataclass
class NameFinding:
    reasons: list[str]
    label: str
    entropy: float


def name_anomaly(name: str, registered_label: Optional[str] = None, *, long_label: int = 40, min_len: int = 16,
                 min_entropy: float = 3.8, long_name: int = 100) -> Optional[NameFinding]:
    """Evidence that a DNS name looks machine-generated or like a tunnel, or ``None``.

    Looks at the registered label (``xjqkzplwvmnb`` in ``xjqkzplwvmnb.example``) and the longest sub-domain label.  A label is
    flagged when it is very long (``long_label`` or more characters — DNS tunnelling packs data into labels) or when it is at least
    ``min_len`` characters with at least ``min_entropy`` bits per character (random-looking).  A whole name of ``long_name`` or
    more characters is flagged too.

    The defaults are the most conservative row of ``ml/name_heuristic_eval.py`` (measured on 360,330 real host names): 0.41 % of benign
    hosts and 7.9 % of phishing hosts are flagged; the long-label rule alone flags 0.02 % and 2.0 %.  (A label of ``n`` characters
    cannot exceed ``log2(n)`` bits, so a 12-character label can never reach 3.6: lengths and entropy have to be read together.)
    """
    name = (name or "").lower().rstrip(".")
    if not name:
        return None
    labels = name.split(".")
    candidates = [registered_label] if registered_label else []
    candidates += [lab for lab in labels[:-1] if lab]
    seen: set[str] = set()
    reasons: list[str] = []
    best_label, best_entropy = "", 0.0
    for label in candidates:
        if not label or label in seen:
            continue
        seen.add(label)
        e = shannon_entropy(label)
        if len(label) >= long_label:
            reasons.append(f"a {len(label)}-character label ({label[:24]}…)")
        elif len(label) >= min_len and e >= min_entropy:
            reasons.append(f"label “{label}” has {len(label)} characters and {e:.2f} bits of entropy per character")
        else:
            continue
        if len(label) > len(best_label):
            best_label, best_entropy = label, e
    if len(name) >= long_name:
        reasons.append(f"a {len(name)}-character name")
        best_label = best_label or labels[0]
        best_entropy = best_entropy or shannon_entropy(best_label)
    return NameFinding(reasons, best_label, best_entropy) if reasons else None


# ── beaconing ────────────────────────────────────────────────────────────────
@dataclass
class BeaconFinding:
    count: int
    period_seconds: float
    jitter: float                      # coefficient of variation of the intervals (std / mean)
    span_seconds: float


class BeaconDetector:
    """Reports a (device, destination) pair contacted at near-regular intervals.

    Connections less than ``merge_seconds`` apart are one visit (a page opens several at once).  A series qualifies with at least
    ``min_events`` visits over at least ``min_span`` seconds, a mean period between ``min_period`` and ``max_period``, and a jitter
    (std / mean of the intervals) of at most ``max_jitter``.  One report per pair per ``cooldown``.
    """

    def __init__(self, min_events: int = 8, min_span: float = 300.0, max_jitter: float = 0.15, min_period: float = 10.0,
                 max_period: float = 3600.0, merge_seconds: float = 2.0, cooldown: float = 3600.0, max_series: int = 5000) -> None:
        self.min_events, self.min_span, self.max_jitter = max(4, min_events), min_span, max_jitter
        self.min_period, self.max_period, self.merge, self.cooldown = min_period, max_period, merge_seconds, cooldown
        self._series: "OrderedDict[tuple[str, str], deque[float]]" = OrderedDict()
        self._reported: dict[tuple[str, str], float] = {}
        self._max_series = max_series

    def observe(self, device: str, destination: str, at: float) -> Optional[BeaconFinding]:
        key = (device, destination)
        dq = self._series.get(key)
        if dq is None:
            dq = self._series[key] = deque(maxlen=max(self.min_events * 4, 64))
            while len(self._series) > self._max_series:
                old, _ = self._series.popitem(last=False)
                self._reported.pop(old, None)
        self._series.move_to_end(key)
        if dq and at - dq[-1] < self.merge:
            return None
        dq.append(at)
        if len(dq) < self.min_events or at - self._reported.get(key, float("-inf")) < self.cooldown:
            return None
        times = list(dq)
        span = times[-1] - times[0]
        if span < self.min_span:
            return None
        intervals = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.fmean(intervals)
        if not (self.min_period <= mean <= self.max_period) or mean <= 0:
            return None
        jitter = statistics.pstdev(intervals) / mean
        if jitter > self.max_jitter:
            return None
        self._reported[key] = at
        return BeaconFinding(count=len(times), period_seconds=round(mean, 1), jitter=round(jitter, 3), span_seconds=round(span, 1))
