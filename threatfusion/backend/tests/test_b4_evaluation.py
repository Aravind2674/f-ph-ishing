"""B4 (evaluation) — how good is the look-alike detector, measured honestly?

``tests/data/b4_lookalike_cases.csv`` is a **synthetic, hand-written** fixture: look-alikes of every kind the detector claims
to catch, genuine brand domains, unrelated domains, and *hard negatives* (ordinary words that contain or nearly equal a brand
name).  It was written by the detector's author, so the numbers below are a regression guard and a sanity check — an
**optimistic upper bound**, not an estimate of field performance (no real phishing feed was used; none is available offline).

The fixture deliberately contains cases the detector is designed to miss (a brand with digits appended, a five-letter brand
typo, a same-name-other-TLD) and ones it is expected to flag wrongly (``ledgers.com``): the test pins those *by name*, so the
trade-off is visible and a change in either direction is a conscious decision.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

import pytest

from app.ml.brands import BrandIndex
from app.ml.lookalike import assess_lookalike

DATA = Path(__file__).parent / "data" / "b4_lookalike_cases.csv"
INDEX = BrandIndex.build()

# Designed misses (label = lookalike, detector does not flag) and expected false positives (label = benign, flagged).
KNOWN_MISSES = {"paypl-help.com", "applle.com", "hdfcbank.co", "incometax-gov-in.com", "flipkart-lucky-draw.in", "paypal123.com"}
KNOWN_FALSE_POSITIVES = {"ledgers.com", "googles.com"}


def _decode(host: str) -> str:
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), host)


def _load() -> list[dict]:
    lines = [ln for ln in DATA.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    rows = list(csv.DictReader(lines))
    for r in rows:
        r["host"] = _decode(r["host"])
    return rows


ROWS = _load()


def _flagged(host: str) -> bool:
    return assess_lookalike(host, INDEX).status == "lookalike"


def test_the_fixture_is_what_it_claims_to_be() -> None:
    labels = Counter(r["label"] for r in ROWS)
    assert set(labels) == {"lookalike", "genuine", "benign"}
    assert labels["lookalike"] >= 40 and labels["genuine"] >= 20 and labels["benign"] >= 30
    assert len({r["host"] for r in ROWS}) == len(ROWS), "no duplicate hosts"
    assert any(r["category"] == "hard_negative" for r in ROWS)


def test_precision_and_recall_on_the_fixture(capsys) -> None:
    tp = fp = fn = tn = 0
    missed, wrong = [], []
    by_kind: dict[str, list[bool]] = {}
    for r in ROWS:
        flagged = _flagged(r["host"])
        if r["label"] == "lookalike":
            by_kind.setdefault(r["category"], []).append(flagged)
            if flagged:
                tp += 1
            else:
                fn += 1
                missed.append(r["host"])
        elif flagged:
            fp += 1
            wrong.append(r["host"])
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn)
    with capsys.disabled():
        print(f"\nB4 fixture: {len(ROWS)} hosts | TP {tp} FP {fp} FN {fn} TN {tn} | precision {precision:.3f} recall {recall:.3f}")
        for kind, hits in sorted(by_kind.items()):
            print(f"  recall[{kind}] = {sum(hits)}/{len(hits)}")
        print(f"  missed: {sorted(missed)}\n  false positives: {sorted(wrong)}")
    assert set(missed) == {_decode(h) for h in KNOWN_MISSES}, "the set of misses changed — decide whether that is intended"
    assert set(wrong) == KNOWN_FALSE_POSITIVES, "the set of false positives changed — decide whether that is intended"
    assert precision >= 0.93 and recall >= 0.85


def test_genuine_brand_domains_are_never_flagged() -> None:
    for r in ROWS:
        if r["label"] == "genuine":
            res = assess_lookalike(r["host"], INDEX)
            assert res.status == "official" and res.match is None, r["host"]


def test_every_flag_is_explained() -> None:
    for r in ROWS:
        res = assess_lookalike(r["host"], INDEX)
        if res.status == "lookalike":
            assert res.match.evidence and res.match.similarity >= res.threshold and res.match.brand_domain, r["host"]
