"""
Brand impersonation: does this domain pretend to be someone else's? (B4)
=======================================================================

Phishing sites rarely use their own name; they borrow a trusted one.  The detector compares the scanned host with a list of
*protected brands* (``ml/brands.py``) and reports ``lookalike_of`` — which brand, by which trick, with what evidence.

The tricks it recognises (``kind``), each with a fixed, documented rule score (a heuristic of how strong that *kind* of
resemblance is — **not** a probability, and not tuned on any data we have not shown):

=====================  =====  =====================================================================================
kind                   score  example
=====================  =====  =====================================================================================
homoglyph              0.98   ``pаypal.com`` (Cyrillic а), ``xn--pypal-4ve.com`` — equal to the brand after Unicode TR39
                              confusable mapping
leetspeak              0.95   ``paypa1``, ``micr0s0ft``, ``arnazon`` (``rn`` reads as ``m``) — equal after digit / sequence
                              mapping
brand_in_subdomain     0.95   ``paypal.com.secure-login.xyz`` — the brand (or its official domain) sits in a *subdomain* of
                              an unrelated registered domain
brand_keyword          0.92   ``paypal-secure.com``, ``hdfcbank-login.com``, ``paypalsupport.net`` — the brand name plus a
                              word phishers like (login, verify, kyc, refund…)
typo                   0.90   ``paypall.com`` — one edit from the brand (two for brands of 9+ letters: 0.82)
separator              0.88   ``pay-pal.com`` — equal once the hyphens are removed
same_name_other_tld    0.70   ``hdfcbank.co`` — the brand's own name on a domain that is not its own (candidate only: it may be
                              a defensive registration, so it is below the default flagging threshold of 0.80)
contains_brand         0.55   ``applesauce-recipes.com`` — an ordinary word that happens to contain a brand (candidate only)
=====================  =====  =====================================================================================

Design choices, and why
-----------------------
* **Registered label, not the whole host.**  ``login.paypal.com`` is genuine and ``paypal.com.evil.xyz`` is not; the
  public-suffix list (tldextract) tells us which part the owner controls.  Official domains, and anything under a
  government-only suffix (``.gov.in``, ``.nic.in``), are never flagged.
* **Normalise both sides** with the same canonical form (``ml/confusables``): ``pаypa1`` and ``paypal`` meet in one lookup.
* **Conservative where words are ordinary.**  Brands of four letters or fewer match only as a standalone hyphen-separated
  word next to a risk word (``sbi-login``), never inside other words (``sbirthday``); typo matching needs 6+ letters;
  popular-site brands (Tranco) get no containment matching at all.  False positives cost trust; the evaluation fixture
  (``tests/data/b4_lookalike_cases.csv``) reports precision and recall so this trade-off is visible, not hidden.
* **Everything is explained.**  Each match lists the substitutions or edits that led to it.

Deterministic, no network, no model: it runs in the fast tier in well under a millisecond per host.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from app.core.targets import _extractor
from app.ml import confusables as cf
from app.ml.brands import GOVERNMENT_SUFFIXES, MIN_CONTAINMENT_LENGTH, RISK_WORDS, Brand, BrandIndex
from app.models.schemas import BrandCheck, LookalikeMatch

DEFAULT_THRESHOLD = 0.80
_MAX_CANDIDATES = 5
_MAX_SUBDOMAIN_LABELS = 6

SCORES = {
    "homoglyph": 0.98, "leetspeak": 0.95, "brand_in_subdomain": 0.95, "brand_keyword": 0.92, "typo": 0.90,
    "separator": 0.88, "same_name_other_tld": 0.70, "contains_brand": 0.55,
}
_PRIORITY = {kind: rank for rank, kind in enumerate(SCORES)}            # insertion order = strongest first
_OBFUSCATED_BONUS = 0.03                                                 # brand + risk word, with the brand also disguised

# Risk words compared in canonical form too (``claim`` folds to ``daim``, ``cl`` → ``d``).
_RISK = frozenset(RISK_WORDS | {cf.canonical(w)[0] for w in RISK_WORDS})


@dataclass
class _Hit:
    brand: Brand
    kind: str
    similarity: float
    matched: str
    evidence: list[str] = field(default_factory=list)
    distance: Optional[int] = None
    ambiguous: bool = False        # the matched word is also a risk word (``booking``): weaker as a brand signal


# ── helpers ─────────────────────────────────────────────────────────────────
def _explain(text: str, canon: str) -> list[str]:
    """Human-readable list of the character substitutions that turn ``text`` into ``canon``."""
    plain, steps = cf.canonical(text)
    lines = [s.describe() for s in steps]
    if canon != plain:                                    # the ``1`` read as ``i`` instead of ``l``
        lines = [line for line in lines if not line.startswith("'1'")]
        lines.append("'1' (U+0031 DIGIT ONE) can be read as 'i' as well as 'l'")
    return list(dict.fromkeys(lines))


def _substitution_kind(text: str) -> str:
    steps = cf.canonical(text)[1]
    return "homoglyph" if any(s.kind in ("homoglyph", "diacritic") for s in steps) else "leetspeak"


def _split(host: str) -> tuple[Optional[tuple[list[str], str, str]], str]:
    """``(subdomain labels, registered label, public suffix)`` of ``host``, or ``(None, why not)``."""
    h = (host or "").strip().lower()
    if "://" in h:
        h = urlsplit(h).hostname or ""
    h = h.strip("[]").rstrip(".")
    if not h:
        return None, "no host to check"
    try:
        ipaddress.ip_address(h)
        return None, "an IP address has no brand name to compare"
    except ValueError:
        pass
    if "." not in h:
        return None, "not a registrable domain name"
    ext = _extractor()(h)
    if ext.suffix and not ext.domain:
        return None, "only a public suffix"
    if ext.suffix and ext.domain:
        label, suffix, sub = ext.domain, ext.suffix, ext.subdomain
    else:                                                  # unknown TLD: treat the last label as the suffix
        parts = h.split(".")
        label, suffix, sub = parts[-2], parts[-1], ".".join(parts[:-2])
    return ([p for p in sub.split(".") if p][-_MAX_SUBDOMAIN_LABELS:], label, suffix), ""


def _is_government(suffix: str) -> bool:
    return any(suffix == g or suffix.endswith("." + g) for g in GOVERNMENT_SUFFIXES)


# ── label analysis ──────────────────────────────────────────────────────────
def _label_hits(label: str, index: BrandIndex, *, subdomain: bool = False) -> list[_Hit]:
    """Every way ``label`` resembles a protected brand.  ``subdomain=True`` keeps only the strong, specific rules."""
    hits: list[_Hit] = []
    variants = cf.canonical_variants(label)
    sub_kind = _substitution_kind(label)

    # 1. the whole label equals a brand name once look-alike characters are normalised
    for canon in variants:
        for brand, original in index.exact(canon):
            if subdomain and (brand.source != "curated" or len(canon) < MIN_CONTAINMENT_LENGTH):
                continue
            if label == original.lower():
                if subdomain:
                    hits.append(_Hit(brand, "brand_in_subdomain", SCORES["brand_in_subdomain"], label,
                                     [f"a subdomain label '{label}' is {brand.name}'s name"]))
                else:
                    hits.append(_Hit(brand, "same_name_other_tld", SCORES["same_name_other_tld"], label,
                                     [f"'{label}' is {brand.name}'s own name, on a domain that is not one of its "
                                      f"official domains"]))
                continue
            kind = "brand_in_subdomain" if subdomain else sub_kind
            hits.append(_Hit(brand, kind, SCORES[kind], label,
                             [f"'{label}' reads as '{canon}' = {brand.name}'s name"] + _explain(label, canon)))

    if not subdomain:
        # 2. equal once the hyphens are removed
        if "-" in label:
            collapsed = label.replace("-", "")
            for canon in cf.canonical_variants(collapsed):
                if len(canon) < MIN_CONTAINMENT_LENGTH:
                    continue
                for brand, original in index.exact(canon):
                    hits.append(_Hit(brand, "separator", SCORES["separator"], label,
                                     [f"removing the hyphens from '{label}' gives '{collapsed}' = {brand.name}'s name"]
                                     + (_explain(collapsed, canon) if collapsed != canon else [])))
        else:
            # 3. a small typo (never on hyphenated labels: those are handled as words below)
            for canon in variants:
                for brand, d in index.near(canon):
                    sim = index.typo_similarity(brand, d)
                    if sim is None:
                        continue
                    line = (f"'{label}' is {d} edit{'s' if d > 1 else ''} from '{brand.key}'" if canon == label else
                            f"'{label}' reads as '{canon}', {d} edit{'s' if d > 1 else ''} from '{brand.key}'")
                    hits.append(_Hit(brand, "typo", sim, label, [line], distance=d))

    # 4. the brand name as a word (or inside a word) together with a risk word — curated brands only
    tokens = [t for t in label.split("-") if t]
    token_variants = [cf.canonical_variants(t) for t in tokens]
    for ti, token in enumerate(tokens):
        others = [t for tj, t in enumerate(tokens) if tj != ti]
        risk = next((o for o in others if o in _RISK or cf.canonical(o)[0] in _RISK), None)
        for canon in token_variants[ti]:
            standalone = [(b, o) for b, o in index.exact(canon) if b.source == "curated"]
            for brand, original in standalone:
                if not others:
                    continue                                   # a lone word is rule 1
                obfuscated = token != original.lower()
                notes = _explain(token, canon) if obfuscated else []
                if risk is not None:
                    score = SCORES["brand_keyword"] + (_OBFUSCATED_BONUS if obfuscated else 0.0)
                    hits.append(_Hit(brand, "brand_keyword", round(score, 2), token,
                                     [f"'{token}' is {brand.name}'s name, next to the risk word '{risk}'"] + notes,
                                     ambiguous=canon in _RISK))
                elif not subdomain:
                    hits.append(_Hit(brand, "contains_brand", SCORES["contains_brand"], token,
                                     [f"'{token}' is {brand.name}'s name used as a word in '{label}'"] + notes))
            if standalone:
                continue
            for cb_canon, brand in index.curated_labels():
                if len(cb_canon) < MIN_CONTAINMENT_LENGTH or cb_canon not in canon:
                    continue
                at = canon.find(cb_canon)
                pieces = [p for p in (canon[:at], canon[at + len(cb_canon):]) if p]
                if pieces and all(p in _RISK for p in pieces):
                    obfuscated = canon != token
                    score = SCORES["brand_keyword"] + (_OBFUSCATED_BONUS if obfuscated else 0.0)
                    hits.append(_Hit(brand, "brand_keyword", round(score, 2), token,
                                     [f"'{token}' joins {brand.name}'s name '{cb_canon}' to "
                                      f"{', '.join(repr(p) for p in pieces)}"] + (_explain(token, canon) if obfuscated else [])))
                elif not subdomain:
                    hits.append(_Hit(brand, "contains_brand", SCORES["contains_brand"], token,
                                     [f"'{token}' contains {brand.name}'s name '{cb_canon}'"]))

    # a word that is both a brand and an ordinary risk word ("booking") only counts when no clearer brand word is present
    if any(h.kind == "brand_keyword" and not h.ambiguous for h in hits):
        hits = [h for h in hits if not (h.kind == "brand_keyword" and h.ambiguous)]
    if subdomain:
        hits = [_Hit(h.brand, "brand_in_subdomain", SCORES["brand_in_subdomain"], h.matched, h.evidence)
                if h.kind == "brand_keyword" else h for h in hits]
    return hits


def _official_in_subdomain(sub_labels: list[str], registered: str, index: BrandIndex) -> list[_Hit]:
    """A brand's official domain written out inside the subdomain: ``paypal.com`` in ``paypal.com.evil.xyz``."""
    hits: list[_Hit] = []
    n = len(sub_labels)
    for i in range(n):
        for j in range(i + 2, n + 1):
            window = ".".join(sub_labels[i:j])
            brand = index.official(window)
            if brand is not None:
                hits.append(_Hit(brand, "brand_in_subdomain", SCORES["brand_in_subdomain"], window,
                                 [f"the subdomain '{window}' is {brand.name}'s official domain, but the site is "
                                  f"registered under '{registered}'"]))
    return hits


def _to_match(hit: _Hit, mixed: bool, scripts: set[str]) -> LookalikeMatch:
    evidence = list(hit.evidence)
    if mixed:
        evidence.append(f"the host mixes scripts ({', '.join(sorted(scripts))}) — the homograph-attack signature")
    domains = hit.brand.domains
    evidence.append(f"{hit.brand.name}'s official domain{'s' if len(domains) > 1 else ''}: {', '.join(domains[:3])}")
    return LookalikeMatch(
        brand=hit.brand.name, brand_domain=domains[0], sector=hit.brand.sector, country=hit.brand.country,
        source=hit.brand.source, kind=hit.kind, similarity=round(hit.similarity, 2), distance=hit.distance,  # type: ignore[arg-type]
        matched=hit.matched, evidence=evidence, mixed_script=mixed)


# ── public API ──────────────────────────────────────────────────────────────
def assess_lookalike(host: str, index: BrandIndex, threshold: float = DEFAULT_THRESHOLD) -> BrandCheck:
    """Compare ``host`` with the protected brands in ``index``; flag it when the best resemblance scores ≥ ``threshold``."""
    stats = index.stats()
    base = {"brands_checked": stats["curated"], "popular_checked": stats["popular"], "threshold": threshold}
    parsed, why = _split(host)
    if parsed is None:
        return BrandCheck(status="no_match", notes=[why], **base)
    sub_labels, label, suffix = parsed
    registered = f"{label}.{suffix}"

    owner = index.official(registered)
    if owner is not None:
        return BrandCheck(status="official", official_of=owner.name, **base,
                          notes=[f"'{registered}' is one of {owner.name}'s official domains"])
    if _is_government(suffix):
        return BrandCheck(status="official", official_of=f"government suffix .{suffix}", **base,
                          notes=[f"'.{suffix}' is a government-only suffix: it cannot be registered by a third party, "
                                 f"so '{registered}' is not a brand look-alike"])

    notes: list[str] = []
    label_uni = cf.to_unicode(label)
    if label_uni != label:
        notes.append(f"decoded punycode label '{label}' as '{label_uni}'")
    sub_uni = [cf.to_unicode(s) for s in sub_labels]
    all_scripts: set[str] = set()
    mixed = False
    for part in [label_uni, *sub_uni]:
        if cf.is_mixed_script(part):
            mixed = True
            all_scripts |= cf.scripts(part)

    hits = _label_hits(label_uni, index)
    hits += _official_in_subdomain(sub_labels, registered, index)
    for sub in sub_uni:
        hits += _label_hits(sub, index, subdomain=True)

    best: dict[tuple[str, str], _Hit] = {}                 # one finding per brand: its strongest
    for hit in hits:
        key = (hit.brand.source, hit.brand.key)
        cur = best.get(key)
        if cur is None or (hit.similarity, -_PRIORITY[hit.kind]) > (cur.similarity, -_PRIORITY[cur.kind]):
            best[key] = hit
    ranked = sorted(best.values(), key=lambda h: (-h.similarity, _PRIORITY[h.kind], h.brand.key))
    matches = [_to_match(h, mixed, all_scripts) for h in ranked]

    if matches and matches[0].similarity >= threshold:
        return BrandCheck(status="lookalike", match=matches[0], candidates=matches[1:1 + _MAX_CANDIDATES], notes=notes, **base)
    return BrandCheck(status="no_match", candidates=matches[:_MAX_CANDIDATES], notes=notes, **base)
