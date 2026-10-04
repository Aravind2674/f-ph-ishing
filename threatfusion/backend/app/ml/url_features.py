"""
URL-string features for the maliciousness model (A2-1)
======================================================

Every feature here is computable from the **URL string alone** — no third-party call, no network, a few tens of microseconds —
so the same function runs in the fast tier (B1), in the browser-extension path, and in offline training over hundreds of
thousands of labelled URLs.  One definition used by both training and serving means no train/serve skew.

Why only URL features?  Infrastructure signals (RDAP age, DNS, TLS, CT, reputation) need one live lookup per URL against a
third party — and, for TLS, a connection to the phishing host itself — so they cannot honestly be collected for a
500k-sample training set (``ml/collect.py`` explains).  They stay in the scan as *reported evidence* and enter fusion (B7)
through their own calibrated channels once labelled data for them exists.

Leakage rules honoured here (master prompt A2-1: "a feed that supplies labels can't also be a feature")
-------------------------------------------------------------------------------------------------------
* **No popularity rank** (Tranco supplies benign labels in other datasets) and **no blocklist membership**.
* **No scheme** (``https://`` flips a naive model; see ``url_canon``) — the canonical form drops it.
* The brand features come from the *curated* brand list (``ml/brands``), which was written without looking at this data.

Feature groups (used by B9 to report how much the model leans on cheap-to-evade *surface* features):

``surface``  length / character-class statistics — trivially changed by an attacker
``host``     structure of the host name — subdomain depth, hyphens, digits, IP literal, punycode, TLD
``path``     path / query structure
``risk``     phishing-flavoured words ("login", "verify", "secure"…) in host, path, query
``brand``    impersonation of a protected brand (confusables, brand + keyword, brand in a subdomain or in the path)
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from functools import lru_cache
from typing import Optional

from app.core.targets import _extractor
from app.ml import confusables as cf
from app.ml.brands import CURATED_BRANDS, RISK_WORDS, BrandIndex
from app.ml.lookalike import assess_lookalike
from app.ml.url_canon import split_canonical

URL_FEATURE_SCHEMA_VERSION = 1

# A-priori list (not fitted to any data): TLDs that are common among legitimate sites.
COMMON_TLDS = frozenset({"com", "org", "net", "edu", "gov", "io", "co", "uk", "de", "in", "info", "app", "dev"})

FEATURE_GROUPS: dict[str, str] = {}


def _group(group: str, *names: str) -> list[str]:
    for n in names:
        FEATURE_GROUPS[n] = group
    return list(names)


FEATURE_NAMES: list[str] = (
    _group("surface", "url_len", "host_len", "path_len", "query_len", "digit_ratio", "letter_ratio", "special_count",
           "upper_ratio", "url_entropy")
    + _group("host", "host_dots", "host_hyphens", "host_digit_ratio", "subdomain_depth", "registered_label_len", "tld_len",
             "tld_is_common", "host_is_ip", "host_has_port", "host_has_userinfo", "host_is_punycode", "host_mixed_script",
             "host_entropy", "host_longest_label")
    + _group("path", "path_segments", "path_longest_segment", "path_entropy", "query_params", "path_has_double_slash",
             "path_has_extension", "path_digit_ratio")
    + _group("risk", "risk_words_host", "risk_words_path", "risk_words_query")
    + _group("brand", "lookalike_score", "lookalike_flagged", "is_official_domain", "brand_in_subdomain", "brand_in_path",
             "brand_keyword")
)

_TOKEN = re.compile(r"[a-z0-9]+")
_EXT = re.compile(r"\.[a-z0-9]{2,5}$")
_SPECIAL = set("@!$&'()*+,;=%~#[]{}|\\^`<>\"")


@lru_cache(maxsize=1)
def _index() -> BrandIndex:
    return BrandIndex.build()


@lru_cache(maxsize=1)
def _brand_path_regex() -> re.Pattern:
    labels = sorted({lab for b in CURATED_BRANDS for lab in b.labels if len(lab) >= 5}, key=len, reverse=True)
    return re.compile("|".join(re.escape(x) for x in labels))


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def _ratio(count: int, total: int) -> float:
    return count / total if total else 0.0


def _risk_count(text: str) -> int:
    return sum(1 for t in _TOKEN.findall(text.lower()) if t in RISK_WORDS)


def extract_url_features(raw: str, index: Optional[BrandIndex] = None) -> dict[str, float]:
    """The features of one URL (any scheme / ``www`` / case variant gives the same values), in ``FEATURE_NAMES`` order."""
    host_part, rest = split_canonical(raw)
    text = host_part + rest
    userinfo, _, hostport = host_part.rpartition("@")
    host = hostport
    has_port = 0
    if hostport.startswith("["):
        host = hostport.split("]", 1)[0].lstrip("[")
        has_port = int("]:" in hostport)
    elif ":" in hostport:
        host, _, port = hostport.partition(":")
        has_port = int(bool(port))
    path, _, after = rest.partition("?")
    path = path.split("#", 1)[0]
    query = after.split("#", 1)[0]

    is_ip = 0
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        pass

    labels = [x for x in host.split(".") if x] if not is_ip else []
    if is_ip or not labels:
        subdomain_depth = registered_len = tld_len = 0
        tld_common = 0
    else:
        ext = _extractor()(host)
        if ext.suffix and ext.domain:
            registered_label, suffix, sub = ext.domain, ext.suffix, ext.subdomain
        else:                                                    # unknown TLD: the last label is the suffix
            registered_label = labels[-2] if len(labels) > 1 else labels[0]
            suffix = labels[-1] if len(labels) > 1 else ""
            sub = ".".join(labels[:-2])
        subdomain_depth = len([x for x in sub.split(".") if x])
        registered_len = len(registered_label)
        tld_len = len(suffix)
        tld_common = int(suffix.split(".")[-1] in COMMON_TLDS)

    host_uni = cf.to_unicode(host) if "xn--" in host else host
    segments = [s for s in path.split("/") if s]
    n = len(text)
    digits = sum(c.isdigit() for c in text)
    letters = sum(c.isalpha() for c in text)

    index = index or _index()
    brand_score = 0.0
    flagged = official = in_sub = keyword = 0
    if host and not is_ip:
        check = assess_lookalike(host, index)
        official = int(check.status == "official")
        best = check.match or (check.candidates[0] if check.candidates else None)
        if best is not None:
            brand_score = best.similarity
        flagged = int(check.status == "lookalike")
        if check.match is not None:
            in_sub = int(check.match.kind == "brand_in_subdomain")
            keyword = int(check.match.kind == "brand_keyword")
    brand_in_path = 0 if official else int(bool(_brand_path_regex().search((path + "?" + query).lower())))

    values = {
        "url_len": n, "host_len": len(host), "path_len": len(path), "query_len": len(query),
        "digit_ratio": _ratio(digits, n), "letter_ratio": _ratio(letters, n),
        "special_count": sum(c in _SPECIAL for c in text), "upper_ratio": _ratio(sum(c.isupper() for c in text), n),
        "url_entropy": _entropy(text),
        "host_dots": host.count("."), "host_hyphens": host.count("-"), "host_digit_ratio": _ratio(sum(c.isdigit() for c in host), len(host)),
        "subdomain_depth": subdomain_depth, "registered_label_len": registered_len, "tld_len": tld_len, "tld_is_common": tld_common,
        "host_is_ip": is_ip, "host_has_port": has_port, "host_has_userinfo": int(bool(userinfo) or "@" in host_part),
        "host_is_punycode": int("xn--" in host), "host_mixed_script": int(cf.is_mixed_script(host_uni)),
        "host_entropy": _entropy(host), "host_longest_label": max((len(x) for x in labels), default=0),
        "path_segments": len(segments), "path_longest_segment": max((len(s) for s in segments), default=0),
        "path_entropy": _entropy(path), "query_params": len([p for p in query.split("&") if p]) if query else 0,
        "path_has_double_slash": int("//" in path), "path_has_extension": int(bool(_EXT.search(path.lower()))),
        "path_digit_ratio": _ratio(sum(c.isdigit() for c in path), len(path)),
        "risk_words_host": _risk_count(host), "risk_words_path": _risk_count(path), "risk_words_query": _risk_count(query),
        "lookalike_score": brand_score, "lookalike_flagged": flagged, "is_official_domain": official,
        "brand_in_subdomain": in_sub, "brand_in_path": brand_in_path, "brand_keyword": keyword,
    }
    return {name: float(values[name]) for name in FEATURE_NAMES}


def feature_row(raw: str, index: Optional[BrandIndex] = None) -> list[float]:
    """The feature values in ``FEATURE_NAMES`` order (what the tree model is trained and served on)."""
    feats = extract_url_features(raw, index)
    return [feats[name] for name in FEATURE_NAMES]
