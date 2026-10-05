"""
Build the labelled, featurised URL dataset and its leakage-controlled splits (A2-1, B9)
=======================================================================================

``python -m ml.dataset build``  — canonicalise every collected URL, drop duplicates and contradictions, compute the offline URL
features (``app/ml/url_features.py``) in parallel, and write ``ml/data/processed/urls_v1.parquet`` plus ``PROVENANCE.json``
(the hash of the raw manifest, the feature-schema version, row counts, the commit) so any reported number can be traced to the
exact data and code that produced it.

Splitting (``make_splits``) — the protocol the master prompt asks for:

* **Time-ordered.**  PhreshPhish's own ``test`` split is later than its ``train`` split; that is used as the TEST set (looked at
  once).  Validation is the *newest* fraction of the dataset's train period, so tuning and calibration also face data that is
  later than what the model fitted.
* **Host-disjoint.**  A site's URLs are near-duplicates of each other; the same registered domain must not be in both the
  fitted data and an evaluation set.  Evaluation rows whose registered domain appears in the fitted data are *removed* (the
  count is reported), and the unfiltered evaluation is kept as a secondary number so the size of the leak is visible.
* **No label-source features** (see ``app/ml/url_features.py``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

from ml.collect import MANIFEST, RAW_DIR, load_collected, sha256_file

logger = logging.getLogger("ml.dataset")

PROCESSED_DIR = Path(__file__).resolve().parent / "data" / "processed"
DATASET = PROCESSED_DIR / "urls_v1.parquet"
PROVENANCE = PROCESSED_DIR / "PROVENANCE.json"
_CHUNK = 4000


def _featurise_chunk(urls: list[str]) -> list[list[float]]:
    from app.ml.url_features import feature_row                              # imported in the worker (spawn-safe)

    return [feature_row(u) for u in urls]


def _domain_of(canon: str) -> str:
    from app.core.targets import _extractor
    from app.ml.url_canon import hostname_of

    host = hostname_of(canon)
    if not host:
        return ""
    ext = _extractor()(host)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host


def clean(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Canonicalise, de-duplicate and drop contradictory rows; returns the cleaned frame and what was removed."""
    from app.ml.url_canon import canonical_url_text

    stats = {"raw_rows": int(len(df))}
    df = df.dropna(subset=["url", "label", "date"]).copy()
    df["label"] = df["label"].map({"phish": 1, "benign": 0})
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    df["canon"] = df["url"].map(canonical_url_text)
    df = df[df["canon"].str.len() > 0]
    stats["after_dropna"] = int(len(df))
    conflict = df.groupby("canon")["label"].nunique()
    bad = set(conflict[conflict > 1].index)
    stats["contradictory_urls_dropped"] = int(len(bad))
    df = df[~df["canon"].isin(bad)]
    before = len(df)
    df = df.sort_values("date", kind="stable").drop_duplicates("canon", keep="first")
    stats["duplicate_rows_dropped"] = int(before - len(df))
    stats["rows"] = int(len(df))
    return df.reset_index(drop=True), stats


def build(workers: Optional[int] = None, limit: Optional[int] = None, raw_dir: Path = RAW_DIR, out: Path = DATASET) -> dict:
    from app.ml.url_features import FEATURE_NAMES, URL_FEATURE_SCHEMA_VERSION

    df = load_collected(raw_dir)
    if limit:
        df = df.sample(n=min(limit, len(df)), random_state=0)
    df, stats = clean(df)
    logger.info("cleaned: %s", stats)
    urls = df["canon"].tolist()
    chunks = [urls[i:i + _CHUNK] for i in range(0, len(urls), _CHUNK)]
    workers = workers or max(1, (os.cpu_count() or 2) - 1)
    rows: list[list[float]] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for i, part in enumerate(pool.map(_featurise_chunk, chunks)):
            rows.extend(part)
            if i % 20 == 0:
                logger.info("featurised %d / %d", len(rows), len(urls))
    feats = pd.DataFrame(rows, columns=FEATURE_NAMES, dtype="float32")
    df = pd.concat([df.reset_index(drop=True), feats], axis=1)
    df["domain"] = [_domain_of(c) for c in df["canon"]]
    out.parent.mkdir(parents=True, exist_ok=True)
    keep = ["sha256", "canon", "label", "target", "date", "lang", "split", "domain"] + FEATURE_NAMES
    df[keep].to_parquet(out, compression="zstd", index=False)
    commit = _git_head()
    prov = {
        "dataset_file": out.name, "dataset_sha256": sha256_file(out), "rows": int(len(df)),
        "phish_rows": int(df["label"].sum()), "benign_rows": int((df["label"] == 0).sum()),
        "date_min": str(df["date"].min().date()), "date_max": str(df["date"].max().date()),
        "feature_schema_version": URL_FEATURE_SCHEMA_VERSION, "n_features": len(FEATURE_NAMES), "cleaning": stats,
        "raw_manifest_sha256": hashlib.sha256((raw_dir / "MANIFEST.json").read_bytes()).hexdigest(),
        "code_commit": commit, "source": "PhreshPhish (CC-BY-4.0), metadata columns only",
    }
    (out.parent / "PROVENANCE.json").write_text(json.dumps(prov, indent=2, sort_keys=True), encoding="utf-8")
    logger.info("wrote %s (%d rows)", out, len(df))
    return prov


def _git_head() -> Optional[str]:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).parent, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def load(path: Path = DATASET) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"{path} not found; run `python -m ml.collect phreshphish` then `python -m ml.dataset build`")
    df = pd.read_parquet(path)
    df["date"] = pd.to_datetime(df["date"])
    return df


@dataclass
class Splits:
    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame            # host-disjoint from train+val
    val_raw: pd.DataFrame         # before the host-disjoint filter (secondary number)
    test_raw: pd.DataFrame
    report: dict


def make_splits(df: pd.DataFrame, val_fraction: float = 0.2) -> Splits:
    """Time-ordered, host-disjoint splits (see the module docstring)."""
    src_train = df[df["split"] == "train"].sort_values("date", kind="stable")
    test_raw = df[df["split"] == "test"]
    cut = int(len(src_train) * (1.0 - val_fraction))
    train = src_train.iloc[:cut]
    val_raw = src_train.iloc[cut:]
    fitted = set(train["domain"])
    val = val_raw[~val_raw["domain"].isin(fitted)]
    test = test_raw[~test_raw["domain"].isin(fitted | set(val["domain"]))]
    report = {
        "train": _describe(train), "val": _describe(val), "val_unfiltered": _describe(val_raw),
        "test": _describe(test), "test_unfiltered": _describe(test_raw),
        "val_rows_removed_for_host_overlap": int(len(val_raw) - len(val)),
        "test_rows_removed_for_host_overlap": int(len(test_raw) - len(test)),
        "train_test_domain_overlap_unfiltered": int(len(set(test_raw["domain"]) & fitted)),
    }
    return Splits(train, val, test, val_raw, test_raw, report)


def _describe(d: pd.DataFrame) -> dict:
    if len(d) == 0:
        return {"rows": 0}
    return {"rows": int(len(d)), "phish_fraction": round(float(d["label"].mean()), 4), "domains": int(d["domain"].nunique()),
            "date_min": str(d["date"].min().date()), "date_max": str(d["date"].max().date())}


# ── label-preserving perturbations for adversarial training (B9 / B10) ───────
# Cheap, content-free edits an attacker can make without changing what the page does: pad the path, add a benign-looking path
# prefix, add a tracking-style query, prefix a sub-domain. The tokens here are for TRAINING; ``ml/evaluate.py`` measures
# robustness with *different* tokens (held-out edits), so the model is tested on edits it never saw.
PERTURB_PREFIXES = ["/en/", "/docs/v2/", "/wiki/", "/products/2023/", "/news/", "/help/article/", "/community/", "/us/", "/store/"]
PERTURB_QUERIES = ["lang=en", "ref=hp&id=12", "page=2", "v=3", "source=home", "q=1&sort=new", "id=7"]
PERTURB_SUBDOMAINS = ["www2.", "m.", "static.", "cdn.", "app.", "en."]


def _split_host_rest(canon: str) -> tuple[str, str]:
    i = next((k for k, ch in enumerate(canon) if ch in "/?#"), len(canon))
    return canon[:i], canon[i:]


def perturb(canon: str, rng) -> str:
    """One or two random label-preserving edits of a canonical URL string."""
    ops = rng.sample(["query", "prefix", "subdomain", "pad"], k=rng.choice([1, 1, 2]))
    host, rest = _split_host_rest(canon)
    for op in ops:
        if op == "query":
            rest = rest + ("&" if "?" in rest else "?") + rng.choice(PERTURB_QUERIES)
        elif op == "prefix":
            rest = rng.choice(PERTURB_PREFIXES).rstrip("/") + (rest if rest.startswith("/") else "/" + rest.lstrip("/") if rest and rest[0] not in "?#" else rest)
        elif op == "subdomain":
            host = rng.choice(PERTURB_SUBDOMAINS) + host
        else:
            pad = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(10, 40)))
            head, sep, tail = rest.partition("?")
            rest = head.rstrip("/") + "/" + pad + (sep + tail if sep else "")
    return host + rest


def augment_train(train: pd.DataFrame, fraction: float = 0.3, seed: int = 0, workers: Optional[int] = None) -> pd.DataFrame:
    """Perturbed copies of a random ``fraction`` of ``train`` (same labels), with features recomputed on the perturbed strings."""
    import random

    from app.ml.url_features import FEATURE_NAMES

    rng = random.Random(seed)
    base = train.sample(frac=fraction, random_state=seed)
    canon = [perturb(c, rng) for c in base["canon"]]
    chunks = [canon[i:i + _CHUNK] for i in range(0, len(canon), _CHUNK)]
    workers = workers or max(1, (os.cpu_count() or 2) - 1)
    rows: list[list[float]] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for part in pool.map(_featurise_chunk, chunks):
            rows.extend(part)
    out = base[["label", "date", "domain", "split"]].copy()
    out["canon"] = canon
    out = pd.concat([out.reset_index(drop=True), pd.DataFrame(rows, columns=FEATURE_NAMES, dtype="float32")], axis=1)
    out["augmented"] = True
    return out


def augmented(train: pd.DataFrame, fraction: float = 0.3, seed: int = 0, cache_dir: Path = PROCESSED_DIR) -> pd.DataFrame:
    """``augment_train`` cached on disk (keyed by the training rows, fraction and seed), so every trainer sees the same copies."""
    key = hashlib.sha256((str(len(train)) + str(train["canon"].iloc[0]) + str(train["canon"].iloc[-1]) + f"{fraction}-{seed}").encode()).hexdigest()[:12]
    path = cache_dir / f"urls_v1_aug_{key}.parquet"
    if path.exists():
        return pd.read_parquet(path)
    out = augment_train(train, fraction, seed)
    cache_dir.mkdir(parents=True, exist_ok=True)
    out.to_parquet(path, compression="zstd", index=False)
    return out


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m ml.dataset")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--limit", type=int, default=None, help="featurise a random sample only (smoke test)")
    b.add_argument("--workers", type=int, default=None)
    sub.add_parser("splits", help="print the split report")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if args.cmd == "build":
        print(json.dumps(build(workers=args.workers, limit=args.limit), indent=2))
    else:
        print(json.dumps(make_splits(load()).report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
