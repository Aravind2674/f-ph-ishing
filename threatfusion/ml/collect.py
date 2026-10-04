"""
Dataset collection for the maliciousness model (A2-1)
=====================================================

The audit found the deployed model was trained on **synthetic** rows.  This module gathers *real, public, labelled* URL data
for a proper retrain, resumably and without ever touching a phishing host:

``python -m ml.collect phreshphish``
    PhreshPhish (Dalton et al. 2025, CC-BY-4.0; Hugging Face ``phreshphish/phreshphish``) — real-world phishing and benign
    web pages, time-stamped, with the brand a phishing page targets.  The parquet shards are tens of GB because they contain
    each page's HTML, but parquet stores columns separately: only the small metadata columns (``sha256, url, label, target,
    date, lang``) are read, with HTTP range requests (~20 MB in total).  **Only the dataset is downloaded — no URL in it is
    ever visited.**

``python -m ml.collect status``
    What has been collected, with row counts and hashes.

Properties required by the master prompt: **quota-aware** (sequential requests, retry with back-off, a polite User-Agent),
**resumable** (a finished shard is never fetched again; an interrupted run continues), **raw data cached** (one small parquet
per shard under ``ml/data/raw/phreshphish/``) and **provenance recorded** (``MANIFEST.json``: source URL, size, rows, retrieval
time and the SHA-256 of every cached file, so a result can be tied to the exact data it was computed on).  Raw data is not
committed (``ml/data/raw/`` is git-ignored); the manifest is.

What this does *not* collect: RDAP / DNS / TLS / CT / reputation features for each URL.  They need one live lookup per URL
against third-party services and (for TLS) a connection to the phishing host itself, so they are deliberately not part of this
offline collection; the URL-level model below uses only features computable from the URL string (see ``app/ml/url_features.py``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("ml.collect")

DATA_DIR = Path(__file__).resolve().parent / "data"
RAW_DIR = DATA_DIR / "raw" / "phreshphish"
MANIFEST = RAW_DIR / "MANIFEST.json"

HF_API = "https://huggingface.co/api/datasets/phreshphish/phreshphish"
HF_RESOLVE = "https://huggingface.co/datasets/phreshphish/phreshphish/resolve/main/"
COLUMNS = ["sha256", "url", "label", "target", "date", "lang"]
USER_AGENT = "ThreatFusion-research/1.0 (academic anti-phishing research; metadata columns only)"
LICENSE = "CC-BY-4.0 (anti-phishing research use only)"
CITATION = "Dalton et al., PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing Website Dataset and Benchmark, arXiv:2507.10854"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: Path = MANIFEST) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"dataset": "phreshphish/phreshphish", "license": LICENSE, "citation": CITATION, "columns": COLUMNS, "shards": {}}


def save_manifest(manifest: dict, path: Path = MANIFEST) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def list_shards(fetch_json: Optional[Callable[[str], dict]] = None) -> list[tuple[str, int]]:
    """``[(shard path, size in bytes)]`` for every parquet file of the dataset, sorted (train first)."""
    if fetch_json is None:
        import urllib.request

        def fetch_json(url: str) -> dict:                                      # pragma: no cover - network
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))

    doc = fetch_json(HF_API + "?blobs=true")
    shards = [(s["rfilename"], int(s.get("size") or 0)) for s in doc.get("siblings", [])
              if s["rfilename"].startswith("data/") and s["rfilename"].endswith(".parquet")]
    return sorted(shards)


def read_remote_columns(url: str, columns: list[str], opener: Optional[Callable] = None):
    """Read only ``columns`` of a remote parquet file (HTTP range requests); returns a pyarrow ``Table``."""
    import pyarrow.parquet as pq

    if opener is None:
        import fsspec

        fs = fsspec.filesystem("https", client_kwargs={"headers": {"User-Agent": USER_AGENT}})

        def opener(u: str):                                                    # pragma: no cover - network
            return fs.open(u, block_size=2 * 1024 * 1024)

    with opener(url) as f:
        return pq.ParquetFile(f).read(columns=columns)


def collect_shard(shard: str, out_dir: Path, manifest: dict, *, reader=read_remote_columns, retries: int = 4,
                  sleep=time.sleep) -> Optional[dict]:
    """Fetch one shard's metadata columns into ``out_dir``. Returns the manifest entry (``None`` if it was already done)."""
    import pyarrow.parquet as pq

    name = Path(shard).name.replace(".parquet", ".meta.parquet")
    target = out_dir / name
    entry = manifest["shards"].get(shard)
    if entry and target.exists() and sha256_file(target) == entry["sha256"]:
        return None                                                            # resumable: already collected and intact
    last: Optional[Exception] = None
    for attempt in range(retries):
        try:
            table = reader(HF_RESOLVE + shard, COLUMNS)
            break
        except Exception as exc:                                               # network / range / parquet error
            last = exc
            logger.warning("%s: attempt %d/%d failed (%s)", shard, attempt + 1, retries, type(exc).__name__)
            sleep(2.0 * (attempt + 1))
    else:
        raise RuntimeError(f"{shard}: gave up after {retries} attempts ({type(last).__name__})") from last
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    pq.write_table(table, tmp, compression="zstd")
    tmp.replace(target)
    entry = {"remote": HF_RESOLVE + shard, "rows": table.num_rows, "file": name, "sha256": sha256_file(target),
             "bytes": target.stat().st_size, "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    manifest["shards"][shard] = entry
    return entry


def collect_phreshphish(out_dir: Path = RAW_DIR, *, max_shards: Optional[int] = None, shards=None, reader=read_remote_columns,
                        sleep=time.sleep) -> dict:
    """Collect every shard (or the first ``max_shards``), saving the manifest after each one so a crash loses nothing."""
    manifest_path = out_dir / "MANIFEST.json"
    manifest = load_manifest(manifest_path)
    listing = shards if shards is not None else list_shards()
    todo = listing[:max_shards] if max_shards else listing
    done = fetched = 0
    for shard, _size in todo:
        entry = collect_shard(shard, out_dir, manifest, reader=reader, sleep=sleep)
        done += 1
        if entry is not None:
            fetched += 1
            save_manifest(manifest, manifest_path)
            logger.info("[%d/%d] %s: %d rows", done, len(todo), shard, entry["rows"])
    manifest["rows"] = sum(e["rows"] for e in manifest["shards"].values())
    save_manifest(manifest, manifest_path)
    logger.info("%d shards (%d fetched now, %d already present); %d rows", done, fetched, done - fetched, manifest["rows"])
    return manifest


def load_collected(out_dir: Path = RAW_DIR):
    """All collected shards as one pandas DataFrame with a ``split`` column (``train`` / ``test``, the dataset's own)."""
    import pandas as pd

    frames = []
    for path in sorted(out_dir.glob("*.meta.parquet")):
        frame = pd.read_parquet(path)
        frame["split"] = "train" if path.name.startswith("train") else "test"
        frames.append(frame)
    if not frames:
        raise FileNotFoundError(f"nothing collected under {out_dir}; run `python -m ml.collect phreshphish`")
    df = pd.concat(frames, ignore_index=True)
    df["date"] = pd.to_datetime(df["date"])
    return df


def status(out_dir: Path = RAW_DIR) -> str:
    manifest = load_manifest(out_dir / "MANIFEST.json")
    shards = manifest.get("shards", {})
    rows = sum(e["rows"] for e in shards.values())
    return f"{len(shards)} shards, {rows:,} rows cached under {out_dir}\nlicense: {manifest.get('license')}\ncite: {manifest.get('citation')}"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.collect", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("phreshphish", help="collect the PhreshPhish metadata columns (resumable)")
    p.add_argument("--max-shards", type=int, default=None)
    sub.add_parser("status", help="show what has been collected")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if args.cmd == "status":
        print(status())
        return 0
    collect_phreshphish(max_shards=args.max_shards)
    print(status())
    return 0


if __name__ == "__main__":
    sys.exit(main())
