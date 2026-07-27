"""ThreatFusion – Real URL Dataset Ingestion  (Phase 1)
=========================================================

Replaces the synthetic URL generator in ``train_neural.py`` with **real,
labelled URLs downloaded from public threat-intelligence feeds**:

* **Positives (label 1)** — live malicious URLs from the abuse.ch **URLhaus**
  recent feed (malware distribution / phishing infrastructure). Optionally
  augmented with **PhishTank** verified phishing URLs when reachable.
* **Negatives (label 0)** — domains from the **Tranco** research top-list, a
  hardened popularity ranking of legitimate sites.

Design decisions (kept deliberately honest — see docs/ARCHITECTURE.md):

1. **No fabricated labels.** Every positive is a URL a threat feed flagged;
   every negative is a real high-reputation domain. The only synthesis is the
   *path* appended to some benign domains (Tranco ships domains, not full URLs)
   — this is transparent structural augmentation of a real host, not a made-up
   reputation signal, and it exists to stop the classifier taking the trivial
   "malicious URLs have a path, benign don't" shortcut.
2. **Deduplicate by host** so a single noisy host (e.g. one Mozi botnet IP
   serving hundreds of payload URLs) cannot dominate the positive class.
3. **Cache** raw downloads under ``ml/data/`` so re-training is offline and
   reproducible.

This module has **no torch dependency** and can be unit-tested on its own.
"""

from __future__ import annotations

import csv
import io
import logging
import random
import urllib.request
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Feed endpoints ──────────────────────────────────────────────────────────
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"
PHISHTANK_CSV_URL = "https://data.phishtank.com/data/online-valid.csv"
# Labelled real full-URL corpus (both classes are real URLs *with real paths*,
# collected comparably — this avoids the "benign=domain, malicious=full-URL"
# structural mismatch that a domain list + live feeds would introduce).
FULLDB_URL = (
    "https://raw.githubusercontent.com/faizann24/"
    "Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv"
)
# Phase 2 — real labelled HTTP request-parameter payloads (CSIC-2010 normal
# params + real SQLi/XSS/path-traversal/cmdi attack payloads). Columns:
# ``payload,length,attack_type,label`` with attack_type in
# {norm, sqli, xss, path-traversal, cmdi}.
HTTP_PARAMS_URL = (
    "https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/master/payload_full.csv"
)

DATA_DIR = Path("ml/data")

# Ordered class list for the HTTP attack classifier. Index == model class id.
HTTP_ATTACK_CLASSES: List[str] = ["benign", "sqli", "xss", "path-traversal", "cmdi"]
_UA = "ThreatFusion-research/1.0 (+academic security project)"

# Realistic *deep* paths applied to REAL benign domains so the two classes share
# URL structure. This is deliberately rich — product IDs, article slugs, repo
# paths, query strings, file downloads — so the classifier cannot equate
# "brand token + contentful path" with phishing (the failure mode observed when
# benign URLs were only homepages). Real domain, real-shaped path.
_SLUG_WORDS = [
    "getting", "started", "guide", "review", "update", "release", "annual",
    "report", "summer", "sale", "how", "to", "best", "top", "new", "pro",
    "max", "ultra", "mini", "kit", "case", "cover", "story", "world", "tech",
    "science", "market", "weekly", "daily", "team", "docs", "api", "cloud",
]
_FILE_EXT = ["pdf", "zip", "dmg", "exe", "tar.gz", "csv", "png", "mp4"]


def _slug(rng: random.Random, n: int = 3) -> str:
    return "-".join(rng.sample(_SLUG_WORDS, k=min(n, len(_SLUG_WORDS))))


def _benign_path(rng: random.Random) -> str:
    """Generate one realistic deep path for a legitimate site."""
    kind = rng.randint(0, 9)
    if kind == 0:                       # homepage (common)
        return rng.choice(["/", "/", "/index.html", "/en/", "/home"])
    if kind == 1:                       # e-commerce product
        pid = "".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") for _ in range(10))
        return rng.choice([f"/dp/{pid}", f"/product/{_slug(rng,2)}/{pid}", f"/item/{rng.randint(1000,999999)}"])
    if kind == 2:                       # news / blog article
        return f"/{rng.randint(2019,2026)}/{rng.randint(1,12):02d}/{_slug(rng,4)}"
    if kind == 3:                       # docs / wiki
        return rng.choice([f"/wiki/{_slug(rng,2).replace('-','_')}", f"/docs/{_slug(rng,1)}/{_slug(rng,2)}", "/en/latest/index.html"])
    if kind == 4:                       # code repo
        return f"/{_slug(rng,1)}/{_slug(rng,1)}/blob/main/src/{_slug(rng,1)}.py"
    if kind == 5:                       # search / query string
        return f"/search?q={_slug(rng,2)}&page={rng.randint(1,9)}"
    if kind == 6:                       # account / user area (legit)
        return rng.choice(["/account/settings", f"/users/{rng.randint(1,99999)}", "/dashboard", "/orders"])
    if kind == 7:                       # file download
        return f"/downloads/{_slug(rng,2)}-{rng.randint(1,9)}.{rng.randint(0,9)}.{rng.choice(_FILE_EXT)}"
    if kind == 8:                       # category listing
        return f"/{_slug(rng,1)}/{_slug(rng,1)}?sort=popular"
    return f"/{_slug(rng,3)}"           # generic slug page


# ── Download / cache ────────────────────────────────────────────────────────
def _download(url: str, dest: Path, timeout: int = 90) -> Path:
    """Download ``url`` to ``dest`` (cached — skips if the file already exists)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        logger.info("cache hit: %s", dest)
        return dest
    logger.info("downloading %s → %s", url, dest)
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted feeds)
        dest.write_bytes(resp.read())
    return dest


# ── Positives: URLhaus ──────────────────────────────────────────────────────
def load_urlhaus(data_dir: Path = DATA_DIR, online_only: bool = True) -> List[str]:
    """Return a list of real malicious URLs from the cached URLhaus feed.

    The CSV is comment-prefixed (``#``) with columns:
    ``id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter``.
    """
    path = _download(URLHAUS_CSV_URL, data_dir / "urlhaus_recent.csv")
    text = path.read_text(encoding="utf-8", errors="replace")
    rows = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    urls: List[str] = []
    for row in csv.reader(rows):
        if len(row) < 4:
            continue
        url, status = row[2].strip(), row[3].strip().lower()
        if online_only and status not in ("online", ""):
            continue
        if url:
            urls.append(url)
    logger.info("URLhaus: %d malicious URLs", len(urls))
    return urls


# ── Positives (optional): PhishTank ─────────────────────────────────────────
def load_phishtank(data_dir: Path = DATA_DIR) -> List[str]:
    """Return verified phishing URLs from PhishTank, or ``[]`` if unavailable.

    PhishTank's anonymous endpoint is rate-limited and may return an HTML error
    page instead of a CSV; we fail soft and simply contribute nothing rather
    than poison the dataset.
    """
    try:
        path = _download(PHISHTANK_CSV_URL, data_dir / "phishtank.csv", timeout=60)
        text = path.read_text(encoding="utf-8", errors="replace")
        if "phish_id" not in text.splitlines()[0].lower():
            logger.warning("PhishTank: unexpected format (likely rate-limited); skipping")
            return []
        urls = [r["url"].strip() for r in csv.DictReader(io.StringIO(text)) if r.get("url")]
        logger.info("PhishTank: %d phishing URLs", len(urls))
        return urls
    except Exception as exc:  # network / rate-limit / format
        logger.warning("PhishTank unavailable (%s); continuing without it", exc)
        return []


# ── Negatives: Tranco ───────────────────────────────────────────────────────
def load_tranco(n: int, data_dir: Path = DATA_DIR) -> List[str]:
    """Return the top ``n`` benign domains from the cached Tranco zip."""
    path = _download(TRANCO_ZIP_URL, data_dir / "tranco_top1m.csv.zip")
    with zipfile.ZipFile(path) as zf:
        name = zf.namelist()[0]
        with zf.open(name) as fh:
            text = io.TextIOWrapper(fh, encoding="utf-8")
            domains = []
            for line in text:
                parts = line.strip().split(",")
                if len(parts) == 2:
                    domains.append(parts[1])
                if len(domains) >= n:
                    break
    logger.info("Tranco: %d benign domains", len(domains))
    return domains


# ── Helpers ─────────────────────────────────────────────────────────────────
def load_url_fulldb(data_dir: Path = DATA_DIR) -> Tuple[List[str], List[str]]:
    """Return ``(malicious_urls, benign_urls)`` from the real full-URL corpus.

    CSV columns are ``url,label`` with label in {``good``, ``bad``}. Every URL is
    a real, historically observed full URL (paths included) — the property that
    lets the classifier learn phishing lexicon rather than "has a path".
    """
    path = _download(FULLDB_URL, data_dir / "url_fulldb.csv")
    text = path.read_text(encoding="utf-8", errors="replace")
    mal: List[str] = []
    ben: List[str] = []
    for row in csv.DictReader(io.StringIO(text)):
        url = (row.get("url") or "").strip()
        label = (row.get("label") or "").strip().lower()
        if not url:
            continue
        if label == "bad":
            mal.append(url)
        elif label == "good":
            ben.append(url)
    logger.info("Full-URL corpus: %d malicious, %d benign", len(mal), len(ben))
    return mal, ben


def _host_of(url: str) -> str:
    """Extract the host (or the whole string if unparseable) for dedup."""
    try:
        netloc = urlparse(url if "://" in url else f"http://{url}").netloc
        return (netloc or url).split("@")[-1].split(":")[0].lower()
    except Exception:
        return url.lower()


def _dedup_by_host(urls: List[str], rng: random.Random, cap_per_host: int = 3) -> List[str]:
    """Keep at most ``cap_per_host`` URLs per host so noisy hosts don't dominate."""
    rng.shuffle(urls)
    seen: dict[str, int] = {}
    out: List[str] = []
    for u in urls:
        h = _host_of(u)
        if seen.get(h, 0) >= cap_per_host:
            continue
        seen[h] = seen.get(h, 0) + 1
        out.append(u)
    return out


def _benign_url(domain: str, rng: random.Random) -> str:
    """Render a real benign domain as a URL with a realistic deep path/subdomain."""
    scheme = "https" if rng.random() < 0.92 else "http"
    host = domain
    if rng.random() < 0.3:
        host = f"{rng.choice(['www', 'docs', 'blog', 'shop', 'en', 'support', 'store', 'help'])}.{domain}"
    return f"{scheme}://{host}{_benign_path(rng)}"


# ── Public API ──────────────────────────────────────────────────────────────
def build_real_dataset(
    n_per_class: int = 8000,
    seed: int = 42,
    data_dir: Path = DATA_DIR,
    source: str = "fulldb",
) -> Tuple[List[str], List[int], dict]:
    """Build a balanced, real, deduplicated ``(urls, labels, provenance)`` set.

    ``source``:
      * ``"fulldb"`` (default) — the labelled real full-URL corpus. Both classes
        are real URLs *with real paths*, so there is no domain-vs-full-URL
        structural shortcut and nothing about the benign side is synthesised.
      * ``"feeds"`` — live URLhaus/PhishTank (malicious) vs Tranco domains
        (benign, with structurally-augmented paths). Fresher, but the benign
        paths are synthetic; kept for currency experiments, not the default.

    ``provenance`` records exactly where every sample came from so the metrics
    file is fully auditable.
    """
    rng = random.Random(seed)

    if source == "fulldb":
        mal_all, ben_all = load_url_fulldb(data_dir)
        raw = {"malicious_raw": len(mal_all), "benign_raw": len(ben_all)}
        mal = _dedup_by_host(mal_all, rng)
        benign = _dedup_by_host(ben_all, rng)
        rng.shuffle(mal)
        rng.shuffle(benign)
        n = min(n_per_class, len(mal), len(benign))
        mal, benign = mal[:n], benign[:n]
        prov_source = "real labelled full-URL corpus (faizann24; real paths both classes)"
        benign_note = "real benign URLs with real paths — nothing synthesised"
    elif source == "feeds":
        mal = load_urlhaus(data_dir)
        raw = {"urlhaus_raw": len(mal)}
        pt = load_phishtank(data_dir)
        raw["phishtank_raw"] = len(pt)
        mal.extend(pt)
        mal = _dedup_by_host(mal, rng)
        rng.shuffle(mal)
        mal = mal[:n_per_class]
        domains = load_tranco(max(n_per_class * 2, 20000), data_dir)
        rng.shuffle(domains)
        benign = [_benign_url(d, rng) for d in domains[:n_per_class]]
        n = min(len(mal), len(benign))
        mal, benign = mal[:n], benign[:n]
        prov_source = "live feeds (URLhaus + PhishTank vs Tranco)"
        benign_note = "real Tranco domains; paths structurally augmented (synthetic paths)"
    else:
        raise ValueError(f"unknown source: {source!r}")

    urls = mal + benign
    labels = [1] * len(mal) + [0] * len(benign)

    idx = list(range(len(urls)))
    rng.shuffle(idx)
    urls = [urls[i] for i in idx]
    labels = [labels[i] for i in idx]

    provenance = {
        "source": prov_source,
        **raw,
        "positives": int(sum(labels)),
        "negatives": int(len(labels) - sum(labels)),
        "benign_note": benign_note,
        "dedup": "<=3 URLs per host",
    }
    logger.info("Real dataset: %d samples (%s)", len(urls), provenance["source"])
    return urls, labels, provenance


# ── Phase 2: HTTP request-parameter attack payloads ─────────────────────────
def load_http_params(data_dir: Path = DATA_DIR) -> Tuple[List[str], List[str]]:
    """Return ``(payloads, attack_types)`` from the real HTTP-params corpus.

    ``attack_type`` is one of {``norm``, ``sqli``, ``xss``, ``path-traversal``,
    ``cmdi``}. Every payload is a real request-parameter value — normal ones from
    CSIC-2010 web traffic, malicious ones from curated real attack corpora.
    """
    path = _download(HTTP_PARAMS_URL, data_dir / "http_params.csv")
    text = path.read_text(encoding="utf-8", errors="replace")
    payloads: List[str] = []
    types: List[str] = []
    for row in csv.DictReader(io.StringIO(text)):
        payload = row.get("payload")
        atype = (row.get("attack_type") or "").strip().lower()
        if payload is None or not atype:
            continue
        payloads.append(payload)
        types.append(atype)
    logger.info("HTTP-params corpus: %d payloads", len(payloads))
    return payloads, types


def build_http_attack_dataset(
    seed: int = 42, data_dir: Path = DATA_DIR
) -> Tuple[List[str], List[int], List[str], dict]:
    """Build ``(payloads, class_ids, class_names, provenance)`` for the classifier.

    ``attack_type`` values are mapped to class ids via ``HTTP_ATTACK_CLASSES``
    (``norm`` → ``benign`` = 0). Rows are de-duplicated and shuffled. The class
    distribution is intentionally left imbalanced (real base rates); the trainer
    handles it with class weights and reports honest per-class metrics.
    """
    rng = random.Random(seed)
    payloads, types = load_http_params(data_dir)

    type_to_id = {t: i for i, t in enumerate(HTTP_ATTACK_CLASSES)}
    type_to_id["norm"] = 0  # dataset labels benign as "norm"

    seen: set = set()
    rows: List[Tuple[str, int]] = []
    dist: dict = {c: 0 for c in HTTP_ATTACK_CLASSES}
    skipped = 0
    for payload, atype in zip(payloads, types):
        cid = type_to_id.get(atype)
        if cid is None:
            skipped += 1
            continue
        key = (payload, cid)
        if key in seen:
            continue
        seen.add(key)
        rows.append((payload, cid))
        dist[HTTP_ATTACK_CLASSES[cid]] += 1

    rng.shuffle(rows)
    out_payloads = [p for p, _ in rows]
    out_labels = [c for _, c in rows]

    provenance = {
        "source": "real HTTP request-parameter corpus (Morzeux HttpParamsDataset; CSIC-2010 + real attack payloads)",
        "total": len(out_payloads),
        "class_distribution": dist,
        "skipped_unknown_type": skipped,
        "dedup": "exact (payload, class) pairs",
    }
    logger.info("HTTP attack dataset: %d payloads %s", len(out_payloads), dist)
    return out_payloads, out_labels, list(HTTP_ATTACK_CLASSES), provenance


if __name__ == "__main__":  # quick manual smoke test
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    u, y, prov = build_real_dataset(n_per_class=2000)
    print("URL total:", len(u), "positives:", sum(y), "negatives:", len(y) - sum(y))
    p, c, names, hprov = build_http_attack_dataset()
    print("HTTP total:", len(p), "classes:", names)
    print("distribution:", hprov["class_distribution"])
