"""
Public corpora and obfuscators for the HTTP attack classifier (A2-4, B10)
=========================================================================

The deployed classifier was trained on one corpus (Morzeux HttpParamsDataset: CSIC-2010 + attack payloads) and evaluated on a
random split *of that same corpus* (99.9 % accuracy — an in-distribution number that says nothing about other traffic), with
18 command-injection test samples.  This module provides what a fair evaluation needs, from public sources only:

``fetch()``
    Downloads the public pentest payload lists of **SecLists** (Daniel Miessler, MIT) and **PayloadsAllTheThings** (swisskyrepo,
    MIT) — plain text files, one payload per line — into ``ml/data/raw/payloads/`` with a manifest of hashes.  *Only text is
    fetched; nothing is executed or sent anywhere.*  SecLists feeds **training** (more XSS / path-traversal / cmdi examples:
    the audited model had 89 cmdi training samples); PayloadsAllTheThings is the **held-out evaluation** corpus: a different
    publisher and different curation, with every payload that also appears in the training data removed.

``benign_values()``
    Real benign parameter values — the query-string values of the *benign* URLs in the PhreshPhish data — for measuring the
    false-positive rate on text that is not from the training corpus.

``OBFUSCATORS``
    Deterministic payload-mangling functions in two **families**: ``TRAIN_FAMILIES`` are used for adversarial augmentation
    (training on obfuscated copies, the approach of ModSec-AdvLearn, arXiv 2308.04964) and ``HELDOUT_FAMILIES`` are used only for
    evaluation, so robustness is measured against *encodings the model never saw during training*.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import urllib.request
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import parse_qsl, quote

logger = logging.getLogger("ml.payload_data")

RAW_DIR = Path(__file__).resolve().parent / "data" / "raw" / "payloads"
USER_AGENT = "ThreatFusion-research/1.0 (defensive payload-classifier evaluation; text lists only)"

SECLISTS = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
PATT = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/"

# (class, source, path) — training extension (SecLists) and held-out evaluation (PayloadsAllTheThings).
TRAIN_FILES: list[tuple[str, str, str]] = [
    ("cmdi", "seclists", "Fuzzing/command-injection-commix.txt"),
    ("path-traversal", "seclists", "Fuzzing/LFI/LFI-Jhaddix.txt"),
    ("path-traversal", "seclists", "Fuzzing/LFI/LFI-LFISuite-pathtotest.txt"),
    ("path-traversal", "seclists", "Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt"),
    ("sqli", "seclists", "Fuzzing/Databases/SQLi/Generic-SQLi.txt"),
    ("sqli", "seclists", "Fuzzing/Databases/SQLi/quick-SQLi.txt"),
    ("sqli", "seclists", "Fuzzing/Databases/SQLi/sqli.auth.bypass.txt"),
    ("sqli", "seclists", "Fuzzing/Databases/SQLi/SQLi-Polyglots.txt"),
    ("xss", "seclists", "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt"),
    ("xss", "seclists", "Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt"),
]
HELDOUT_FILES: list[tuple[str, str, str]] = [
    ("cmdi", "patt", "Command%20Injection/Intruder/command-execution-unix.txt"),
    ("cmdi", "patt", "Command%20Injection/Intruder/command_exec.txt"),
    ("path-traversal", "patt", "File%20Inclusion/Intruders/Traversal.txt"),
    ("path-traversal", "patt", "Directory%20Traversal/Intruder/deep_traversal.txt"),
    ("path-traversal", "patt", "Directory%20Traversal/Intruder/directory_traversal.txt"),
    ("path-traversal", "patt", "Directory%20Traversal/Intruder/traversals-8-deep-exotic-encoding.txt"),
    ("sqli", "patt", "SQL%20Injection/Intruder/Auth_Bypass.txt"),
    ("sqli", "patt", "SQL%20Injection/Intruder/Auth_Bypass2.txt"),
    ("sqli", "patt", "SQL%20Injection/Intruder/Generic_ErrorBased.txt"),
    ("sqli", "patt", "SQL%20Injection/Intruder/Generic_TimeBased.txt"),
    ("sqli", "patt", "SQL%20Injection/Intruder/Generic_UnionSelect.txt"),
    ("sqli", "patt", "SQL%20Injection/Intruder/payloads-sql-blind-MySQL-WHERE"),
    ("xss", "patt", "XSS%20Injection/Intruders/IntrudersXSS.txt"),
    ("xss", "patt", "XSS%20Injection/Intruders/MarioXSSVectors.txt"),
    ("xss", "patt", "XSS%20Injection/Intruders/XSSDetection.txt"),
    ("xss", "patt", "XSS%20Injection/Intruders/XSS_Polyglots.txt"),
    ("xss", "patt", "XSS%20Injection/Intruders/0xcela_event_handlers.txt"),
]
_BASES = {"seclists": SECLISTS, "patt": PATT}
_MAX_LEN = 600                                   # drop absurd lines (binary blobs, huge fuzz strings)


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:               # pragma: no cover - network
        return resp.read()


def fetch(out_dir: Path = RAW_DIR, files: Optional[list[tuple[str, str, str]]] = None, downloader: Callable[[str], bytes] = _download) -> dict:
    """Download the payload lists (skipping ones already cached) and write ``MANIFEST.json``; returns the manifest."""
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"files": {}}
    for cls, source, path in files or TRAIN_FILES + HELDOUT_FILES:
        url = _BASES[source] + path
        name = f"{source}__{path.replace('/', '__').replace('%20', '_')}"
        target = out_dir / name
        known = manifest["files"].get(name, {})
        if known.get("error") == "unreadable":
            continue                                                     # blocked by the OS / antivirus: do not fight it
        try:
            if target.exists() and "sha256" in known and hashlib.sha256(target.read_bytes()).hexdigest() == known["sha256"]:
                continue
        except OSError:
            manifest["files"][name] = {"class": cls, "source": source, "url": url, "error": "unreadable"}
            logger.warning("%s: cached file cannot be read (antivirus or filesystem); skipped", name)
            continue
        try:
            data = downloader(url)
        except Exception as exc:                                         # a moved file must not sink the whole run
            logger.warning("%s: not fetched (%s)", url, type(exc).__name__)
            manifest["files"][name] = {"class": cls, "source": source, "url": url, "error": type(exc).__name__}
            continue
        try:
            target.write_bytes(data)
            hashlib.sha256(target.read_bytes())
        except OSError:                                                  # e.g. real-time antivirus blocking an attack-payload list
            manifest["files"][name] = {"class": cls, "source": source, "url": url, "error": "unreadable"}
            logger.warning("%s: could not be stored/read (antivirus or filesystem); skipped", name)
            continue
        manifest["files"][name] = {"class": cls, "source": source, "url": url, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    manifest["licenses"] = {"seclists": "MIT (danielmiessler/SecLists)", "patt": "MIT (swisskyrepo/PayloadsAllTheThings)"}
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def _norm_key(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _bucket(text: str) -> int:
    return int(hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[-1], 16)


_MIN_ALNUM = 2          # a "payload" of lone metacharacters (`|`, `` ` ``, `&& `) cannot be told from punctuation: not a labelled example
# Command injection has little real, varied public training data: SecLists' commix list is one templated command (``echo``) and
# the audited corpus had 89 real examples.  The PayloadsAllTheThings command-injection lists are therefore split BY HASH of the
# line: 3/4 join the training data, 1/4 stays held-out.  The lines are variations of a few templates (``;id``, ``|id``, ``%0Aid``…),
# so the cmdi held-out number is *optimistic*; the report says so.  Every other class is held out whole.
_CMDI_HELDOUT_BUCKETS = 4          # buckets 0..3 of 16 stay held-out
_COMMIX_KEEP_BUCKETS = 3


def read_corpus(out_dir: Path = RAW_DIR, role: str = "train") -> dict[str, list[str]]:
    """``{class: [payload, …]}`` for the training (``role='train'``) or held-out (``'heldout'``) lists, deduplicated."""
    manifest = json.loads((out_dir / "MANIFEST.json").read_text())
    corpus: dict[str, list[str]] = {}
    seen: set[str] = set()
    for name, meta in sorted(manifest["files"].items()):
        source = meta.get("source")
        if source not in ("seclists", "patt") or "sha256" not in meta:
            continue
        if role == "train" and source != "seclists" and meta["class"] != "cmdi":
            continue
        if role == "heldout" and source != "patt":
            continue
        try:
            lines = (out_dir / name).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            logger.warning("%s is unreadable and was left out", name)
            continue
        for line in lines:
            line = line.rstrip("\r\n")
            if not line.strip() or line.startswith("#") or len(line) > _MAX_LEN or sum(c.isalnum() for c in line) < _MIN_ALNUM:
                continue
            if "command-injection-commix" in name and _bucket(_norm_key(line)) >= _COMMIX_KEEP_BUCKETS:
                continue                       # one templated command (``echo`` + random tokens): 3/16 of it is plenty; it must not drown the rest
            if source == "patt" and meta["class"] == "cmdi":
                in_heldout = _bucket(_norm_key(line)) < _CMDI_HELDOUT_BUCKETS
                if (role == "heldout") != in_heldout:
                    continue
            key = _norm_key(line)
            if key in seen:
                continue
            seen.add(key)
            corpus.setdefault(meta["class"], []).append(line)
    return corpus


def remove_overlap(heldout: dict[str, list[str]], train_texts: Iterable[str]) -> tuple[dict[str, list[str]], int]:
    """Drop held-out payloads that also occur (after whitespace/case normalisation) in the training data."""
    train_keys = {_norm_key(t) for t in train_texts}
    out, removed = {}, 0
    for cls, items in heldout.items():
        kept = [p for p in items if _norm_key(p) not in train_keys]
        removed += len(items) - len(kept)
        out[cls] = kept
    return out, removed


def benign_values(limit: int = 20000, seed: int = 0, role: str = "eval", dataset_path: Optional[Path] = None) -> list[str]:
    """Real benign text a parameter could carry: the query-string values *and* the percent-decoded path segments of the benign
    URLs in the processed PhreshPhish data. A value is assigned to ``train`` or ``eval`` by a hash of its text (16 buckets,
    0-3 → eval), so the two sets never overlap whatever the sampling."""
    import pandas as pd
    from urllib.parse import unquote

    from ml import dataset

    df = pd.read_parquet(dataset_path or dataset.DATASET, columns=["canon", "label"])
    values: list[str] = []
    for canon in df[df["label"] == 0]["canon"]:
        head, _, query = canon.partition("?")
        path = head.split("/", 1)[1] if "/" in head else ""
        for seg in path.split("/"):
            seg = unquote(seg)
            if 3 <= len(seg) <= 120 and not seg.isdigit():
                values.append(seg)
        for _, v in parse_qsl(query.split("#", 1)[0], keep_blank_values=False):
            if 3 <= len(v) <= 200:
                values.append(v)
    want_eval = role == "eval"
    values = [v for v in dict.fromkeys(values) if (_bucket(v) < 4) == want_eval]
    random.Random(seed).shuffle(values)
    return values[:limit]


# ── obfuscators ─────────────────────────────────────────────────────────────
def url_encode_all(s: str) -> str:
    return quote(s, safe="")


def comment_split(s: str) -> str:
    return s.replace(" ", "/**/")


def case_alternate(s: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def double_url_encode(s: str) -> str:
    return quote(quote(s, safe=""), safe="")


def html_entities(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" if not c.isalnum() else c for c in s)


def fullwidth(s: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in s)


def whitespace_variants(s: str) -> str:
    return s.replace(" ", "%09")


def plus_for_space(s: str) -> str:
    return s.replace(" ", "+")


def zero_width_split(s: str) -> str:
    return "​".join(s[i:i + 4] for i in range(0, len(s), 4))


OBFUSCATORS: dict[str, Callable[[str], str]] = {
    "url_encode_all": url_encode_all, "comment_split": comment_split, "case_alternate": case_alternate,
    "double_url_encode": double_url_encode, "html_entities": html_entities, "fullwidth": fullwidth,
    "whitespace_variants": whitespace_variants, "plus_for_space": plus_for_space, "zero_width_split": zero_width_split,
}
TRAIN_FAMILIES = ["url_encode_all", "comment_split", "case_alternate"]
HELDOUT_FAMILIES = ["double_url_encode", "html_entities", "fullwidth", "whitespace_variants", "plus_for_space", "zero_width_split"]
