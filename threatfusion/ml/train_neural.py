"""ThreatFusion – Neural Fusion Model Training

Trains the character-level two-branch neural network (``UrlFusionNet``) that
reads a raw URL string *and* the 19-dim tabular feature vector, then fuses them
into a single risk probability. This is the project's deep-learning upgrade over
the reputation-only XGBoost model.

Produces:
- ml/models/neural_fusion.pt              — trained PyTorch weights
- ml/models/neural_fusion_config.json     — architecture + vocab + norm stats
- ml/models/neural_fusion_metrics.json    — evaluation + 3-way ablation

Usage:
    python -m ml.train_neural
    python -m ml.train_neural --samples 12000 --epochs 12

Training data
-------------
Labelled URLs are synthesised from well-documented phishing lexical patterns
(brand impersonation, typosquatting, suspicious TLDs, IP hosts, hyphen/keyword
stuffing, homoglyphs) for the positive class and realistic clean URLs for the
negative class. Each URL is paired with a tabular feature row drawn from the
same class-conditional distributions used by ``ml/train.py`` so both branches
carry real signal. The synthetic nature is documented as a limitation in
docs/ARCHITECTURE.md — the pipeline is drop-in ready for real URLhaus/Tranco
feeds via ``load_url_dataset`` when they are available.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from pathlib import Path
from typing import List, Tuple

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from torch.utils.data import DataLoader, TensorDataset

# Make ``app`` importable when run as ``python -m ml.train_neural`` from the
# threatfusion/ root (backend/ holds the package).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.ml.url_model import (  # noqa: E402
    UrlFusionConfig,
    UrlFusionNet,
    build_vocab,
    encode_url,
    save_checkpoint,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = Path("ml/models")
WEIGHTS_PATH = MODELS_DIR / "neural_fusion.pt"
METRICS_PATH = MODELS_DIR / "neural_fusion_metrics.json"

# Feature column order — MUST match FeatureVector field order in schemas.py.
FEATURE_NAMES: List[str] = [
    "vt_malicious_ratio", "vt_suspicious_ratio", "vt_reputation_score",
    "vt_last_seen_days_ago", "shodan_open_port_count", "shodan_has_high_risk_port",
    "shodan_cve_count", "shodan_max_cvss_score", "shodan_has_iot_tag",
    "shodan_has_compromised_tag", "shodan_service_diversity_score",
    "shodan_high_risk_cpe_count", "tech_count", "tech_has_known_eol_component",
    "tech_avg_confidence", "tech_stack_diversity_count", "tech_has_eol_cms_version",
    "ssl_cert_valid", "domain_age_days",
]


# ───────────────────────────────────────────────────────────────────────────
# URL corpus synthesis
# ───────────────────────────────────────────────────────────────────────────
BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "netflix", "facebook", "google",
    "bankofamerica", "wellsfargo", "chase", "instagram", "whatsapp", "coinbase",
    "dhl", "fedex", "usps", "irs", "hmrc", "linkedin", "dropbox", "outlook",
]
PHISH_TOKENS = [
    "secure", "login", "signin", "verify", "account", "update", "confirm",
    "webscr", "alert", "suspended", "billing", "unlock", "recover", "support",
    "auth", "session", "validation", "security", "id", "customer",
]
BAD_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "info",
    "buzz", "zip", "work", "rest", "click", "link", "live",
]
HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
CYRILLIC = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с"}

GOOD_DOMAINS = [
    "google.com", "wikipedia.org", "github.com", "stackoverflow.com",
    "nytimes.com", "amazon.com", "apple.com", "microsoft.com", "bbc.co.uk",
    "reddit.com", "python.org", "cloudflare.com", "mozilla.org", "netflix.com",
    "paypal.com", "linkedin.com", "dropbox.com", "wordpress.org", "medium.com",
    "spotify.com", "gov.uk", "harvard.edu", "nature.com", "who.int",
]
GOOD_SUBS = ["www", "docs", "blog", "mail", "support", "api", "en", "help", "shop"]
GOOD_PATHS = [
    "/", "/index.html", "/about", "/search?q=weather", "/wiki/Cybersecurity",
    "/questions/12345/how-to", "/articles/2024/report", "/products/item-42",
    "/help/getting-started", "/en/latest/guide", "/blog/2024/announcement",
]


def _rand_typosquat(brand: str, rng: random.Random) -> str:
    """Perturb a brand name into a look-alike (homoglyph / hyphen / doubling)."""
    s = brand
    choice = rng.random()
    if choice < 0.4:  # digit/letter homoglyph substitution
        for a, b in HOMOGLYPHS.items():
            if a in s and rng.random() < 0.5:
                s = s.replace(a, b, 1)
                break
    elif choice < 0.6:  # cyrillic homoglyph (visual spoof)
        for a, b in CYRILLIC.items():
            if a in s:
                s = s.replace(a, b, 1)
                break
    elif choice < 0.8:  # internal hyphen
        i = rng.randint(1, len(s) - 1)
        s = s[:i] + "-" + s[i:]
    else:  # doubled character
        i = rng.randint(0, len(s) - 1)
        s = s[:i] + s[i] + s[i:]
    return s


def _rand_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def make_phishing_url(rng: random.Random) -> str:
    """Generate one realistic phishing-style URL."""
    brand = rng.choice(BRANDS)
    tok = rng.choice(PHISH_TOKENS)
    tok2 = rng.choice(PHISH_TOKENS)
    tld = rng.choice(BAD_TLDS)
    scheme = "http" if rng.random() < 0.7 else "https"
    structure = rng.randint(0, 6)

    if structure == 0:  # brand in subdomain of a junk domain
        host = f"{brand}.{tok}-{tok2}.{tld}"
        path = f"/{tok}/{rng.choice(['index', 'verify', 'signin'])}.php"
    elif structure == 1:  # typosquatted registrable domain
        host = f"{_rand_typosquat(brand, rng)}-{tok}.{tld}"
        path = f"/{tok2}"
    elif structure == 2:  # raw IP host
        host = _rand_ip(rng)
        path = f"/{brand}/{tok}/login"
    elif structure == 3:  # long hyphen chain
        host = f"{brand}-{tok}-{tok2}-{rng.choice(PHISH_TOKENS)}.{tld}"
        path = "/"
    elif structure == 4:  # random hex host
        host = f"{rng.randbytes(6).hex()}.{tld}"
        path = f"/{brand}/{tok}?id={rng.randint(1000, 999999)}"
    elif structure == 5:  # legit-looking free host + brand path stuffing
        host = f"{brand}{rng.randint(1, 99)}.{rng.choice(['weebly', 'blogspot', 'firebaseapp'])}.com"
        path = f"/{tok}/{tok2}/account-{rng.randint(1, 9999)}"
    else:  # deep sub-domain nesting
        host = f"{tok}.{brand}.{tok2}.{tld}"
        path = f"/secure/{tok}?token={rng.randbytes(4).hex()}"

    return f"{scheme}://{host}{path}"


def make_benign_url(rng: random.Random) -> str:
    """Generate one realistic benign URL."""
    domain = rng.choice(GOOD_DOMAINS)
    scheme = "https" if rng.random() < 0.9 else "http"
    host = domain if rng.random() < 0.5 else f"{rng.choice(GOOD_SUBS)}.{domain}"
    path = rng.choice(GOOD_PATHS)
    return f"{scheme}://{host}{path}"


# ───────────────────────────────────────────────────────────────────────────
# Tabular feature synthesis (class-conditional; mirrors ml/train.py)
# ───────────────────────────────────────────────────────────────────────────
def _tab_row(label: int, rng: np.random.Generator) -> np.ndarray:
    """Draw one 19-dim tabular feature row for the given class."""
    if label == 0:  # benign
        row = [
            rng.uniform(0.0, 0.3), rng.uniform(0.0, 0.4), rng.uniform(0.2, 1.0),
            rng.uniform(0.0, 100.0), float(rng.poisson(3.0)),
            float(rng.choice([0, 1], p=[0.8, 0.2])), float(rng.poisson(1.0)),
            rng.uniform(0.0, 8.0) if rng.random() < 0.4 else 0.0,
            float(rng.choice([0, 1], p=[0.8, 0.2])),
            float(rng.choice([0, 1], p=[0.9, 0.1])), float(rng.poisson(2.0)),
            float(rng.poisson(0.5)), float(rng.poisson(6.0)),
            float(rng.choice([0, 1], p=[0.7, 0.3])), rng.uniform(0.6, 1.0),
            float(rng.poisson(3.0)), float(rng.choice([0, 1], p=[0.85, 0.15])),
            float(rng.choice([1, 0], p=[0.85, 0.15])), rng.uniform(100, 3650),
        ]
    else:  # malicious
        row = [
            rng.uniform(0.1, 0.9), rng.uniform(0.0, 0.6), rng.uniform(0.0, 0.7),
            rng.uniform(0.0, 365.0), float(rng.poisson(4.0)),
            float(rng.choice([0, 1], p=[0.5, 0.5])), float(rng.poisson(2.0)),
            rng.uniform(4.0, 10.0) if rng.random() < 0.6 else 0.0,
            float(rng.choice([0, 1], p=[0.6, 0.4])),
            float(rng.choice([0, 1], p=[0.7, 0.3])), float(rng.poisson(3.0)),
            float(rng.poisson(1.0)), float(rng.poisson(8.0)),
            float(rng.choice([0, 1], p=[0.6, 0.4])), rng.uniform(0.4, 0.9),
            float(rng.poisson(3.0)), float(rng.choice([0, 1], p=[0.7, 0.3])),
            float(rng.choice([1, 0], p=[0.6, 0.4])), rng.uniform(1.0, 400.0),
        ]
    return np.array(row, dtype=np.float64)


def build_dataset(
    n_samples: int, seed: int = 42
) -> Tuple[List[str], np.ndarray, np.ndarray]:
    """Build the paired (url, tabular, label) dataset.

    Returns ``(urls, tab_matrix[n,19], labels[n])``. 15% label noise is injected
    to keep the task realistic (perfect separability would be a red flag).
    """
    rng_py = random.Random(seed)
    rng_np = np.random.default_rng(seed)

    urls: List[str] = []
    tab_rows: List[np.ndarray] = []
    labels: List[int] = []

    for _ in range(n_samples):
        label = int(rng_np.random() < 0.5)
        if label == 1:
            urls.append(make_phishing_url(rng_py))
        else:
            urls.append(make_benign_url(rng_py))
        tab_rows.append(_tab_row(label, rng_np))
        labels.append(label)

    tab = np.vstack(tab_rows)
    y = np.array(labels, dtype=np.int64)

    # Inject 15% label noise (flip a random subset) — documented limitation.
    n_flip = int(0.15 * n_samples)
    flip_idx = rng_np.choice(n_samples, size=n_flip, replace=False)
    y[flip_idx] = 1 - y[flip_idx]

    return urls, tab, y


# ───────────────────────────────────────────────────────────────────────────
# Training / evaluation
# ───────────────────────────────────────────────────────────────────────────
def _metrics(y_true: np.ndarray, y_prob: np.ndarray) -> dict:
    y_pred = (y_prob >= 0.5).astype(int)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the neural fusion model")
    parser.add_argument("--samples", type=int, default=10000,
                        help="synthetic sample count (ignored with --real)")
    parser.add_argument("--real", action="store_true",
                        help="train on REAL URLhaus/PhishTank + Tranco feeds instead of synthetic")
    parser.add_argument("--n-per-class", type=int, default=8000,
                        help="real URLs per class when --real is set")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Data ────────────────────────────────────────────────────────────
    if args.real:
        # Real, labelled URLs from public threat feeds. No fabricated labels.
        from ml.data_sources import build_real_dataset

        logger.info("Building REAL dataset (%d per class)...", args.n_per_class)
        urls, labels, data_source = build_real_dataset(
            n_per_class=args.n_per_class, seed=args.seed
        )
        y = np.array(labels, dtype=np.int64)
        # Neutral pre-enrichment tabular vector — exactly what the live system
        # feeds the tabular branch before any VT/Shodan enrichment is available.
        # It is constant across samples, so the fused score relies on the URL
        # branch here; training the tabular branch on real *multi-source* labels
        # is a later phase (documented, not faked).
        neutral = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
        neutral[FEATURE_NAMES.index("ssl_cert_valid")] = 1.0
        neutral[FEATURE_NAMES.index("domain_age_days")] = 365.0
        tab = np.tile(neutral, (len(urls), 1))
    else:
        logger.info("Building SYNTHETIC dataset (%d samples)...", args.samples)
        urls, tab, y = build_dataset(args.samples, seed=args.seed)
        data_source = {"source": "synthetic (np.random lexical patterns; documented limitation)"}

    # Deterministic train/test split.
    rng = np.random.default_rng(args.seed)
    perm = rng.permutation(len(y))
    n_test = int(0.2 * len(y))
    test_idx, train_idx = perm[:n_test], perm[n_test:]

    # Standardise tabular features using TRAIN statistics only (no leakage).
    tab_mean = tab[train_idx].mean(axis=0)
    tab_std = tab[train_idx].std(axis=0)
    tab_std_safe = np.where(tab_std < 1e-8, 1.0, tab_std)
    tab_norm = (tab - tab_mean) / tab_std_safe

    # ── Encode URLs ─────────────────────────────────────────────────────
    config = UrlFusionConfig(
        vocab=build_vocab(),
        n_tabular_features=len(FEATURE_NAMES),
        feature_names=FEATURE_NAMES,
        tab_mean=tab_mean.tolist(),
        tab_std=tab_std.tolist(),
    )
    char_ids = np.array(
        [encode_url(u, config.vocab, config.max_len) for u in urls], dtype=np.int64
    )

    def _loader(idx: np.ndarray, shuffle: bool) -> DataLoader:
        ds = TensorDataset(
            torch.tensor(char_ids[idx], dtype=torch.long),
            torch.tensor(tab_norm[idx], dtype=torch.float32),
            torch.tensor(y[idx], dtype=torch.float32).unsqueeze(1),
        )
        return DataLoader(ds, batch_size=args.batch_size, shuffle=shuffle)

    train_loader = _loader(train_idx, shuffle=True)

    # ── Model / optimiser ───────────────────────────────────────────────
    model = UrlFusionNet(config)
    optim = torch.optim.Adam(model.parameters(), lr=args.lr)
    bce = nn.BCEWithLogitsLoss()
    n_params = sum(p.numel() for p in model.parameters())
    logger.info("UrlFusionNet: %d trainable parameters", n_params)

    # ── Training loop ───────────────────────────────────────────────────
    for epoch in range(1, args.epochs + 1):
        model.train()
        running = 0.0
        for cb, tb, yb in train_loader:
            optim.zero_grad()
            fused, text, tabl = model.forward_all(cb, tb)
            # Joint loss: fusion head is primary; the single-modality heads are
            # regularised so each branch stays independently discriminative.
            loss = bce(fused, yb) + 0.5 * bce(text, yb) + 0.5 * bce(tabl, yb)
            loss.backward()
            optim.step()
            running += loss.item() * cb.size(0)
        logger.info("epoch %2d/%d  loss=%.4f", epoch, args.epochs, running / len(train_idx))

    # ── Evaluation + 3-way ablation ─────────────────────────────────────
    model.eval()
    with torch.no_grad():
        cb = torch.tensor(char_ids[test_idx], dtype=torch.long)
        tb = torch.tensor(tab_norm[test_idx], dtype=torch.float32)
        fused, text, tabl = model.forward_all(cb, tb)
        y_test = y[test_idx]
        fused_p = torch.sigmoid(fused).squeeze(1).numpy()
        text_p = torch.sigmoid(text).squeeze(1).numpy()
        tab_p = torch.sigmoid(tabl).squeeze(1).numpy()

    ablation = {
        "fused": _metrics(y_test, fused_p),
        "text_only": _metrics(y_test, text_p),
        "tabular_only": _metrics(y_test, tab_p),
    }
    logger.info("Fused        : %s", ablation["fused"])
    logger.info("Text-only    : %s", ablation["text_only"])
    logger.info("Tabular-only : %s", ablation["tabular_only"])

    # ── Persist ─────────────────────────────────────────────────────────
    save_checkpoint(model, config, WEIGHTS_PATH)
    metrics = {
        "model": "UrlFusionNet (char-CNN text branch + tabular MLP fusion)",
        "framework": "pytorch",
        "data_source": data_source,
        "n_parameters": n_params,
        "n_samples": len(urls),
        "epochs": args.epochs,
        "test_size": int(n_test),
        "ablation": ablation,
        "primary": ablation["fused"],
        "feature_names": FEATURE_NAMES,
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    logger.info("Saved weights → %s", WEIGHTS_PATH)
    logger.info("Saved metrics → %s", METRICS_PATH)


if __name__ == "__main__":
    main()
