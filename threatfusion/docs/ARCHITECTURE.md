# ThreatFusion — System Architecture

## Overview

ThreatFusion is an ML-based risk fusion platform for web and network attack
surface analysis. It aggregates threat intelligence from multiple sources
and uses a trained ML model to produce a single explainable risk score.

## Research Question

> Does a learned fusion model produce more accurate attack-surface risk
> scores than a naive rule-based/weighted-sum heuristic baseline, when
> trained on correlated multi-source security signals?

## System Architecture

```
User Input (domain/IP/hash)
        │
        ▼
┌─────────────────────────────────┐
│       FastAPI Backend           │
│                                 │
│  Ingestion Layer                │
│  ├─ VirusTotal (file/URL rep)   │
│  ├─ Shodan/InternetDB (ports)   │
│  ├─ NVD/CVE (vulnerabilities)   │
│  └─ Tech Fingerprint (web tech) │
│         │                       │
│         ▼                       │
│  Feature Engineering            │
│  (raw API → numeric vector)     │
│         │                       │
│         ▼                       │
│  Scoring Layer                  │
│  ├─ Baseline heuristic          │
│  ├─ ML fusion model (XGBoost)   │
│  └─ SHAP explainer              │
└─────────────────────────────────┘
        │
        ▼
  React Dashboard / Browser Extension
```

## Data Sources

| Source | Data Provided | Auth Required |
|--------|--------------|---------------|
| VirusTotal | File/URL reputation, engine verdicts | API key (free tier) |
| Shodan InternetDB | Open ports, services, CVEs | None (free) |
| Shodan Full API | Detailed service banners | API key |
| NVD | CVE details, CVSS scores | Optional API key |
| Tech Fingerprint | Web technologies, versions | None (local analysis) |

### Third-Party Datasets
- **Wappalyzer**: The technology fingerprinting module utilizes an open-source subset of the [Wappalyzer technologies dataset](https://github.com/wappalyzer/wappalyzer) (v6). This dataset is distributed under the **MIT License** and allows us to run accurate regex-based DOM/header matching locally without an API.

## Feature Engineering

The feature engineering layer maps raw API JSON into a 19-dimensional continuous feature space. The initial schema contained 13 features heavily focused on VirusTotal heuristics. In Phase 3, we expanded the feature space to 19 dimensions by incorporating richer signals:
- **Shodan Context**: Added categorical/tag-based tracking (`shodan_has_iot_tag`, `shodan_has_compromised_tag`), CPE risk counts, and service diversity scores.
- **Technology Fingerprinting**: Added Wappalyzer-powered tech stack diversity counts, version EOL tracking, and confidence scoring.

## Model Architecture

The system utilizes an **XGBoost (Extreme Gradient Boosting)** classifier (`FusionModel`).
- **Input**: 19-dimensional continuous feature vector.
- **Output**: Binary classification (`0` = Safe, `1` = Malicious) and continuous risk probability.
- **Explainability**: SHAP (SHapley Additive exPlanations) is used to attribute the final risk score back to the exact features that drove the decision, providing human-readable context to analysts.

### Neural Fusion Model (deep learning)

XGBoost scores a target purely from *third-party reputation*, which is blind on
day zero: a freshly-registered phishing domain has no vendor detections yet, so
a reputation-only model rates it *safe*. To close that gap we add a
**character-level neural network** (`UrlFusionNet`, PyTorch) that reads the raw
URL/domain **string** directly and fuses it with the tabular features.

```
raw URL string ──► char embedding ──► parallel Conv1d (k=3,4,5)  ─┐  (TextCNN)
                                       ReLU + global max-pool      │
                                                                   ├─► fusion MLP ─► fused risk
19-dim FeatureVector ──► tabular MLP ──────────────────────────────┘
                                       │
              text representation ─────┴─► text-only head ─► URL-only risk (zero-day)
```

- **Text branch** – a TextCNN (Kim, 2014) over character embeddings; multiple
  kernel widths act as learned character n-gram detectors for phishing lexicon
  (brand impersonation, homoglyphs, hyphen/keyword stuffing, suspicious TLDs,
  IP hosts). ~40k parameters; sub-millisecond CPU inference.
- **Tabular branch** – a small MLP over the standardised 19-dim reputation vector.
- **Fusion head** – concatenates both branches and predicts the final risk;
  trained end-to-end with back-propagation (`ml/train_neural.py`).
- **URL-only head** – a second head over the text representation alone, so a bare
  URL can be scored with **no** external enrichment. This is surfaced in the API
  as `neural_url_score` — the zero-day signal.
- **Explainability** – per-character **saliency** (gradient of the URL-only logit
  w.r.t. the character embeddings) highlights the exact suspicious substring
  (e.g. the `paypa1` look-alike token), returned as `neural_explanations`.

The API (`/scan`) runs the neural model alongside XGBoost and returns
`neural_score`, `neural_label`, `neural_url_score`, and `neural_explanations`
in addition to the existing baseline/ML scores. Loading is best-effort: if the
checkpoint is absent the pipeline transparently falls back to the prior scores.

## Phase 2 — Neural HTTP Attack Classifier

Where Phase 1 reads a URL string, Phase 2 reads the **contents of a request**.
`PayloadCNN` (`app/ml/vuln_classifier.py`) is a character-level TextCNN that
classifies a request-parameter value into **benign / sqli / xss /
path-traversal / cmdi**. Unlike a signature/regex WAF — which matches fixed
strings and is bypassed by obfuscation — a learned character model generalises to
unseen mutations (`' OR 1=1--` vs `'/**/oR/**/1=1-- -`) because it learns the
lexical shape of an attack.

- **Training data (real).** `ml/train_vuln.py` trains on the **Morzeux
  HttpParamsDataset** (`ml/data_sources.py` → `build_http_attack_dataset`): real
  CSIC-2010 normal request parameters plus real SQLi/XSS/path-traversal/cmdi
  attack payloads. The class distribution is genuinely imbalanced (benign and
  sqli dominate); we do **not** fabricate minority samples — the loss is weighted
  by inverse class frequency and per-class precision/recall/F1 are reported so
  weak rare-class numbers stay visible.
- **Explainability.** Per-character saliency highlights the substring that drove
  the verdict (e.g. the `' or 1=1` span).
- **API.** `POST /analyze` classifies a submitted payload, query string, or URL
  (each parameter value individually) and returns per-value verdicts with
  confidence and the suspicious span. It is **passive** — it classifies text the
  caller submits and makes no network request against any target. Active,
  scope-gated probing of a live target is a later phase.

## Evaluation Results

**Conclusion:** A learned ML fusion model modestly but consistently outperforms a calibrated rule-based baseline (ROC-AUC 0.86 vs 0.82, F1 0.84 vs 0.77) on multi-source security risk classification. Expanding the feature space from 13 to 19 dimensions by incorporating richer Shodan and technology-fingerprint signals did not measurably improve raw classification performance on this dataset, but substantially enriched the SHAP-based explainability output available to analysts.

## Known Limitations

### Synthetic Training Data
Real labeled ground-truth data for domain risk assessment at scale is not
freely available. Our training data is synthesized by:
- Using known-malicious domains from URLhaus and PhishTank (freely
  downloadable CSVs) as positive examples (label=1)
- Using top domains from the Tranco list as negative examples (label=0)

This introduces potential biases:
- Malicious domains may be taken down by the time we query them
- "Safe" domains from popularity lists may still have vulnerabilities
- The distribution doesn't match real-world base rates

We document this transparently as a limitation and discuss its impact
on our evaluation metrics in the results section.

> **Phase 1 update — the neural URL model now trains on real data.**
> `ml/train_neural.py --real` trains the character-level `UrlFusionNet` on a
> **real labelled full-URL corpus** (~40k URLs, both benign and malicious are
> real observed URLs *with real paths*, so there is no domain-vs-full-URL
> shortcut and nothing on the benign side is synthesised — see
> `ml/data_sources.py`). Honest held-out performance is **F1 ≈ 0.94 /
> ROC-AUC ≈ 0.98** for the URL-only (text) branch — lower than the earlier
> synthetic figure precisely because the task is harder and the evaluation is
> no longer drawn from the training distribution. The `tabular_only` ablation
> is ~0.50 AUC by design here: with no real *multi-source* labels per URL the
> tabular branch is fed the neutral pre-enrichment vector, so the fused score
> leans on the URL branch. Real multi-source tabular labels are a later phase.
>
> **Registered-domain allowlist.** A character-level model cannot tell a brand
> in the *registered domain* (`paypal.com/us/signin`, legitimate) from a brand
> used as a *token* (`paypal-verify.tk`, phishing) — they are lexically almost
> identical. `NeuralFusionModel` therefore caps the URL risk at 0.15 when the
> registered domain is a known top site (real Tranco top-3000, in
> `app/ml/top_domains.txt`), using last-2/last-3 label matching so a spoof like
> `paypal.com.secure-verify.tk` (registrable domain `secure-verify.tk`) is
> **not** suppressed. This eliminates the brand false-positive class without
> creating a bypass.

### Mock Data Mode
The system supports a `USE_MOCK_DATA=true` mode for development and
demonstration without API keys. Mock responses are based on real API
schemas but do not reflect live threat intelligence.

## Technology Stack

- **Backend:** Python 3.11, FastAPI, Pydantic v2, httpx
- **ML:** scikit-learn, XGBoost, SHAP, pandas, numpy
- **Deep learning:** PyTorch (character-level neural URL fusion model)
- **Database:** SQLite (development) — PostgreSQL migration is a documented TODO
- **Frontend:** React + Vite, Tailwind CSS, recharts
- **Browser Extension:** Manifest V3, vanilla JS
- **Testing:** pytest with mocked API responses
