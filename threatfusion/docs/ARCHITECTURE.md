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

### Mock Data Mode
The system supports a `USE_MOCK_DATA=true` mode for development and
demonstration without API keys. Mock responses are based on real API
schemas but do not reflect live threat intelligence.

## Technology Stack

- **Backend:** Python 3.11, FastAPI, Pydantic v2, httpx
- **ML:** scikit-learn, XGBoost, SHAP, pandas, numpy
- **Database:** SQLite (development) — PostgreSQL migration is a documented TODO
- **Frontend:** React + Vite, Tailwind CSS, recharts
- **Browser Extension:** Manifest V3, vanilla JS
- **Testing:** pytest with mocked API responses
