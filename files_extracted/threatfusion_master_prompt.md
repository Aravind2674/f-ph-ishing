# MASTER PROMPT — Paste this into Claude Code to build ThreatFusion

---

## ROLE

You are acting as the lead engineer building **ThreatFusion**, a final-year
AI/ML university project for a team of 2-3 students. Build this as a real,
working codebase — not a toy demo. Prioritize clean architecture, working
code over placeholder stubs, and inline comments that explain *why*, since
the students must be able to defend every design decision to academic staff
in a viva/demo.

---

## PROJECT SUMMARY

**Title:** ThreatFusion — ML-Based Risk Fusion for Web & Network Attack
Surface Analysis

**One-line pitch:** A unified threat-intelligence platform that aggregates
signals from VirusTotal (file/URL reputation), Shodan/InternetDB (exposed
network services + open ports), and Wappalyzer-style web technology
fingerprinting — then uses a trained ML model to fuse these into a single
explainable risk score, instead of the rule-based/weighted-sum heuristics
existing tools use.

**Research question the project must be able to answer with evidence:**
> Does a learned fusion model produce more accurate attack-surface risk
> scores than a naive rule-based/weighted-sum heuristic baseline, when
> trained on correlated multi-source security signals?

This means the codebase MUST include both:
1. A rule-based baseline scorer (simple, transparent, hand-coded weights)
2. A trained ML fusion model
3. An evaluation script that benchmarks (2) against (1) on held-out labeled
   data, reporting precision/recall/F1/ROC-AUC, so the comparison is a real,
   reportable result

---

## SYSTEM ARCHITECTURE

```
User enters domain / IP / file hash
        │
        ▼
┌─────────────────────────────────────────┐
│           FastAPI Backend                │
│                                           │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │ Ingestion    │  │ Feature          │  │
│  │ Layer        │─▶│ Engineering      │  │
│  │ - VT client  │  │ (combine raw     │  │
│  │ - Shodan/    │  │  API responses   │  │
│  │   InternetDB │  │  into a flat     │  │
│  │   client     │  │  feature vector) │  │
│  │ - CVE/NVD    │  └────────┬─────────┘  │
│  │   client     │           │            │
│  │ - Tech       │           ▼            │
│  │   fingerprint│  ┌──────────────────┐  │
│  │   client     │  │ Scoring Layer     │  │
│  └─────────────┘  │ - Baseline        │  │
│                    │   heuristic       │  │
│                    │ - ML fusion model │  │
│                    │ - SHAP explainer  │  │
│                    └────────┬─────────┘  │
│                             ▼            │
│                    JSON response:        │
│                    {raw_data, baseline_  │
│                     score, ml_score,     │
│                     explanation}         │
└─────────────────────────────────────────┘
        │
        ▼
  React Dashboard  /  Browser Extension
```

---

## TECH STACK (use exactly this, don't substitute without a strong reason)

- **Backend:** Python 3.11, FastAPI, Pydantic v2, httpx (async API calls)
- **ML:** scikit-learn + XGBoost for the fusion model, SHAP for explainability,
  pandas/numpy for feature engineering
- **Database:** SQLite for development (single file, zero setup — swap to
  PostgreSQL later is a documented TODO, not built now)
- **Frontend:** React + Vite, Tailwind CSS, recharts for score visualizations
- **Browser extension:** Manifest V3, vanilla JS content script (reuses
  Wappalyzer's open-source MIT-licensed fingerprint rules — do NOT scrape or
  call Wappalyzer's paid API)
- **Testing:** pytest for backend, with mocked API responses (no real API
  calls in tests)

---

## BUILD ORDER (build and verify each phase before moving to the next)

### Phase 1 — Repo scaffold
Create this exact structure:
```
threatfusion/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/            # route handlers: scan.py, health.py
│   │   ├── core/           # config.py (env/settings), logging.py
│   │   ├── ingestion/      # virustotal.py, shodan.py, cve.py, techfingerprint.py
│   │   ├── ml/             # features.py, baseline.py, fusion_model.py, explain.py
│   │   └── models/         # pydantic schemas (request/response)
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
├── ml/
│   ├── data/                # sample labeled dataset (synthesize if no real data yet)
│   ├── train.py             # trains + saves the fusion model
│   ├── evaluate.py          # benchmarks fusion model vs baseline, prints metrics
│   └── notebooks/
├── frontend/                 # React app
├── extension/                 # browser extension
└── docs/
    ├── ARCHITECTURE.md
    └── ROADMAP.md
```

### Phase 2 — Ingestion layer
Build async API client wrappers for:
- `virustotal.py`: lookup by domain/URL/file hash, return normalized dict
  (reputation score, malicious/harmless engine counts, last analysis date)
- `shodan.py`: use free InternetDB (`https://internetdb.shodan.io/{ip}`, no
  key required) for open ports/services/CVEs; also support full Shodan API
  if a key is present
- `cve.py`: query NVD API for CVE details given a CPE/product+version string
- `techfingerprint.py`: implement a minimal Wappalyzer-style detector —
  fetch a URL, inspect response headers, HTML meta tags, and common JS
  globals against a small curated ruleset (don't need the full Wappalyzer
  ruleset, ~30-40 common technologies is enough for a student project)

All clients: async, rate-limited, cached (simple in-memory or SQLite cache
to avoid hitting free-tier API limits during testing), and must read API
keys from environment variables via `core/config.py` — never hardcoded.
Include realistic mocked responses as test fixtures so the rest of the
system can be built/tested without live API keys.

### Phase 3 — Feature engineering
`ml/features.py`: given raw ingestion output for a target, produce a flat
numeric feature vector, e.g.:
- `vt_malicious_ratio`, `vt_last_seen_days_ago`
- `shodan_open_port_count`, `shodan_has_high_risk_port` (RDP/Telnet/etc.)
- `shodan_cve_count`, `shodan_max_cvss_score`
- `tech_stack_age_days` (time since detected framework's last release),
  `tech_has_known_eol_component`
- `domain_age_days`, `ssl_cert_valid`

Document each feature's rationale in comments — staff will ask "why this
feature."

### Phase 4 — Baseline heuristic
`ml/baseline.py`: a simple, transparent weighted-sum or rule-based scorer
using the same features. This is the control group for your evaluation —
keep it genuinely simple (e.g., normalized weighted sum with hand-picked
weights, documented), not secretly sophisticated.

### Phase 5 — ML fusion model
`ml/fusion_model.py` + `ml/train.py`:
- Since real labeled attack-surface data is scarce, generate a synthetic
  but realistic labeled dataset (script this — combine known-malicious
  domains from open lists like URLhaus/PhishTank with known-benign popular
  domains, run them through the ingestion+feature pipeline, label
  malicious=1/benign=0)
- Train an XGBoost classifier (or gradient boosting) on the feature vectors
- Save the trained model (joblib/pickle) to `ml/models/fusion_model.pkl`
- `ml/ml/explain.py`: SHAP explainer that returns top contributing features
  per prediction, in human-readable form (e.g., "Open RDP port (+0.31 risk),
  outdated CMS version (+0.22 risk)")

### Phase 6 — Evaluation
`ml/evaluate.py`: load held-out test set, run both baseline and fusion model,
report precision/recall/F1/ROC-AUC for both side by side, output as a table
and a saved comparison chart (matplotlib). This script's output IS your
core research result — make it clean and reproducible.

### Phase 7 — Backend API
`backend/app/api/scan.py`:
- `POST /scan` — body: `{"target": "example.com", "type": "domain"}` →
  runs ingestion + features + baseline_score + ml_score + explanation,
  returns unified JSON
- `GET /scan/{id}` — retrieve a past scan result from SQLite
- `GET /health` — basic healthcheck
Include OpenAPI docs (FastAPI gives this for free via `/docs`).

### Phase 8 — Frontend dashboard
React app with:
- Search input (domain/IP/hash) → calls `/scan`
- Results view: raw data summary (VT/Shodan/tech-stack panels), risk score
  gauge (baseline vs ML side-by-side for demo purposes), SHAP explanation
  as a horizontal bar chart of feature contributions
- Scan history list

### Phase 9 — Browser extension
Manifest V3 extension:
- Content script detects tech stack on the current page (reuse the same
  ruleset as `techfingerprint.py`, ported to JS)
- Popup shows detected tech + a "Check full risk score" button that calls
  the backend `/scan` endpoint for the current page's domain

---

## CODING STANDARDS

- Type hints everywhere in Python; Pydantic models for all API I/O
- Every ingestion client must handle API failures gracefully (timeouts,
  rate limits, malformed responses) — never let one failed source crash
  the whole scan
- Docstrings on every non-trivial function explaining intent, not just
  mechanics
- No hardcoded secrets — `.env` + `.env.example` pattern
- Write pytest tests for: each ingestion client (mocked), feature
  engineering, baseline scorer, and the `/scan` endpoint end-to-end (mocked)
- After each phase, run the tests and confirm they pass before moving on

---

## WHAT TO DO IF DATA/LABELS ARE UNAVAILABLE

Real labeled ground-truth data for "risky vs safe" domains at this scale is
hard to get. Do NOT block on this — synthesize a reasonable labeled dataset
using: known-malicious lists (URLhaus, PhishTank — both freely downloadable
CSVs, no API key needed) as positive examples, and a curated list of
well-known safe domains (e.g. top Tranco list entries) as negative examples.
Document this clearly as a limitation in `docs/ARCHITECTURE.md` — being
upfront about synthetic-data limitations is expected and fine for a
final-year project, and staff will respect the honesty more than a
hand-waved "we have great data."

---

## DELIVERABLE AT THE END

After building, produce `docs/ARCHITECTURE.md` summarizing: final system
design, feature list with rationale, model choice rationale, evaluation
results (baseline vs ML numbers), and known limitations — this becomes the
backbone of the written project report.

Work phase by phase. After each phase, briefly summarize what was built and
run relevant tests before proceeding to the next phase.
