# ThreatFusion — AI Project Context

> Feed this file to an AI assistant so it understands the full project without exploring the repo from scratch.
> Last oriented for the codebase under `f-ph-ishing` / `threatfusion/`.

---

## 1. What this project is

**Name:** ThreatFusion  
**Tagline:** ML-Based Risk Fusion for Web & Network Attack Surface Analysis  

**Repo root:** `f-ph-ishing` (legacy folder name; the product lives in `threatfusion/`)  
**Primary app root:** `threatfusion/`

ThreatFusion is a **final-year university project** that:

1. Takes a target (domain, IP, URL, or file hash)
2. Pulls threat intel from multiple sources (VirusTotal, Shodan/InternetDB, NVD/CVE, local tech fingerprinting)
3. Turns those signals into a **19-dimensional numeric feature vector**
4. Scores risk two ways:
   - **Baseline:** hand-tuned weighted-sum heuristic
   - **ML fusion:** trained **XGBoost** classifier
5. Explains the ML score with **SHAP**
6. Optionally builds **attack paths / vulnerability chains** using EPSS, CISA KEV, Exploit-DB (+ optional local Ollama LLM)

**Research question:**  
Does a learned fusion model produce more accurate attack-surface risk scores than a naive rule-based / weighted-sum baseline when trained on correlated multi-source security signals?

**Reported eval (approx.):** ML F1 ~0.84 / ROC-AUC ~0.85–0.86 vs baseline F1 ~0.70–0.77 / ROC-AUC ~0.80–0.82. Training data is largely **synthetic** (URLhaus / PhishTank / Tranco-inspired distributions) because labeled multi-source ground truth at scale is scarce.

> ⚠ **Correction (post-audit, 2026-10-02).** These numbers are **not valid for the deployed model**: they predate it (git history), were measured on synthetic data with 15 % injected label noise, and the deployed `fusion_model.json` actually uses only 3 VirusTotal features (see `AUDIT_REPORT.md` §E). The XGBoost score is therefore labelled *experimental*; the baseline is the headline score until the model is retrained on real data (roadmap A2-1).

---

## 2. Repository layout

```
f-ph-ishing/                          # Git root
├── AI_CONTEXT.md                     # This file
├── README.md                         # Minimal (# f-ph-ishing)
├── epss_scores-*.csv                 # EPSS scores (offline intel for chaining)
├── known_exploited_vulnerabilities.csv  # CISA KEV
├── files_exploits.csv                # Exploit-DB-derived data
├── files_extracted/                  # Scaffolding prompts used to build the project
│   ├── threatfusion_master_prompt.md
│   └── threatfusion_placeholder_api_prompt.md
└── threatfusion/                     # ★ Main product
    ├── README.md
    ├── docs/
    │   ├── ARCHITECTURE.md
    │   └── ROADMAP.md
    ├── backend/                      # FastAPI API + ML inference
    │   ├── app/
    │   │   ├── main.py               # App entry, CORS, DB init
    │   │   ├── api/                  # Routes: health, scan
    │   │   ├── core/                 # config, logging, validation
    │   │   ├── ingestion/            # VT, Shodan, CVE, tech fingerprint
    │   │   ├── ml/                   # features, baseline, fusion, SHAP, chaining
    │   │   └── models/schemas.py     # Single Pydantic data contract
    │   ├── tests/
    │   ├── requirements.txt
    │   ├── .env.example
    │   └── threatfusion.db           # SQLite (partially used)
    ├── frontend/                     # React + Vite + Tailwind dashboard
    │   └── src/
    │       ├── App.tsx
    │       ├── api.ts                # Calls http://127.0.0.1:8000
    │       └── components/           # ScanForm, ScanResult, History, Settings, DashboardLayout
    ├── ml/                           # Offline training & evaluation
    │   ├── train.py / train_real.py / evaluate.py
    │   ├── models/fusion_model.json  # Deployed XGBoost artifact
    │   └── results/evaluation_metrics.json
    └── extension/                    # Chrome MV3 popup → local API
```

---

## 3. Tech stack

| Layer | Stack |
|-------|--------|
| Backend | Python 3.11+, FastAPI, Uvicorn, Pydantic v2, pydantic-settings, httpx, aiosqlite |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS 3, Lucide icons |
| ML | scikit-learn, XGBoost, SHAP, pandas, numpy, joblib |
| Attack chaining | networkx; optional Ollama (`llama3` @ `http://localhost:11434`) |
| Tech fingerprint | python-Wappalyzer + bundled `wappalyzer_tech.json` |
| DB | SQLite (`sqlite:///./threatfusion.db`); Postgres mentioned as future |
| Extension | Manifest V3, vanilla JS/HTML/CSS |
| Tests | pytest, pytest-asyncio, pytest-httpx / respx |
| Infra | Local-dev only (no Docker found). CORS allows Vite `5173` / `4173`. |

---

## 4. Runtime architecture

```
User (domain / IP / URL / file hash)
        │
        ▼
┌────────────── FastAPI (localhost:8000) ──────────────┐
│  Ingestion (async httpx; mock OR live)                 │
│    VirusTotal → Shodan/InternetDB → NVD/CVE            │
│    → Tech fingerprint (Wappalyzer-style)               │
│                                                        │
│  Feature engineering → FeatureVector (19 floats)       │
│                                                        │
│  Scoring: baseline + XGBoost FusionModel + SHAP        │
│                                                        │
│  Optional: VulnerabilityChainer                        │
│    EPSS + CISA KEV + Exploit-DB + NetworkX             │
│    (+ Ollama for pre/post conditions, with fallback)   │
└───────────────────────┬────────────────────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
    React dashboard  Browser ext   OpenAPI /docs
```

**Scan flow (`POST /scan`):**  
validate target → enrich sources (tolerate partial failures) → optional CVE chaining → `extract_features` → `baseline_score` + `FusionModel.predict_proba` → `explain_prediction` → return `ScanResponse`.

**Clients** hardcode API base: `http://127.0.0.1:8000`.

---

## 5. API surface

Base: `http://127.0.0.1:8000` · Swagger: `/docs`

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness; `status`, `version`, `mock_mode` |
| `POST` | `/scan` | Full enrichment + scoring. Body: `{ "target": "...", "target_type": "domain\|ip\|url\|file_hash" }` |
| `GET` | `/scan/history` | Abbreviated past scans (newest first) |
| `GET` | `/scan/{scan_id}` | Full result for one scan |

**Important inconsistencies an AI should know:**

- Docs/schemas sometimes say `/api/v1/scan`; **live routes have no `/api/v1` prefix**.
- (Fixed in Phase A0) Scans are now persisted to SQLite (`core/scan_store.py`, versioned migrations in `core/db.py`); history survives restarts.
- Mock mode is the **default** (`USE_MOCK_DATA=true`) so demos work without API keys.

---

## 6. Data contract (schemas)

Single source of truth: `threatfusion/backend/app/models/schemas.py`

Key types:

- `TargetType`: `domain` | `ip` | `url` | `file_hash`
- `ScanRequest` → `ScanResponse` / `ScanResult`
- Per-source: `VirusTotalResult`, `ShodanResult`, `CVEResult` / `CVEDetail`, `TechFingerprintResult` / `DetectedTechnology`
- ML: `FeatureVector` (19 floats), `RiskExplanation`
- Chaining: `AttackChainNode`, `AttackPath`
- History: `ScanHistoryItem`, Health: `HealthResponse`

### FeatureVector (19 dimensions)

**VirusTotal:** `vt_malicious_ratio`, `vt_suspicious_ratio`, `vt_reputation_score`, `vt_last_seen_days_ago`  
**Shodan:** `shodan_open_port_count`, `shodan_has_high_risk_port`, `shodan_cve_count`, `shodan_max_cvss_score`, `shodan_has_iot_tag`, `shodan_has_compromised_tag`, `shodan_service_diversity_score`, `shodan_high_risk_cpe_count`  
**Tech:** `tech_count`, `tech_has_known_eol_component`, `tech_avg_confidence`, `tech_stack_diversity_count`, `tech_has_eol_cms_version`  
**Other:** `ssl_cert_valid`, `domain_age_days` (often static placeholders in feature eng today)

Older docs may say “13 features”; the live pipeline uses **19**.

---

## 7. Backend module map

| Path under `backend/app/` | Role |
|---------------------------|------|
| `main.py` | FastAPI app, CORS, lifespan / DB init, router mount |
| `api/health.py` | Health check |
| `api/scan.py` | Scan orchestration + history |
| `core/config.py` | Settings from env (pydantic-settings) |
| `core/validation.py` | Domain / target pre-validation |
| `core/logging.py` | Logging setup |
| `ingestion/virustotal.py` | VT client (mock + live) |
| `ingestion/shodan.py` | Shodan / InternetDB |
| `ingestion/cve.py` | NVD / CVE enrichment |
| `ingestion/techfingerprint.py` | Local Wappalyzer-style fingerprinting |
| `ml/features.py` | Raw results → FeatureVector |
| `ml/baseline.py` | Weighted-sum heuristic |
| `ml/fusion_model.py` | Load/run XGBoost from `ml/models/fusion_model.json` |
| `ml/explain.py` | SHAP TreeExplainer |
| `ml/chaining.py` | Attack path / vuln chaining |
| `models/schemas.py` | All Pydantic models |

Ingestion clients are async, accept a `use_mock` flag, and return Pydantic models (not raw JSON).

---

## 8. Frontend & extension

**Frontend** (`threatfusion/frontend`):

- Vite React SPA dashboard for scanning, viewing results (baseline vs ML, SHAP), history, settings
- API client: `src/api.ts` → `http://127.0.0.1:8000`
- Components: `ScanForm`, `ScanResult`, `History`, `Settings`, `DashboardLayout`

**Extension** (`threatfusion/extension`):

- Manifest V3 popup that scans the current tab URL via the local backend
- Load as unpacked extension; backend must be running on `:8000`

---

## 9. ML training & artifacts

| Item | Location / notes |
|------|------------------|
| Train (synthetic) | `threatfusion/ml/train.py` |
| Train (real-ish) | `threatfusion/ml/train_real.py` |
| Evaluate | `threatfusion/ml/evaluate.py` |
| Model artifact | `threatfusion/ml/models/fusion_model.json` |
| Metrics | `threatfusion/ml/results/evaluation_metrics.json` |
| Older/ablation | `fusion_model_v1_baseline.json` (if present) |

Run from `threatfusion/`: e.g. `python -m ml.train`, `python -m ml.evaluate`.

---

## 10. Environment variables (names only)

From `.env.example` / `Settings`:

- `USE_MOCK_DATA` — default true for demos
- `VIRUSTOTAL_API_KEY`
- `SHODAN_API_KEY`
- `NVD_API_KEY`
- `DATABASE_URL`
- `LOG_LEVEL`
- Also in config (may not be in `.env.example`): `CACHE_TTL_SECONDS`, `RATE_LIMIT_REQUESTS_PER_MINUTE`

Copy `backend/.env.example` → `backend/.env` for live mode; set `USE_MOCK_DATA=false`.

**Not env vars but used:** Ollama at `localhost:11434`; Shodan InternetDB needs no key.

---

## 11. How to run

```bash
# Backend
cd threatfusion/backend
pip install -r requirements.txt
uvicorn app.main:app --reload
# → http://localhost:8000/docs

# Frontend
cd threatfusion/frontend
npm install
npm run dev
# → typically http://localhost:5173

# Tests
cd threatfusion/backend
pytest -v
```

Prereqs: Python 3.11+, Node.js 18+.

---

## 12. Conventions & gotchas for contributors / AIs

1. **Mock-first** — Prefer keeping mock + live paths sharing the same signatures and response shapes.
2. **Single schemas file** — Prefer extending `schemas.py` rather than inventing parallel DTOs.
3. **Academic comments** — Code often has verbose “why” comments for viva/defense; preserve that tone when editing core ML/API modules unless asked otherwise.
4. **Hardcoded localhost API** — Frontend and extension assume `127.0.0.1:8000`.
5. **Roadmap lag** — `docs/ROADMAP.md` checkboxes may lag reality; trust the code for what’s implemented.
6. **Partial failures** — Scans should still return results when some data sources fail (`data_sources_succeeded` / `data_sources_failed`).
7. **Root CSVs** — EPSS / KEV / Exploit-DB CSVs at repo root support chaining; don’t delete casually.
8. **Do not commit secrets** — Never commit real `.env` API keys.
9. **Repo name vs product** — Folder `f-ph-ishing` is historical; product branding is **ThreatFusion**.

---

## 13. Key files quick index

```
threatfusion/README.md
threatfusion/docs/ARCHITECTURE.md
threatfusion/docs/ROADMAP.md
threatfusion/backend/app/main.py
threatfusion/backend/app/api/scan.py
threatfusion/backend/app/models/schemas.py
threatfusion/backend/app/core/config.py
threatfusion/backend/requirements.txt
threatfusion/backend/app/ml/{features,baseline,fusion_model,explain,chaining}.py
threatfusion/backend/app/ingestion/{virustotal,shodan,cve,techfingerprint}.py
threatfusion/frontend/src/{App.tsx,api.ts}
threatfusion/ml/{train.py,evaluate.py,models/fusion_model.json}
threatfusion/extension/manifest.json
files_extracted/threatfusion_master_prompt.md
```

---

## 14. Suggested system prompt snippet

When giving this context to another AI, you can prepend:

> You are helping develop **ThreatFusion**, an ML-based multi-source attack-surface risk fusion platform (FastAPI + React + XGBoost/SHAP). Prefer matching existing patterns: mock+live ingestion clients, Pydantic schemas in `schemas.py`, 19-feature vector, dual baseline/ML scoring, localhost:8000 API without `/api/v1` prefix. Read the relevant module before editing. Do not invent Docker/Postgres unless asked. Preserve academic clarity in core ML/API comments.

---

## 15. Phase A0 — what changed (2026-10, branch `a0-remediation`)

Audit remediation (see `AUDIT_REPORT.md`). Facts a contributor/AI must know:

- **Auth:** every route except `/health` needs `Authorization: Bearer <token>`. Token = `API_TOKEN` env, else generated on first start and stored **outside the repo** (`%APPDATA%\ThreatFusion\api_token` / `~/.config/threatfusion/api_token`); print with `python -m app.core.auth`. `Host` header must be local (`ALLOWED_HOSTS`); POST/PUT/PATCH/DELETE must be `application/json`. SSE uses single-use tickets (`POST /network/stream-ticket`).
- **Provider results are three-state** (`ProviderResult`, `ProviderStatus`: ok / not_found / error / skipped / not_configured). A failed lookup is **never** data. Features that a provider could not supply are `None` (XGBoost sees NaN) — there are no neutral constants any more (`ssl_cert_valid` / `domain_age_days` stay `None` until A1-3).
- **Verdict:** `verdict_status` ok | partial | unknown. With no VirusTotal answer: `ml_score=None`, `ml_label="Unknown"`, `baseline_score=None`. `baseline_label` is the headline; the XGBoost score is "experimental".
- **Config:** placeholders (`PASTE_YOUR_*`) mean *unset*; unconfigured providers are never called (listed in `data_sources_skipped`). `/health` reports `providers` states. `MODEL_DIR` is absolute (no CWD dependence); every model file is checked against `ml/models/manifest.json` (SHA-256; regenerate with `python -m ml.hash_models`).
- **Outbound HTTP to user-supplied targets goes only through `core/safe_http.SafeFetcher`** (DNS pinning, all A/AAAA checked, per-hop redirect validation, caps). Provider clients talk only to fixed provider hosts.
- **`POST /verify`** is OFF by default (`VERIFY_ENABLED`); scope is server config (`VERIFY_ALLOWED_HOSTS`), the body's `authorized_hosts` is ignored; every call is written to the append-only `verify_audit` table.
- **Privacy:** `core/privacy.py` — private/local/reverse-DNS/invalid names and private IPs never reach a third party; URL scans send only `scheme://host/path` unless `send_full_url`; sensitive headers redacted; network data purged after `NETWORK_RETENTION_DAYS` (30), `DELETE /network/data` erases it.
- **Limits:** per-client `/scan` rate limit (429), body cap (413), `/traffic/analyze` request cap, model inference in worker threads, scan deadline + per-provider timeout.
- **Environment:** Python **3.12**, exact lock files (`backend/requirements*.txt`, compiled with `uv`); run from `backend/`. Tests never touch the real dev DB (conftest forces a throwaway one) and never call real providers (respx / mock mode; `fake_dns` + `mock_site` fixtures for pinned-IP routing).

---

## 16. Phase A1 — what changed (2026-10, branch `a1-enrichment`, stacked on `a0-remediation`)

Making enrichment real (see `threatfusion/docs/ROADMAP.md`). Facts a contributor/AI must know:

- **Targets are canonicalised once** (`core/targets.py`); `ScanResult.canonical` shows what was actually looked up. Invalid IP/hash targets are a 400 `stage: "format"` before any provider is called. The char-CNN still gets the string *as typed* (userinfo/odd casing are its signal).
- **Provider clients are process-wide** (`core/hub.py`); never construct or close one per request. VirusTotal and NVD go through `core/quota.py` (free-tier VT: 4/min, 500/day; NVD: 50 per 30 s) and `core/cache.py` (SQLite `provider_cache`, schema v3, answers only). `ProviderResult`/`ProviderOutcome` gained `retry_after`.
- **New keyless signals** — `ingestion/tls.py` (`ssl_cert_valid`), `rdap.py` (`domain_age_days`, from the registration *date*; WHOIS only where a TLD has no RDAP), `dns_records.py`, `eol.py` (endoflife.date). Each can be switched off (`TLS_ENABLED`, `RDAP_ENABLED`, `DNS_ENABLED`, `EOL_ENABLED`); tests turn them **off by default** (they open sockets respx cannot intercept) and swap in stubs/local servers. `FEATURE_SCHEMA_VERSION` is 3. `ScanResult` gained `tls`, `rdap`, `dns`; `FeatureCoverage` gained `has_tls/has_rdap/has_dns`; `DetectedTechnology` gained `eol*`, `implied`, real `confidence`.
- **`EOL_SET` is gone.** `tech_has_known_eol_component` / `tech_has_eol_cms_version` are 1.0 if any release is end-of-life per endoflife.date, 0.0 if assessed-and-supported (or nothing detected), `None` when techs were found but none could be assessed. The Wappalyzer engine's shared state is reset per page under a lock; `wappalyzer_tech.json` was measured and deleted (see `techfingerprint.py` docstring).
- **Scans run concurrently** (`api/scan.py`): chains `[VT] [InternetDB→NVD] [tech→EOL] [TLS] [RDAP] [DNS]`, gated by `SCAN_MAX_CONCURRENT_PROVIDERS`; `provider_results` keeps a stable order. Progress is published to `core/scan_events.py` and streamed at `GET /scan/{id}/events` (token or single-use ticket from `POST /scan/events-ticket`); a client may choose the `scan_id` so it can subscribe *before* POSTing. Events never contain the target or findings.
- **Mock mode touches no network** (it used to resolve the typed host through the real resolver); the scan `summary` now follows the headline baseline label, not the experimental model's.
- **Frontend:** evidence-first UI (`lib/evidence.ts`, `lib/hostsignals.ts` + components); `npm test` runs the pure view-model tests with Node's built-in runner (CI runs it).

---

## 17. One-paragraph elevator pitch

ThreatFusion fuses VirusTotal reputation, Shodan exposure, CVE severity, and web technology fingerprints into one explainable risk score, comparing a trained XGBoost fusion model against a rule-based baseline, with SHAP explanations and optional EPSS/KEV/Exploit-DB attack-path chaining — delivered via a FastAPI backend, React dashboard, and browser extension for a university research demo.
