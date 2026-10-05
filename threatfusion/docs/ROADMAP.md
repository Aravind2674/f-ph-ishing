# ThreatFusion — Development Roadmap

> **Status note.** The phase checklists further down were never ticked and lag reality (the code exists
> for most of them). The authoritative status after the 2026-10-02 audit is the programme below; see
> `AUDIT_REPORT.md` for the evidence.

## Remediation programme (post-audit)

### Phase A0 — correctness, security, data integrity ✅ (branch `a0-remediation`)
- [x] A0-7 Reproducible environment: Python 3.12, exact lock files, CI, model SHA-256 manifest, `weights_only=True`
- [x] A0-5 Config validation: placeholders are *unset*, unconfigured providers are never called, `/health` provider states
- [x] A0-1 Three-state provider results; unknown stays unknown; verdict `ok | partial | unknown`
- [x] A0-2 Models located independently of the CWD; baseline is the headline, XGBoost labelled experimental
- [x] A0-4 One SSRF-safe fetcher (DNS pinning, per-hop redirect validation, size/time caps)
- [x] A0-3 `/verify`: server-side scope, off by default, audited, rate-limited, TLS-verified
- [x] A0-6 Scans persisted (versioned migrations, absolute DB path, provenance incl. model/feature-schema versions)
- [x] A0-8 Local API token, Host allow-list, JSON-only mutations, no credentialed CORS, SSE tickets
- [x] A0-9 Rate limit, body/batch caps, inference off the event loop, scan deadline + provider timeouts
- [x] A0-10 Privacy defaults (private names never sent out, URL stripping, header redaction), retention + erase

### Phase A1 — make enrichment and scoring work ✅ (branch `a1-enrichment`, stacked on A0)
- [x] A1-6 One input canonicaliser (`core/targets.py`): punycode host, eTLD+1 from an offline Public Suffix List, IP/hash validation, `ScanResult.canonical`
- [x] A1-1 VirusTotal: one shared client + quota limiter (4/min, 500/day, shared with the network layer), SQLite `provider_cache`, `/ip_addresses` for IPs, `Retry-After`
- [x] A1-2 NVD: backoff on 403/429/503, config-driven rate window, bounded fan-out with a deadline that keeps partial results, persistent CVE cache, CPE lookups with pagination
- [x] A1-3 Real host signals: TLS certificate (`ssl_cert_valid`), RDAP/WHOIS registration (real `domain_age_days`), DNS records + SPF/DMARC/CAA + hosting ASN
- [x] A1-4 Technology / EOL accuracy: endoflife.date (cached weekly), real Wappalyzer confidence, no cross-site version leaks, warning-free fingerprints; unused fingerprint dump deleted
- [x] A1-5 Concurrent providers (`asyncio.gather` + a process-wide gate) and live per-provider progress over SSE (`GET /scan/{id}/events`)
- [x] A1-7 Evidence-first UI: per-source status chips (live and final), "based on N of M sources", "No findings ≠ safe", per-feature provenance, host-evidence cards

### Next
- [ ] **A2** Validate the ML pipeline: retrain on real snapshot-enriched labels, model-health tests, neural URL canonicalisation, payload-classifier evaluation, model cards
- [ ] **A3** Passive network monitoring: capture preflight, sensor lifecycle, DNS responses/SNI, reputation fan-out control, rogue-AP precision
- [ ] **A4** Attack chains, reports, history UX, repo hygiene
- [ ] **Part B** research-backed features (independent reputation channels, CT/RDAP, lookalike detection, calibrated fusion, …)

---

## Original phase checklists (historical — not maintained)

## Phase 1 — Repo Scaffold ✅
- [x] Project directory structure
- [x] Pydantic schemas for all data models
- [x] FastAPI app skeleton with health endpoint
- [x] Configuration management (env vars, mock/live switch)
- [x] Test infrastructure

## Phase 2 — Ingestion Layer
- [ ] VirusTotal async client (mock + live modes)
- [ ] Shodan/InternetDB async client (mock + live modes)
- [ ] CVE/NVD async client (mock + live modes)
- [ ] Tech fingerprint client with Wappalyzer-style rules
- [ ] Rate limiting and caching for all clients
- [ ] Pytest tests with mocked responses for each client

## Phase 3 — Feature Engineering
- [ ] Feature extraction from raw ingestion data
- [ ] Feature documentation with security rationale
- [ ] Feature vector tests

## Phase 4 — Baseline Heuristic
- [ ] Weighted-sum rule-based scorer
- [ ] Document weight rationale
- [ ] Baseline scorer tests

## Phase 5 — ML Fusion Model
- [ ] Synthetic labeled dataset generation
- [ ] XGBoost classifier training pipeline
- [ ] SHAP explainer integration
- [ ] Model serialization

## Phase 6 — Evaluation
- [ ] Baseline vs ML comparison on held-out test set
- [ ] Precision/Recall/F1/ROC-AUC reporting
- [ ] Comparison chart generation

## Phase 7 — Backend API
- [ ] Full /scan endpoint implementation
- [ ] SQLite persistence for scan history
- [ ] Scan retrieval endpoint

## Phase 8 — Frontend Dashboard
- [ ] React + Vite project setup
- [ ] Search interface
- [ ] Results view with risk gauge
- [ ] SHAP explanation visualization
- [ ] Scan history

## Phase 9 — Browser Extension
- [ ] Manifest V3 setup
- [ ] Content script tech detection
- [ ] Popup UI with risk check button

## Future Work (Post-Submission)
- [ ] PostgreSQL migration
- [ ] Real-time monitoring/webhooks
- [ ] Multi-user support with authentication
- [ ] Additional data sources (AbuseIPDB, URLScan.io)
