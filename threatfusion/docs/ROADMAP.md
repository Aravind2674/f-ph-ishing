# ThreatFusion — Development Roadmap

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
