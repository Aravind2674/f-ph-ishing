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

## Phase 3 — Live Traffic Capture

Phase 3 feeds **real HTTP traffic** into the Phase 2 classifier — the model reads
the request packets. Capture is source-agnostic (`app/recon/traffic.py`):

- **HAR import.** `parse_har` accepts a HAR export — the JSON format produced by
  Burp Suite, Chrome/Firefox DevTools, and OWASP ZAP — so traffic from any of
  those tools can be scored without extra integration.
- **Live mitmproxy stream.** `tools/mitm_addon.py` is a real mitmproxy addon
  (mitmproxy is the scriptable equivalent of Burp's proxy). Run
  `mitmdump -s tools/mitm_addon.py` and browse an authorised target through it;
  every request is POSTed to the backend and scored live, with injection
  attempts printed to the event log.
- **Analysis.** For each request, `extract_values` pulls the attacker-controlled
  inputs — query parameters, URL path, and body (form-encoded or JSON, flattened
  to `body:<path>`) — and classifies each; the request's verdict is its most
  severe value.

`POST /traffic/analyze` accepts either a normalised batch (`requests`) or a HAR
document (`har`) and returns per-request verdicts, a flagged count, and a
summary. Like Phase 2 it is **passive** — it scores captured traffic and issues
no requests of its own. Raw packet capture (tshark/PCAP) and out-of-band blind
detection are future additions; HTTPS payloads are covered via the mitmproxy CA
or a HAR export rather than raw TLS sniffing.

## Phase 4 — Active Verification (scope-gated, non-destructive)

Phases 2–3 *flag* likely injection points; Phase 4 *confirms* them by actively
probing the target — the "simulate the attack and check" step that separates a
real finding from a false positive. `app/verify/active.py` + `POST /verify`.

Safety is the design:

- **Scope gate (default-deny).** `host_is_authorized` only permits **loopback**
  or a host the caller explicitly attests to in `authorized_hosts`. Every other
  host is refused *before any packet is sent* — the tool is a scoped assessment
  aid, not a weapon.
- **Non-destructive probes only.** Three read-only signals: a **reflected-XSS
  canary** (a unique inert marker with raw angle brackets — confirmed only if it
  returns unescaped), **error-based SQLi** (a lone quote; a real SQL error string
  is the evidence), and **boolean-based SQLi** (a TRUE tautology vs a FALSE
  contradiction; a large, consistent divergence means the condition is evaluated
  server-side). There is deliberately no payload that writes, deletes,
  exfiltrates, executes, or calls out-of-band.
- **Bounded.** Short timeouts and a hard cap on parameters probed.

`tools/vuln_lab.py` is a tiny local intentionally-vulnerable app (reflected-XSS,
SQLi, and a safe/escaped control) — the local equivalent of standing up Juice
Shop/DVWA. Verified: the engine confirms the XSS and SQLi endpoints, correctly
clears the escaped control, and refuses any non-loopback host.

## Security & data-integrity architecture (Phase A0)

The post-audit hardening added these cross-cutting components (all under `backend/app/core/` unless noted):

| Concern | Component | Guarantee |
|---|---|---|
| Honest data | `providers.py`, `ProviderResult` / `ProviderStatus` (`models/schemas.py`) | Every provider call returns a status (ok / not_found / error / skipped / not_configured) with HTTP status, reason, timestamp, cache flag, latency. A failure is never turned into data and never cached. |
| Missing evidence | `ml/features.py` | A provider that did not answer leaves its features `None` (XGBoost sees NaN); coverage flags (`FeatureCoverage`) are reported; verdict is `ok / partial / unknown`. |
| Outbound safety | `safe_http.py` | User-supplied targets are fetched only through `SafeFetcher`: all A/AAAA checked, connection pinned to the validated IP, redirects re-validated per hop, size/time caps. |
| Access control | `auth.py`, `security.py` | Bearer token on every route but `/health`; `Host` allow-list; JSON-only mutations; body-size cap; single-use SSE tickets. |
| Active probing | `verify/active.py`, `audit.py` | Off by default; scope is server config; every call appended to `verify_audit` (append-only triggers). |
| Privacy | `privacy.py` | Private/local/reverse-DNS/invalid names and private IPs never sent to third parties; URL scans strip userinfo/query/fragment unless opted in; sensitive headers redacted; network data retention + erase. |
| Persistence | `db.py`, `scan_store.py` | `PRAGMA user_version` migrations; every scan stored with mock flag, provider provenance, model versions, feature-schema version. |
| Model integrity | `artifacts.py`, `ml/models/manifest.json` | Model files verified by SHA-256 before loading; `weights_only=True`. |
| Limits | `ratelimit.py`, `config.py` | Per-client `/scan` rate limit, request caps, per-scan deadline, inference in worker threads. |

## Enrichment architecture (Phase A1)

| Concern | Component (`backend/app/…`) | Behaviour |
|---|---|---|
| One parser | `core/targets.py` | `canonicalize(raw, declared) → Target` (punycode host, eTLD+1 via an offline PSL, IP/hash validation, public URL form). Every component consumes the `Target`, never the typed string. |
| Shared provider clients | `core/hub.py` | One client per provider for the whole process (VirusTotal, NVD, TLS, RDAP, DNS, endoflife) built from settings; scans and the network layer share them. |
| Quota | `core/quota.py` | Sliding-window limiter with *slot reservation* (exact under concurrency, FIFO), bounded queueing (`rate_limited` + `retry_after` instead of hanging), `penalize()` to honour `Retry-After`/backoff. Arbitrary windows (NVD: 50 / 30 s). |
| Cache | `core/cache.py`, `provider_cache` (schema v3) | SQLite TTL cache. Only answers (`ok`, `not_found`) are stored — never failures; the original `fetched_at` is kept; URLs keyed by SHA-256; erased by `DELETE /network/data`. |
| Host signals | `ingestion/tls.py`, `rdap.py`, `dns_records.py` | Keyless, three-state, cached. TLS: verified handshake + an unverified second read so an expired/self-signed certificate is still parsed and explained. RDAP via the IANA bootstrap (WHOIS only where a TLD has no RDAP). DNS per-family `list \| [] \| None` (none exist ≠ lookup failed). |
| Lifecycle | `ingestion/eol.py`, `techfingerprint.py` | endoflife.date by release cycle; Wappalyzer's real confidence; analysis state reset per page under a lock, run in a worker thread; fingerprint data loaded lazily and warning-free. |
| Concurrency | `api/scan.py` | Chains run together: `[VirusTotal] [InternetDB → NVD] [tech → endoflife] [TLS] [RDAP] [DNS]`; a process-wide gate (`SCAN_MAX_CONCURRENT_PROVIDERS`) bounds calls in flight; outcomes keep a stable order. |
| Live progress | `core/scan_events.py`, `GET /scan/{id}/events` | Replay + live SSE bus (thread/loop-safe, bounded). Events carry provider names, statuses, reasons and timings only — never the target or any finding. Token or single-use ticket. |
| Evidence UI | `frontend/src/lib/evidence.ts`, `hostsignals.ts`, `components/{SourceChip,EvidencePanel,FeatureProvenance,HostSignals,LiveSources}.tsx` | Pure view models (unit-tested with `npm test`) rendered monochrome: state is carried by icon + wording + border style, never colour. |

## Evaluation Results

> ⚠ **Correction (2026-10-02):** the figures below are **not valid for the deployed model** — they predate it,
> were measured on synthetic data with 15 % injected label noise, and the deployed XGBoost model uses only
> three VirusTotal features. See `AUDIT_REPORT.md` §E. They are kept for history until the model is retrained
> and evaluated on real, time-split data (roadmap A2-1).

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
