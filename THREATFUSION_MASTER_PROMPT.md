# ThreatFusion — Master Implementation Prompt
### Task 1: Fix what the audit found · Task 2: Add research-backed features

> Paste this file into Claude Code / Copilot from the repo root (`f-ph-ishing/`).
> Read `AUDIT_REPORT.md` in full before starting. This prompt depends on it.

---

## 0. Context and ground rules

You are a senior security-ML engineer taking over **ThreatFusion** (`threatfusion/`), a final-year B.Tech Cybersecurity
project: FastAPI backend, React 19 + Vite + Tailwind dashboard, Chrome MV3 extension. It enriches a target (domain / URL /
IP / hash) from VirusTotal, Shodan InternetDB, NVD and Wappalyzer, builds a 19-float feature vector, scores it with a
heuristic baseline, an XGBoost "fusion" model and a char-CNN URL model, explains with SHAP, chains CVEs using
EPSS/KEV/Exploit-DB, classifies HTTP payloads (`/analyze`, `/traffic/analyze`), runs scoped checks (`/verify`), and has a
network layer (ARP/DNS sensors, Wi-Fi AP scanner, correlation engine, SSE alert feed).

The 2026-10-02 audit showed the results cannot be trusted yet:
- The XGBoost score is constant. It uses 3 of 19 features (all VirusTotal) and gave one output value over 20,000 inputs.
- Provider failures are reported as successes, so outages look like "clean" results.
- `ssl_cert_valid` and `domain_age_days` are hard-coded on every scan.
- The URL model jumps from 0.13 to 0.99 because of an `https://` prefix.
- `/verify` trusts an allowlist supplied in the request body.
- NVD key is a placeholder, so CVE data is always empty.
- Scan history is stored only in RAM.

### Rules
1. **Re-verify each finding before fixing.** The audit cites `file:line` at commit `b28b76d`; lines may have moved.
   If something is already fixed, note it and move on.
2. **No live third-party API calls** during development or tests unless I approve. Tests use `respx` / fixtures.
   Never print or commit `.env` values.
3. **Every change ships with a test** that fails before the change. `pytest`, `tsc --noEmit` and `oxlint` stay green.
4. **Keep mock mode, but label it per scan.** Every result carries its own `mock_mode` flag and per-source provenance.
5. **Additive API changes only.** Existing endpoint shapes keep working; new fields are optional.
6. **Keep the academic "why" comment style** in core ML/API modules (it supports the viva).
7. **Never fabricate data, labels or metrics.** No random features in training. Missing signal = `null` + a
   missingness flag, never a neutral constant.
8. One branch and one PR per phase, small commits, acceptance checklist in each PR. Update `docs/ROADMAP.md`,
   `docs/ARCHITECTURE.md` and `AI_CONTEXT.md` at the end of each phase.
9. Items marked **[ASK]** need my decision. Stop and give me 2–3 options.
10. Do A0-7 (pinned environment) before anything else.

### Core design decision
Split the single "risk" score into two scores, each with its own evidence:
- **Maliciousness**: is this URL/domain phishing, malware or a scam? Public labelled data exists, so this is where the
  ML-vs-baseline research question lives.
- **Exposure**: how exposed is this host's attack surface? Good labels don't exist, so use a transparent,
  exploit-informed score (EPSS, KEV, SSVC, CVSS; see B11) rather than a classifier trained on fake labels.

The UI shows both scores and the evidence behind each. Never blend them into one unexplained number.

---

# PART A — Audit remediation

Order: **A0 → A1 → A2 → A3 → A4**. IDs map to audit §J (P0-1 = A0-1, and so on).

## A0 — Correctness, security, data integrity

### A0-1 Three-state provider results *(P0-1)*
**Problem:** any HTTP error becomes an empty object, then zeros, then "clean". Failed sources are even listed as succeeded.
**Fix:**
- Add a generic `ProviderResult[T]` to `models/schemas.py` with: `source`, `status`
  (`ok | not_found | error | skipped | not_configured`), `data`, `http_status`, `reason`, `fetched_at`, `cached`, `latency_ms`.
- Every client in `ingestion/`, `network/enrichment/` and `app_layer.py` returns it. Map 404 → `not_found`,
  401/403 → `error(auth)`, 429 → `error(rate_limited)`, 5xx/timeout → `error`.
- Remove truthiness checks like `if vt:` (an empty `VirusTotalResult()` is truthy).
- `scan.py` builds `data_sources_succeeded/failed/skipped` from statuses only.
- `features.py` adds a `has_<provider>` flag per source and sets that provider's numeric features to `NaN`
  (XGBoost handles NaN natively) instead of 0 or 0.5.
- If every maliciousness source fails, the verdict is `unknown`, never `Low`.
**Accept:** respx tests for 401/403/404/429/503/timeout per provider; a full-outage scan returns `unknown` with every
provider listed as failed; the UI shows "unavailable" instead of zeros.

### A0-2 Stop presenting the broken XGBoost score *(P0-2)*
- Until A2-1 ships a validated model, label it "Experimental (VirusTotal only)" in `RiskScorePanel.tsx`,
  `ScanResult.tsx` and `popup.js`. Make the baseline and the evidence the headline.
- If a model fails to load, return `ml_score: null` and `ml_status: "model_not_loaded"`. Delete the code that sets
  `ml_score = baseline` (`scan.py` ~215-218).
- Load models from a `MODEL_DIR` setting resolved from `Path(__file__)`, not from the current working directory.
**Accept:** no UI text claims a "learned multi-source score"; running uvicorn from any directory gives identical results.

### A0-3 Server-side scope for `/verify` *(P0-3, H1)*
- Ignore `authorized_hosts` from the request body (keep the field for compatibility and log a warning).
- Read the allowlist from config (`VERIFY_ALLOWED_HOSTS`, default: local lab only), behind a `VERIFY_ENABLED=false` master switch.
- Deny private, link-local and cloud-metadata ranges unless explicitly listed. Route all requests through the safe
  fetcher (A0-4).
- Write an append-only `verify_audit` table (time, target, resolved IP, checks run, outcome). Cap the request rate per
  host. Turn TLS verification on by default.
**Accept:** a host supplied in the body is refused; a host not in config is refused; every call writes an audit row.

### A0-4 One SSRF-safe fetcher *(P0-4, H2)*
Create `core/safe_http.py` and make it the only way the backend fetches a user-supplied target (validation, tech
fingerprinting, verify, and the future crawler).
- Resolve all A/AAAA records asynchronously. Reject the target if any resolved address is internal or reserved.
- Connect to the resolved, validated IP (pinned), so a second DNS lookup can't swap it.
- Handle redirects manually and re-validate every hop. Cap redirects, response size and total time. Allow only
  http/https on configured ports.
- Use Python's `ipaddress` module to classify addresses. Don't hand-roll string checks.
**Accept:** tests against local test servers show redirects to internal and metadata addresses are blocked, and that a
resolver changing its answer between lookups has no effect.

### A0-5 Config validation *(P0-5, H9)*
Treat `PASTE_YOUR_*`, empty and `your_*_here` values as unset. Log a configured / missing / placeholder table at
startup. Extend `/health` with `providers: {name: {configured, mock}}`, booleans only. Never call an unconfigured
provider; return `status=not_configured` instead.
**Accept:** with no NVD key, NVD is never called and the UI shows "not configured".

### A0-6 Persist scans and fix schema drift *(P0-6)*
Write every scan to the existing (never-used) `scans` table: id, target, type, created_at, result JSON, model versions,
feature schema version, mock flag and provenance JSON. Add a small versioned migration helper. Add `summary` to
`ScanResult`: it is computed today and then dropped. Take the DB path from an absolute setting.
**Accept:** history is identical after a restart; the summary renders in the UI.

### A0-7 Reproducible environment *(P0-7, H7)*
- Pin dependencies with a lockfile (`pip-compile` or `uv`). **[ASK]** Python version: default 3.12, since the audit
  hit numba/NumPy conflicts on 3.14.
- Replace the single `aiohttp` use with httpx. Move Playwright into an optional requirements file.
- Use `torch.load(..., weights_only=True)` and check a SHA-256 hash of each model file at load.
- Add GitHub Actions CI: install from the lockfile, then run `pytest`, `tsc`, `oxlint`, `pip-audit` and `npm audit`.
**Accept:** a fresh clone passes CI.

### A0-8 Local API token, Host check, JSON-only POSTs *(P0-8, H3)*
- Generate a random token on first start, store it outside the repo, and require it as a Bearer token on every
  mutating route plus `/network/*` and `/scan/history`.
- Reject requests whose `Host` header isn't localhost:8000 or 127.0.0.1:8000.
- Require `Content-Type: application/json` on POSTs; the body-less monitor start/stop routes become JSON POSTs.
- The frontend and extension read the token from Settings. Set CORS `allow_credentials=False`.
**Accept:** a cross-site form POST and a request with a foreign `Host` header are both rejected.

### A0-9 Request limits and event-loop hygiene *(H4)*
- Cap `/traffic/analyze` (number of requests and HAR size).
- Add a per-client rate limit on `/scan`, wiring up the currently unused `RATE_LIMIT_REQUESTS_PER_MINUTE`.
- Run torch inference and other blocking calls in a threadpool.
- Give each scan an overall deadline (around 45 s); slow providers become `error(timeout)`.
**Accept:** oversized HAR → 413; the SSE heartbeat keeps flowing during a long scan.

### A0-10 Privacy defaults *(H5, H6)*
- The extension sends only the registered domain by default; sending the full URL is a per-scan opt-in.
- Never send private names (`.local`, `.lan`, `.internal`, `.home.arpa`, reverse-DNS names, single-label names) to any
  third party. Validate DNS names before putting them in provider URLs.
- The mitm addon redacts `Cookie`, `Authorization`, `Set-Cookie` and API-key headers.
- Add a retention TTL for `net_*` tables (default 30 days), a purge job, and `DELETE /network/data`.
**Accept:** tests prove private names never reach a provider client; purge test passes.

## A1 — Make enrichment and scoring work

### A1-1 VirusTotal *(P1-1)*
- Create one process-wide client in the FastAPI lifespan. Today a new client per scan or DNS event means the cache never hits.
- Share one token bucket between scans and the network layer (free tier: 4/min, 500/day; configurable).
- Add a SQLite TTL cache table (`provider_cache`).
- Call the right endpoint per kind; IPs must go to `/ip_addresses/{ip}`, not `/domains/`.
- Honour `Retry-After` on 429.
**Accept:** in a 50-scan load test the limit is never exceeded and the cache hits; IP targets use `/ip_addresses`.

### A1-2 NVD *(P1-2)*
Use a real key (I'll add it). Back off on 403/429/503. Respect NVD's published rate window, read from config. Bound
concurrency, add a deadline, persist a CVE cache, and look up by CPE from InternetDB with pagination.
**Accept:** a 20-CVE fixture finishes within the deadline; the Log4Shell fixture returns CVSS 10.0.

### A1-3 Real host signals *(P1-3)*
All of these are three-state, cached, and have mock + live modes:
- `ingestion/tls.py`: chain validity, days to expiry, certificate age, issuer type (free DV vs OV/EV), SAN matches host.
- `ingestion/rdap.py`: RDAP through the IANA bootstrap (RFC 9224). Gives registration date (the real
  `domain_age_days`), registrar and status flags. Fall back to WHOIS only where a TLD has no RDAP.
- `ingestion/dns_records.py` (`dnspython`, async): A/AAAA/MX/NS/TXT/CAA, SPF and DMARC presence, hosting ASN.
**Accept:** an old domain and a 2-day-old domain produce different ages; an expired certificate gives `ssl_cert_valid=0`.

### A1-4 Tech / EOL accuracy *(P1-4)*
- Use the endoflife.date API (cached locally, refreshed weekly) with a mapping table from Wappalyzer names to its slugs.
- Fix `EOL_SET` so `tech_has_eol_cms_version` can actually be 1.
- Use Wappalyzer's real confidence instead of a fixed 100, and fix the regex warnings.
- Either load `wappalyzer_tech.json` or delete it.
**Accept:** old WordPress / PHP 5.x / AngularJS 1.x fixtures are flagged as end-of-life.

### A1-5 Concurrency and live progress *(P1-5)*
Run independent providers with `asyncio.gather` plus a semaphore; chain the dependent ones. Stream per-provider progress
over `/scan/{id}/events` so the UI shows live status chips.

### A1-6 One input canonicaliser *(P1-6)*
`core/targets.py`: `canonicalize(raw) -> Target{kind, url, host, registered_domain, ip, hash}`, using `tldextract` with
an offline Public Suffix List and IDNA handling. Every component consumes `Target`, never the raw string.
**Accept:** a table test with about 30 input variants (scheme, `www.`, trailing dot, IDN, IPv6, case, ports).

### A1-7 Evidence-first UI *(P1-7, P4-4)*
Per-source status chips and per-feature provenance. Use wording like "No findings ≠ safe", show unknown and partial
states, and say how much evidence a score rests on ("based on 4 of 7 sources").

## A2 — ML pipeline and explainability

### A2-1 Retrain the maliciousness model on real data *(P2-1)*
- **Labels:** positives from PhreshPhish (Hugging Face), URLhaus, OpenPhish and PhishTank; negatives from Tranco,
  including deep benign paths such as `/login` and `/checkout`.
- **Features:** collect them when each URL is labelled, using a new `ml/collect.py` that reuses the real ingestion
  clients. It must be quota-aware, resumable, and cache raw JSON. Cover lexical, RDAP, DNS, TLS/CT, other reputation
  sources and page features. VirusTotal is optional, not the backbone.
- **Leakage controls:** a feed that supplies labels can't also be a feature. Split so the same host never appears in
  both train and test, and train on older data / test on newer data (B9).
- **Evaluation:** tune on validation, test once, calibrate (B7). Report PR-AUC, ROC-AUC, F1, FPR at a fixed recall,
  Brier score and ECE, each with bootstrap 95% CIs. Evaluate the baseline under the same protocol.
**Accept:** no metric equals 1.0; at least 8 features carry meaningful permutation importance; one command
(`python -m ml.evaluate --report`) regenerates the comparison table.

### A2-2 Model-health regression tests *(P2-2)*
These tests must fail on today's model file:
- output variance over a grid of feature values is above a threshold;
- at least N features are used in the trees;
- the model's feature-schema version matches the code;
- monotonic sanity checks hold (more blocklist hits never lowers the score). Optionally enforce with XGBoost `monotone_constraints`.

### A2-3 Neural URL model *(P2-3)*
- Canonicalise inputs exactly as in training: strip scheme and `www.`, lowercase the host only.
- Remove the dead tabular branch: it was trained on a constant vector, and the text-only metrics already match the fused ones.
- Evaluate on real benign login/checkout pages and on a later phishing set. Pick a threshold for a target FPR (≤ 1%).
- Build the allowlist from Tranco plus the Public Suffix List instead of the static `top_domains.txt`.
**Accept:** scheme-invariance test (scores within 0.02 with or without `https://` / `www.`); documented FPR on benign login pages.

### A2-4 Payload classifier *(P2-4)*
- Normalise text before inference (URL decoding, HTML entities, Unicode NFKC, whitespace).
- Replace the 256-character truncation with sliding windows plus max-pooling.
- Evaluate on public corpora that weren't used in training, with per-class recall. The cmdi class has only 18 test
  samples; collect more or merge it into a broader class.
- Apply temperature scaling so the confidence numbers mean something.
**Accept:** long padded inputs and comment-split inputs are classified the same as their plain forms; `| whoami` is not benign.

### A2-5 Explainability *(P2-5)*
- Build the SHAP explainer once at startup.
- Label values correctly as log-odds contributions, or convert them properly to probability changes.
- Add an additivity test (contributions + base value = model margin).
- Present the top factors as plain-English evidence cards.

### A2-6 Model cards *(P2-6)*
Add `ml/models/<name>.card.json` with data sources and hashes, date range, commit, feature schema, metrics with CIs, and
limitations. Load it at startup and show it in `/health`. A schema mismatch disables the model.

## A3 — Network layer

| ID | Task | Key points | Accept |
|---|---|---|---|
| A3-1 | Capture preflight *(P3-1)* | Detect Npcap, elevation and interfaces; explicit states (`no_npcap`, `not_elevated`, `no_interface`, `no_packets_seen`, `running`) | Each failure reason is visible in the UI |
| A3-2 | Sensor lifecycle *(P3-2)* | scapy `AsyncSniffer`, idempotent start/stop, packet timestamps, IPv6 | Start/stop ×10 leaves no leaked threads |
| A3-3 | DNS responses + TLS SNI *(P3-3)* | Parse answers/rcode/TTL and map domains to IPs; read SNI; filter mDNS/PTR | Replaying a PCAP fixture gives the expected fields |
| A3-4 | Reputation fan-out control *(P3-4)* | Shared VT client and bucket, TTL cache, dedup, private-name filter, local blocklists checked first | A 1,000-query burst causes a bounded number of VT calls |
| A3-5 | Rogue-AP precision *(P3-5)* | See B14; investigate WiGLE HTTP 412 with one approved call | No alert on my own multi-AP network; WiGLE returns 200 |
| A3-6 | Honest scope in docs/UI | A laptop sensor sees only its own DNS plus broadcast traffic; watching other devices needs gateway/mirror placement or Zeek/Suricata logs (B13) | Docs updated |

Also fix:
- `AppLayerScorer` flags a domain on a single engine hit; require at least 2 engines or a blocklist hit.
- `baseline.py` treats port 22 alone as high-risk.

## A4 — Chains, reports, UX, hygiene
- **A4-1 Chain model** *(P4-1)*:
  - Derive pre- and post-conditions deterministically from the CVSS vector plus CWE→CAPEC mappings.
  - Path probability is the **product** of the step probabilities, not a union.
  - Use live EPSS/KEV data (B11) and show a staleness banner when data is more than 7 days old.
  - Replace the hard-coded `parents[4]` CSV path with a configured data directory.
- **A4-2 Reports**: see B17.
- **A4-3 History**: pagination, a side-by-side evidence diff for two scans of the same target, and delete.
- **A4-4 SSE**: backfill missed events with `Last-Event-ID`; show the errors `NetworkSection` currently swallows.
- **A4-5 Docs**: remove unsupported metrics and fix the outdated "13 features" text.
- **A4-6 Repo hygiene [ASK]**:
  - Remove stray files: `!DOCTYPE html.txt`, `files.zip`, `files_extracted/`, `qa_results.txt`, raw JSON dumps,
    screenshots, `capture*.py`, `integration*.py`.
  - Once B11 is live, move the ~22 MB intel CSVs out of git into a download-and-cache script.

---

# PART B — Research-backed features

Format for each feature: what → why (source) → how → acceptance.
Tiers: **M** = must-have for the final-year submission, **S** = should-have, **X** = stretch.
Every new source follows A0-1 (three-state results), A0-5 (config), A1-1 (shared client, cache, rate limit) and A0-10 (privacy).

## B1 [M] Fast/slow two-tier pipeline
**Why:** PhishIntel (arXiv 2412.09057) made heavy, reference-based detection deployable by answering most URLs from
local blocklists and a cache, and queueing only unknown URLs for slow crawling and analysis.
**How:**
- `POST /scan` returns a fast verdict right away (local feeds, cache, lexical model, lookalike check) plus a `scan_id`.
- Provider calls, page fetch, screenshot and brand checks run in a background job queue and stream results over SSE.
  **[ASK]** in-process queue (default) or `arq` + Redis.
- The extension uses only the fast tier.
**Accept:** p95 under 300 ms for cached or listed targets; slow stages stream into the UI.

## B2 [M] Independent reputation channels
**Why:** VirusTotal's free quota is small, and the model collapsed onto it. Independent channels make fusion meaningful
and provide labels for A2-1.
| Source | Use | Note |
|---|---|---|
| abuse.ch URLhaus + ThreatFox | malware URLs and IOCs | free Auth-Key now required for all API requests |
| OpenPhish community feed | phishing URLs | local copy, refreshed every 12 h |
| PhishTank | phishing URLs | bulk download, kept locally |
| Google Safe Browsing Lookup API | malware / social engineering | non-commercial use; check the terms (commercial use = Web Risk) |
| AbuseIPDB | IP abuse confidence | for IP targets and resolved IPs |
| urlscan.io (search only) | prior verdicts and screenshots | never submit private URLs |
| AlienVault OTX | threat-intel pulses | free key |
| GreyNoise Community | mass-scanner vs targeted IP | cuts false positives |
| Tranco | popularity prior | local, refreshed daily |
**Accept:** each client has mock tests and respx tests for every status; local feeds show their age in the UI.

## B3 [M] Domain and certificate intelligence
**Why:** brand-new domains with fresh free certificates are among the strongest phishing signals. Certificate
Transparency research (Phish-Hook, TU Graz; Twente's CT early-warning work) flags phishing domains when their
certificate is issued, often before the first victim.
**How:** `ingestion/ct.py` uses crt.sh JSON (cached, tolerant of outages) to produce `cert_first_seen_days`,
`cert_count_30d`, `issuer_is_free_dv` and `san_brand_keyword_hits`. Combine with the RDAP and DNS features from A1-3.
All of these feed A2-1.
**Accept:** fixtures for a brand-new lookalike and an established domain.

## B4 [M] Brand impersonation (lookalike domains)
**Why:** lookalike domains are a dominant phishing tactic. PhishReplicant (ACSAC 2023) tracked 205k of them targeting
265 brands, and a language-model approach confirmed most of its flagged domains as phishing.
**How:**
- Build a protected-brand list: Tranco top-N plus a curated India list (major banks, UPI apps, IRCTC, India Post,
  UIDAI, Income Tax, EPFO, DigiLocker, large e-commerce and telecom brands).
- Score each scanned domain against the list with string similarity on the registered label.
- Normalise Unicode confusables using the Unicode TR39 skeleton.
- Detect brand names inside longer labels ("brand + keyword" patterns).
- Output a `lookalike_of` field with the matched brand and a similarity score. It feeds both the fast tier and the model.
**Accept:** labelled fixture set of lookalikes vs genuine brand domains, with precision and recall reported.

## B5 [S] Reference-based brand-intent check
**Why:** Phishpedia, PhishIntention, PhishLLM (USENIX Sec 2024: +21–66% recall over earlier tools), KnowPhish (USENIX Sec
2024: 20k-brand knowledge base) and PhishAgent (AAAI 2025) all detect phishing by asking: does the brand this page claims
match the domain it's hosted on, and is it asking for credentials?
**How (slow tier, sandboxed headless browser via A0-4):**
1. Infer the claimed brand from the title, favicon hash, logo alt text and visible text. Optionally use a local LLM
   (Ollama), with results checked against the brand list to limit hallucinations.
2. Detect a credential-collection intent (password fields, login forms).
3. Flag when the inferred brand's official domains don't include this domain.
**Accept:** evaluation on a sample from PhreshPhish plus benign login pages, reporting precision and recall.

## B6 [S] Page-content features
Classic, well-studied HTML signals, computed from the safe fetch:
- forms that submit to a different domain;
- password fields on non-HTTPS pages;
- ratio of external resources;
- favicon loaded from another domain;
- hidden iframes;
- title vs domain mismatch.

Also compute a favicon hash and a DOM fingerprint so you can cluster related phishing pages into campaigns.

## B7 [M] Calibrated multi-channel fusion
**Why:** a 2026 hybrid pipeline (arXiv 2606.21690) calibrates each channel first, then combines them with a
probabilistic OR, so one confident channel can raise the verdict without being averaged away.
**How:**
- Calibrate each channel (isotonic or Platt scaling).
- Fuse with a stacked logistic regression that uses the missingness flags, and compare it against noisy-OR and the baseline.
- Plot reliability diagrams and report Brier score and ECE.

## B8 [S] Abstaining when uncertain
**Why:** Transcend and "Transcending Transcend" (S&P 2022) show conformal evaluation can spot drifting or out-of-distribution
inputs and decline to classify them.
**How:** wrap the model with conformal prediction (e.g. the MAPIE library). Low-confidence inputs return
`verdict: "uncertain"` with the reason shown in the UI.

## B9 [M] Time-aware evaluation
**Why:** TESSERACT (USENIX Sec 2019; extended version 2024) shows random splits overstate accuracy, and PhreshPhish
(2025) highlights leakage and unrealistic base rates.
**How:** use time-ordered splits, report how performance decays over time (TESSERACT's AUT metric), and evaluate at
realistic phishing base rates. Also report robustness: arXiv 2603.19204 found most cheap evasions concentrate on a few
surface features, so favour infrastructure features (domain age, certificates, hosting) and report how much the model
depends on surface features.

## B10 [S] Hardening the payload classifier
Train and evaluate on established public web-attack datasets, plus the published adversarially-robust training approach
from ModSec-AdvLearn (arXiv 2308.04964). Measure robustness on held-out obfuscated samples from public corpora.

## B11 [M] Exploit-informed exposure score
**Why:** CVSS measures severity, not likelihood. EPSS predicts exploitation probability, CISA KEV confirms
in-the-wild exploitation, and CISA Vulnrichment publishes SSVC decision points (Exploitation, Automatable, Technical Impact).
**How:**
- Pull EPSS live from `api.first.org/data/v1/epss` (batched, cached daily) and KEV from CISA's JSON feed, including the
  ransomware-use field.
- Read Vulnrichment ADP data from the CVE JSON 5 records.
- Compute an SSVC-style category (Track / Track* / Attend / Act) per CVE, and an exposure score per host built from
  those, shown with its evidence.
**Accept:** fixtures for a KEV-listed CVE vs a high-CVSS CVE with low EPSS rank them correctly.

## B12 [X] Better attack paths
Build the deterministic chain model first (A4-1). As an optional enhancement, use retrieval-augmented LLM attack-graph
generation in the style of CrystalBall (arXiv 2408.05855), via local Ollama. Always show which steps were derived
deterministically and which the LLM suggested.

## B13 [S] Network-layer upgrades (defensive monitoring)
- **JA4+ fingerprints** (FoxIO, `ja4plus` library): identify client applications from TLS ClientHello metadata and
  match against known-bad fingerprint lists.
- **DGA scoring** for observed DNS names: a character model, reusing the URL CNN architecture, trained on public DGA
  lists vs Tranco.
- **Anomaly heuristics:** unusually long or high-entropy query names, high TXT query volume, periodic beaconing to the same host.
- **Zeek / Suricata log ingestion** (EVE JSON / Zeek logs) as an alternative sensor source. More reliable than raw
  sniffing and fits gateway deployments.

## B14 [M] Rogue / evil-twin AP precision
Treat BSSIDs with the same SSID and the same vendor OUI or adjacent MACs (mesh / multi-radio) as known. Raise severity
on a security-mode mismatch (e.g. open network vs your WPA2 SSID) and on unexpected channels. Let the user confirm known
APs. Report the false-positive rate on your own network.

## B15 [M] Extension upgrade
- A service worker checks pages on navigation (`webNavigation.onCommitted`) using only the fast tier and registered domains.
- Show a warning banner when there's a lookalike or blocklist hit.
- A content script flags password fields on suspicious domains.
- A "Report" button sends feedback to B20.
- Keep permissions minimal and documented.

## B16 [M] India-specific citizen features
This brings back the original f(ph)ishing goal.
- Reporting helpers that pre-fill a summary and link to cybercrime.gov.in, the 1930 helpline, Sanchar Saathi Chakshu
  (for SMS / call / WhatsApp fraud) and CERT-In incident reporting.
- The India brand list from B4.
- UPI-scam and KYC-scam phrase patterns for page text.
- Plain-English verdicts, with optional Hindi/Tamil copy **[ASK]**.

## B17 [S] Reports and intel export
Export scans as PDF/JSON reports with evidence, provenance and uncertainty, plus STIX 2.1 bundles and MISP event JSON
so the results can plug into SOC tooling.

## B18 [S] Plain-English explanations
Turn SHAP output into evidence cards plus a short "what would change this verdict" note. An optional LLM summary must
be grounded only in the scan's evidence and labelled as generated.

## B19 [S] Watchlists and change alerts
Re-scan watched domains on a schedule. Alert when a new certificate appears, DNS changes, or reputation flips. Optionally
use CertStream to watch for new certificates containing your protected brand names.

## B20 [S] Feedback loop
Users mark false positives and false negatives. Feedback is stored with provenance and reviewed before entering
training data (guarding against poisoning). Retraining reuses the A2-1 pipeline and model cards.

---

## Execution order and definition of done
1. A0 (all) → 2. A1 → 3. B2, B3, B4, B11 (they also supply real features and labels) → 4. A2 together with B7, B9 →
5. B1, B15, B16 → 6. A3 together with B13, B14 → 7. A4, B5, B6, B8, B10, B17–B20.

**Done means:**
- every audit finding is fixed or explicitly deferred with a reason;
- CI is green from a fresh clone;
- `python -m ml.evaluate --report` regenerates every number in the docs;
- the UI never shows a score without its evidence;
- the docs match the code.

## Sources
- PhishLLM — https://www.usenix.org/conference/usenixsecurity24/presentation/liu-ruofan
- KnowPhish — https://arxiv.org/abs/2403.02253
- PhishIntel — https://arxiv.org/abs/2412.09057
- PhishAgent — https://ojs.aaai.org/index.php/AAAI/article/view/35003
- PhreshPhish — https://arxiv.org/abs/2507.10854
- Calibrated multi-channel fusion — https://arxiv.org/abs/2606.21690
- Cost-aware robustness of phishing detectors — https://arxiv.org/abs/2603.19204
- TESSERACT — https://arxiv.org/abs/2402.01359
- Transcending Transcend — https://arxiv.org/abs/2010.03856
- PhishReplicant — https://arxiv.org/abs/2310.11763
- Phish-Hook (CT logs) — https://pure.tugraz.at/ws/portalfiles/portal/25394076/156259641564590.pdf
- CT early-warning (Twente) — https://essay.utwente.nl/essays/102379
- ModSec-AdvLearn — https://arxiv.org/abs/2308.04964
- CrystalBall (RAG attack graphs) — https://arxiv.org/abs/2408.05855
- EPSS API — https://www.first.org/epss/api
- CISA Vulnrichment — https://www.helpnetsecurity.com/2024/05/09/cisa-vulnrichment-cve-enrichment/
- JA4+ — https://github.com/FoxIO-LLC/ja4
- abuse.ch Auth-Key requirement — https://www.elastic.co/guide/en/integrations/current/ti_abusech.html
- RDAP bootstrap (RFC 9224) — https://datatracker.ietf.org/doc/rfc9224/
- endoflife.date — https://github.com/endoflife-date/endoflife.date/
- Sanchar Saathi Chakshu — https://sancharsaathi.gov.in/sfc/
