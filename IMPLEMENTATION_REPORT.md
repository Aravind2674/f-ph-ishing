# ThreatFusion — implementation report (state at 2026-10-05)

Covers the remediation + research programme defined in `AUDIT_REPORT.md` and `THREATFUSION_MASTER_PROMPT.md`
(Part A: A0–A4 remediation, Part B: B1–B20 research features). Everything below is **committed on local branches
that you have not pushed yet** (only `a0-remediation` exists on `origin`); there is no `gh` here, so pushing and opening
PRs is yours.

## 1. Where everything is — branch stack

Each phase is one branch stacked on the previous one, with its own PR description at the repo root.

| # | Branch | Phase | PR text | Backend tests at that commit |
|---|---|---|---|---|
| 1 | `a0-remediation` (pushed) | A0 correctness, security, data integrity | `PR_A0_REMEDIATION.md` | 385 |
| 2 | `a1-enrichment` | A1 enrichment that works | `PR_A1_ENRICHMENT.md` | 682 |
| 3 | `b-intel-exposure` | B11 exposure · B4 look-alikes · B3 cert history · B2 reputation channels | `PR_B_INTEL.md` | 1,074 |
| 4 | `a2-ml-validation` | A2 real-data ML + B7 calibrated fusion + B9 time-aware eval + part of B10 | `PR_A2_ML.md` | 1,153 |
| 5 | `b-fast-tier` | B1 fast tier · B15 extension · B16 India helpers · B20 feedback | `PR_B_FAST_TIER.md` | 1,224 |
| 6 | **`a3-network`** (**partial** — do not open its PR until the rest of A3 is done) | A3 network layer — foundations only | this file, §4–§5 | see §6 |

Merge order is the table order. (Rows 3–6 were rebased once, on 2026-10-05, to move a date-dependent test fix — `test_b3_ct.py` — down to `b-intel-exposure`
where the bug was introduced; nothing from rows 1–2 changed.) `a3-network` contains all of the earlier work, so it is the branch to look at if you only
want to inspect one.

## 2. What is implemented, by phase

### A0 — correctness, security, data integrity (pushed)
Exact lock files for Python 3.12 + CI, SHA-256 model manifest, `weights_only=True`; placeholder keys treated as *unset*; a
three-state `ProviderResult` (ok / not_found / error / skipped / not_configured) so a failed lookup is **unknown**, never
"clean"; baseline score is the headline, the XGBoost one was labelled experimental; one SSRF-safe fetcher (DNS pinning,
per-hop redirect checks); `/verify` scope moved server-side, off by default, audited; scans persisted in SQLite with
versioned migrations; local API token + Host allow-list + JSON-only mutations + single-use SSE tickets; rate limits, body caps,
inference off the event loop, scan deadlines; privacy defaults (private names never leave the machine, URL stripping,
retention + erase).

### A1 — enrichment and scoring that actually work
One canonical `Target` (punycode, eTLD+1 from an offline PSL, IP/hash validation); one shared VirusTotal client with a real
quota limiter (4/min, 500/day) and a persistent TTL cache; NVD with backoff, deadline, partial results and a CVE cache;
real host signals (TLS certificate, RDAP/WHOIS registration age, DNS + SPF/DMARC/CAA + hosting ASN); real technology
end-of-life data (endoflife.date) and honest Wappalyzer confidence; providers run concurrently with live progress over SSE;
evidence-first UI ("based on 4 of 7 sources", "No findings ≠ safe", per-feature provenance).

### B-intel — independent evidence (kept separate from the maliciousness score)
* **B11 exposure**: EPSS + CISA KEV + CISA Vulnrichment SSVC → per-CVE Track / Track* / Attend / Act and a per-host exposure
  score; never blended into the maliciousness score.
* **B4 brand impersonation**: Unicode TR39 confusables, ~110 curated brands (global + India), look-alike kinds with evidence.
* **B3 certificate transparency (crt.sh)**: first-seen age, recent issuance, free-DV issuer, brand-like SAN names.
* **B2 reputation channels**: URLhaus, ThreatFox, Google Safe Browsing, AbuseIPDB, urlscan (search only), AlienVault OTX,
  GreyNoise, plus local OpenPhish / PhishTank / Tranco feeds that show their own age. Reported as evidence, not a score.

### A2 (+ B7, B9, part of B10) — a measured ML pipeline
The audited models (synthetic data with 15 % label noise; XGBoost effectively on 3 features; a neural model whose tabular
branch was trained on a constant vector; 0.13 → 0.99 jump from a prepended `https://`; a static allow-list that capped
popular domains at 0.15) were **deleted** and replaced by:
* data: PhreshPhish (CC-BY-4.0), 654,382 URLs, 2024-07 → 2025-12, metadata columns only (no phishing page is visited);
* models: 39-feature XGBoost (monotone brand constraints), a character CNN, an a-priori lexical baseline, each calibrated,
  plus a stacked-logistic fusion with missingness flags (noisy-OR and mean compared);
* protocol: time-ordered, host-disjoint splits; tune on validation, test once; cluster-bootstrap 95 % CIs; one command
  `python -m ml.evaluate --report` regenerates every table (`ml/results/report.md`);
* explanations: exact TreeSHAP in log-odds + probability what-ifs; model cards (hashed in the manifest) shown in `/health`;
  a schema mismatch disables the model;
* payload classifier: iterated decoding + NFKC + comment stripping, sliding windows (no 256-character truncation),
  temperature scaling, adversarial augmentation, held-out evaluation.

### B1 / B15 / B16 / B20
* **B1** `POST /scan/fast` answers from **local data only** (blocklist feeds, look-alike check, URL models, Tranco prior,
  cached recent scan) with measured latency; `POST /scan {mode:"async"}` returns that verdict + `scan_id` immediately and
  runs the slow tier as a bounded in-process job (`GET /scan/{id}`: running / done / error). Sync mode is unchanged.
* **B15** Chrome MV3 extension: host-only checks on navigation, badge `!` / `!!` (never "safe"), closed-Shadow-DOM warning
  banner, password-field outline on flagged pages, *Report a mistake*; decision logic is a pure module tested with `node --test`.
* **B16** India: rule-based scam-message patterns (fixed a-priori weights, plain-English why/what-to-do, not a verdict) and a
  report kit (1930, cybercrime.gov.in, Sanchar Saathi Chakshu, CERT-In) that **submits nothing**.
* **B20** Feedback reports with provenance, `pending` until a person accepts them; accepted-only export (DB schema v5).

### A3 — network layer: foundations committed in this branch (partial)
Done and tested (details in §4): capture **preflight** with explicit states; a **sensor lifecycle** rewrite on scapy's
`AsyncSniffer` (idempotent start/stop, no leaked threads, packet-time timestamps, IPv4 + IPv6); **DNS response parsing**
(rcode, A/AAAA/CNAME answers + TTL) with mDNS / PTR / `.local` / single-label filtering; a **TLS ClientHello parser** with SNI,
**JA3 and JA4** computation and bounded multi-segment reassembly; a new **TLS SNI sensor**; the **two-engine corroboration
rule** in `AppLayerScorer`. **Not yet wired in or finished:** see §5.

## 3. Verification status
| Check | Result |
|---|---|
| Backend `pytest` per phase (clean checkouts for A2 and B-fast-tier) | 385 → 682 → 1,074 → 1,153 → 1,224 passed, 1 skipped (POSIX-only test) |
| Frontend `npm test` | 24 → 63 → 70 → 82 passed; `tsc --noEmit` (app + test projects) clean; `oxlint` 0 errors |
| Extension `node --test "extension/tests/*.test.mjs"` | 9 passed (new CI job added) |
| Live third-party calls made during development | **none** (respx / fixtures / local servers only), except downloading the public datasets and payload lists |

## 4. What the A3 commit contains
New / changed files (all under `threatfusion/backend/`):
* `app/network/preflight.py` — states `no_scapy · no_npcap · not_elevated · no_interface · ready · running · no_packets_seen · error`;
  each carries a reason and a fix; the elevation check *tries to open the handle* (Npcap can be installed for non-admins);
  `effective_state()` upgrades to `running` / `no_packets_seen` once capture is live. (16 tests)
* `app/network/sensor/base.py`, `capture.py` — `CaptureSensor` on `AsyncSniffer`: waits until the handle is open or reports the
  verbatim failure; `stop()` wakes a quiet capture; a failing handler is counted, never fatal; PCAP replay (`offline=`) runs the
  same handlers. (30 tests incl. 10× start/stop with no thread left over, on both a fake and the real `AsyncSniffer`)
* `app/network/sensor/packets.py`, `dns_sensor.py`, `arp_sensor.py`, `dot11_sensor.py`, `tls_sensor.py` — DNS queries **and**
  responses (device = packet destination for a response), IPv6, filtering counted by reason, bounded tables, packet timestamps.
* `app/network/tls_hello.py` — ClientHello → SNI, JA3 (MD5) and JA4 (FoxIO layout), GREASE removal, `NeedMoreData` /
  `NotClientHello` for truncated / hostile bytes, `HelloAssembler` (bounded). (22 tests)
* `app/network/models.py` — additive: `DNS_RESPONSE`, `TLS_CLIENT_HELLO`, `AP_OBSERVED` events; `TLS_FINGERPRINT`, `DGA_SUSPECT`,
  `BEACONING`, `DNS_ANOMALY` alert types; `MonitorStatus.capture / scope_note / dropped_events`; `AppLayerSubScore.source /
  corroborated / blocklists / popularity_rank`.
* `app/network/enrichment/app_layer.py` — a cross-layer flag now needs **≥ 2 VirusTotal engines** (malicious + suspicious);
  one engine, or the URL-text model alone, no longer flags a domain (audit item).

## 5. What is NOT done (remaining work)

### 5.1 Rest of A3 (+ B13, B14) — in order of the plan
| Item | What is missing |
|---|---|
| A3-1 wiring | `NetworkMonitorService.start()` does not call `run_preflight()` yet; `/network/status` doesn't return `capture`; the UI (`NetworkSection`) does not show the states/reasons/fix; `TlsSensor` is not registered in the service |
| A3-2 | `WifiScanner` (polling `netsh`) still uses the base-thread lifecycle (now idempotent, but not covered by a start/stop ×10 test); bounded event queue + `dropped_events` counter not implemented in the service |
| A3-3 | `CorrelationEngine` ignores `DNS_RESPONSE` / `TLS_CLIENT_HELLO` (needs a domain→IP resolution map with TTL, SNI → reputation path, NXDOMAIN counters) |
| A3-4 reputation fan-out | the shared gate is **not written**: TTL cache keyed by registered domain, in-flight de-duplication, private-name filter first, local blocklists / Tranco before VirusTotal, a dedicated network VT budget so monitoring can't starve user scans; **test: a 1,000-query burst causes a bounded number of VT calls** |
| A3-5 / B14 rogue-AP precision | group same-SSID + same-OUI / adjacent-MAC BSSIDs as one network; security-mode mismatch and unexpected-channel severity; user-confirmed known APs; WiGLE BSSID normalisation; **WiGLE HTTP 412 needs one approved live call to investigate** (likely BSSID formatting); report the false-positive rate on your own network |
| A3-6 | docs/UI statement of scope ("a laptop sensor sees its own DNS plus broadcast traffic; other devices need gateway/mirror placement or Zeek/Suricata logs") — the `scope_note` field exists but docs/UI don't use it yet |
| `baseline.py` | port 22 alone must not count as high-risk (audit item, not yet changed) |
| B13 | known-bad JA3 list (abuse.ch SSLBL feed — **no invented fingerprints**) and alert path; DGA scoring (unsupervised n-gram/entropy unless a licensed public DGA list is approved); long/high-entropy name, TXT-volume and beaconing heuristics; Zeek / Suricata EVE ingestion as an alternative sensor; JA4 has not been cross-checked against the reference implementation |
| docs | ROADMAP / ARCHITECTURE / AI_CONTEXT updates for A3 and `PR_A3_NETWORK.md` with an acceptance checklist |

### 5.2 A4 — chains, reports, UX, hygiene
A4-1 deterministic chain model (pre/post-conditions from CVSS vector + CWE→CAPEC, path probability as a product, live EPSS/KEV
with a >7-day staleness banner, configured data dir instead of `parents[4]`); A4-2 reports (= B17); A4-3 history pagination,
side-by-side evidence diff, delete; A4-4 SSE `Last-Event-ID` backfill and visible network errors; A4-5 docs (remove
unsupported metrics, fix "13 features" text); **A4-6 repo hygiene is an [ASK]** — nothing will be deleted until you decide
(`!DOCTYPE html.txt`, `files.zip`, `files_extracted/`, raw JSON dumps, screenshots, `capture*.py`, the ~22 MB intel CSVs).

### 5.3 Part B items not started
B5 reference-based brand-intent check · B6 page-content features (+ favicon hash / DOM fingerprint) · B8 conformal
abstention (`verdict: "uncertain"`) · B10 remainder (broader payload corpora; the part done is in A2) · B12 attack-graph via local
Ollama (stretch) · B17 PDF/JSON reports + STIX 2.1 + MISP export · B18 plain-English evidence cards / "what would change this
verdict" · B19 watchlists, scheduled re-scans, change alerts (+ optional CertStream) · B20 richer review UI (only the minimal
API + export is done).

### 5.4 Known weak spots to keep in mind (all documented in the PRs / model cards)
* URL-text models are **modest**: CNN recall 0.65 and fusion 0.70 at a 1 % false-positive rate; recall decays across months;
  at 0.1 % prevalence even the best channel's precision is ≈ 9 %.
* **Cheap evasions work** (a benign path prefix cuts CNN recall from 0.65 to 0.07); appending a query string *raises* recall
  (a dataset artefact). Fusion's false-positive rate on real benign login pages is 1.8 % (above the 1 % target).
* B4 look-alike recall on real phishing is only 3.5 % (most phishing sits on free hosting).
* Payload classifier held-out recall: sqli 0.99, path-traversal 0.98, cmdi 0.85 (optimistic — see the disclosed training-split
  choice), **xss 0.64**.
* The Chrome extension has not been loaded in a real browser; the India report-kit contact details were not verified live.
* No Npcap on the development PC → real packet capture could not be exercised here; parsing and lifecycle are verified by
  PCAP-fixture replay with synthetic packets only.

### 5.5 Needs you
1. **Push** `a1-enrichment`, `b-intel-exposure`, `a2-ml-validation`, `b-fast-tier`, `a3-network` and open PRs in that order.
2. **Approve live verification calls** (one each): crt.sh, URLhaus, ThreatFox, Safe Browsing, AbuseIPDB, urlscan, OTX, GreyNoise,
   PhishTank dump keys, Tranco zip layout, endoflife.date slugs, **WiGLE 412**.
3. Keys (free): `ABUSECH_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY` (non-commercial; commercial = Web Risk), `ABUSEIPDB_API_KEY`,
   `OTX_API_KEY`; optional `URLSCAN_API_KEY`, `GREYNOISE_API_KEY`, `PHISHTANK_APP_KEY`; a real `NVD_API_KEY`.
4. Decide **A4-6 repo hygiene**; confirm the two defaults taken (B1 in-process queue, B16 English only).
5. Install **Npcap** and run the backend elevated if you want to see real capture (preflight will tell you if something is missing).

## 6. Test status of the A3 commit
See the final line of this file, filled in after the last run.
