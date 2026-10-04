# Phase B-intel — independent evidence: exposure (B11), brand look-alikes (B4), certificate history (B3), reputation channels (B2)

Branch `b-intel-exposure` (stacked on `a1-enrichment`, which is stacked on `a0-remediation`). Four commits, one per feature.

## Why
After A1 the scan had real host signals but still only **one** reputation opinion (VirusTotal) and no notion of *how
exposed* a host is or *who a domain is pretending to be*. This phase adds independent evidence and keeps two questions
apart — **"is this target malicious?"** and **"how exposed is this host to exploited vulnerabilities?"** — never blended
into one unexplained number.

## What changed
| | Feature | New `ScanResult` field | Notes |
|---|---|---|---|
| B11 | EPSS (live, batched, cached daily) + CISA KEV (local feed, age shown) + CISA Vulnrichment SSVC points → SSVC-style category per CVE, noisy-OR exposure per host | `exposure` | our own category mapping, labelled "not CISA's official decision tree"; unknown stays `None`; coverage "N of M CVEs" |
| B4 | Brand impersonation: TR39 confusables, ~110 curated brands (global + India list), kinds with evidence | `brand_check`, `lookalike_of` | local, deterministic, runs in mock mode; rule scores, **not probabilities**; official domains and `.gov.in`/`.nic.in` never flagged |
| B3 | crt.sh certificate-transparency history: `cert_first_seen_days`, `cert_count_30d`, `issuer_is_free_dv`, brand-like SAN names | `ct`, `feature_coverage.has_ct` | host name only; outage-tolerant; ages re-derived on read |
| B2 | URLhaus, ThreatFox, Google Safe Browsing, AbuseIPDB, urlscan (search only), AlienVault OTX, GreyNoise + local OpenPhish / PhishTank / Tranco | `reputation` | **not a score**; the verdict no longer hinges on VirusTotal; local feeds show their age |

All API changes are additive. `FEATURE_SCHEMA_VERSION` is unchanged and **none of the new signals feeds the deployed
19-column XGBoost vector or the baseline score** — that is A2-1 (retrain) and B7 (calibrated fusion), on purpose: folding
unvalidated signals into the headline would be the unexplained blending this phase avoids. They are reported next to it,
named in the summary sentence, and recorded for training.

## Honesty properties (each has a test)
- A feed never downloaded is **unknown** (`feed_unavailable`), never "not listed", and starts a background download.
- A failed / truncated / shrunken download keeps the previous copy; stale answers are flagged and carry the list's age.
- "Not listed" is `not_found` = absence of evidence; the UI never says "safe". A channel that errored or has no key is a **gap**
  ("N of M answered"), not a clean result.
- Verdict: any reputation source with a record ⇒ not *unknown*; none ⇒ *unknown*. For B2 channels "no record" is a normal answer.
- Privacy: private/local names and internal IPs are refused before any request; IP channels get a *public* resolved address only;
  the URL is trimmed to `scheme://host/path` unless the user opted in; API keys are sent in headers (URLs are logged); urlscan is
  search-only; nothing about a target is ever put in an SSE event.
- B4 does not flag user-content hosting domains as "official"; typo matching is off for brands of five letters or fewer.

## Verification
- `pytest`: **1074 passed, 1 skipped**; frontend `npm test`: 63 passed; `tsc --noEmit` (app + test projects) clean; `oxlint` 0 errors (2 pre-existing warnings).
- **No live third-party call was made** — every client is tested with respx / local fixtures for each status
  (ok / not_found / auth / rate-limited with `Retry-After` / server error / unparseable / not configured / skipped), the cache
  (answers cached, failures never), privacy, and a deterministic labelled mock.
- B4 evaluation (`tests/test_b4_evaluation.py`, fixture `tests/data/b4_lookalike_cases.csv`): 113 hand-written hosts —
  **precision 0.957, recall 0.880**. The fixture is **synthetic and written by the detector's author**: an optimistic upper
  bound, not a field estimate. The six designed misses (e.g. brand + digits, 5-letter-brand typo, same-name-other-TLD) and the
  two expected false positives (`ledgers.com`, `googles.com`) are pinned *by name*, so any change is a conscious decision.
  The fixture run also found and fixed two real gaps (one-letter deletion on a 6-letter brand; the risk-word list lacked
  "deals").

## Not verified (needs one approved live call each — nothing was fetched)
Response shapes for crt.sh, URLhaus, ThreatFox, Safe Browsing, AbuseIPDB, urlscan, OTX, GreyNoise, the PhishTank dump keys and
the Tranco zip layout come from the services' public documentation, not from a live response. Also still pending from A1: the
endoflife.date slugs/shape and WiGLE's HTTP 412 root cause.

## Needs a decision / action from you
- **Keys** (all free): `ABUSECH_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY` (non-commercial use; commercial = Web Risk),
  `ABUSEIPDB_API_KEY`, `OTX_API_KEY`; optional `URLSCAN_API_KEY`, `GREYNOISE_API_KEY`, `PHISHTANK_APP_KEY`. Without them those channels
  show "not configured" and the verdict reads *partial*.
- Confirm the Safe Browsing terms fit your use before enabling it outside a non-commercial setting.
- First live scan after install: the three local lists download in the background (tens of MB); until then they report
  "feed unavailable".

## Acceptance checklist
- [x] B11 fixtures: a KEV-listed CVE outranks a high-CVSS / low-EPSS CVE; unknown stays unknown
- [x] B4 labelled fixture with precision and recall reported
- [x] B3 fixtures: brand-new look-alike vs established domain
- [x] B2 each client has mock tests and respx tests for every status; local feeds show their age in the UI
- [x] ROADMAP / ARCHITECTURE / AI_CONTEXT / README / `.env.example` updated
