# Phase B-fast-tier — fast verdict (B1), browser extension (B15), India helpers (B16), feedback loop (B20)

Branch `b-fast-tier` (stacked on `a2-ml-validation` → `b-intel-exposure` → `a1-enrichment` → `a0-remediation`). Single commit.

## Why
A full scan waits on a dozen third-party providers (seconds, quota-limited, and it tells those providers what you are looking at). Most
decisions a person or a browser needs are answerable from data already on the machine. This phase adds that **first answer**, a browser
extension that uses it, helpers for the way phishing actually reaches people in India (messages, not just pages), and a safe way for users to
say "this verdict was wrong".

## What changed
| | Feature | Surface | Notes |
|---|---|---|---|
| B1 | Fast tier from **local data only**: OpenPhish / PhishTank feeds, brand look-alike (B4), URL-text models (A2), Tranco prior, a recent stored scan as cache | `POST /scan/fast` → `FastVerdict` | levels `block / warn / info / none`; `none` = **nothing found, not "safe"**; unreadable lists are reported as gaps; measured `latency_ms` |
| B1 | Async scans: the POST returns the fast verdict + `scan_id` at once, the slow tier runs as a bounded in-process job | `POST /scan {mode:"async"}`, `GET /scan/{id}` (`running / done / error`), SSE | **sync mode unchanged**; 4 concurrent, 50 waiting, then HTTP 429 |
| B15 | Extension: checks each navigation with the fast tier, badge `!` / `!!` (never "safe"), closed-Shadow-DOM banner, password fields outlined on flagged pages, *Report a mistake* | `extension/` | **host only** is sent (full URL is opt-in); permissions documented in `extension/README.md` |
| B16 | Scam-message patterns (fixed a-priori weights, plain-English why / what to do, URLs checked for look-alikes) and a report kit that **submits nothing** (1930, cybercrime.gov.in, Sanchar Saathi Chakshu, CERT-In) | `POST /india/analyze-text`, `/india/report-kit`, `GET /india/scan/{id}/report-kit`; UI section 04 and "Report this site" | not a verdict; English (+ common Hinglish spellings) |
| B20 | Feedback: reports with provenance, `pending` until a person accepts them, accepted-only export | `POST/GET /feedback`, `POST /feedback/{id}/review`, `ml/feedback_export.py`; schema v5 | unreviewed feedback is never training data |

All API changes are additive.

## Honesty properties (each has a test)
- The fast tier makes **no network call** (asserted with respx in "assert none called" mode) and refuses private / local names.
- A host on a list but a different page is a `warn`, not a `block`; an official brand domain is `info`; nothing found is `none` with the sentence
  "not a clean bill of health".
- p95 latency of the fast tier is under 300 ms for listed and cached targets (test measures it).
- Async errors are never silent: a validation failure in the background becomes an `error` status and an SSE `error` event; a flood of async
  scans is bounded.
- The extension's pure module is tested (what may be checked, what leaves the browser, when a banner shows, the badge wording, the cache, the report body);
  local and private hosts are never sent.
- Feedback: private names refused, note capped and stripped, identical report within an hour deduplicated, host-only unless the user opts in.

## Verification
- `pytest`: **1224 passed, 1 skipped**; frontend `npm test` 82 passed, `tsc --noEmit` (app + test projects) clean, `oxlint` 0 errors; extension `node --test` 9 passed.
- **Not tested in a real browser.** The service worker and content script are thin wrappers around the tested module; loading the unpacked extension
  and clicking through it is still to be done by a person.
- **No live third-party call was made.**

## Decisions taken (the master prompt's [ASK] items) — change them if you disagree
- **B1 queue:** an in-process `asyncio` queue instead of `arq` + Redis (single-user local tool, nothing extra to install). Cost: jobs do not survive a restart
  (`GET /scan/{id}` then answers 404 and the client re-submits). The `submit / state / shutdown` interface is small enough to put `arq` behind later.
- **B16 languages:** English only (plus common Hinglish spellings). Hindi / Tamil safety copy needs a native reviewer — a wrong safety sentence in
  someone's own language is worse than an English one.

## Not verified
- The report-kit channel details (helpline number, portal addresses, mailbox) come from public knowledge, **not a live check** — the text tells users to confirm on the official site.
- The extension has not been loaded in Chrome in this environment.

## Acceptance checklist
- [x] B1 fast verdict < 300 ms p95 for listed / cached targets; sync scans unchanged; async returns at once and finishes in the background
- [x] B15 badge never says "safe"; only the host is sent by default; permissions listed and justified
- [x] B16 each pattern has a "why" and "what to do"; nothing is submitted for the user
- [x] B20 feedback is reviewed before use; accepted-only export
- [x] Docs: ROADMAP, ARCHITECTURE, AI_CONTEXT §19, `extension/README.md`; CI runs the extension tests

🤖 Generated with [Claude Code](https://claude.com/claude-code)
