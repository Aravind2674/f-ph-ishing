# Phase A0 — correctness, security & data-integrity remediation

Branch: `a0-remediation` (13 commits on top of `main` @ `b28b76d`) · Closes the P0 items of `AUDIT_REPORT.md`.
Verification: `pytest` **385 passed, 1 skipped** (POSIX-only permission test) · `tsc --noEmit` 0 errors · `oxlint` 0 errors (1 pre-existing warning) · `pip check` clean · `pip-audit` clean (1 documented ignore) · `npm audit` 0 vulnerabilities · model manifest OK.

## What this fixes

| Audit finding | Fix | Commit |
|---|---|---|
| Two of three interpreters could not `import app.main`; `aiohttp` undeclared; unsafe `torch.load` | Exact lock files for Python 3.12 (`uv`), CI workflow, `aiohttp` → `httpx`, `weights_only=True`, SHA-256 model manifest checked at load | A0-7 |
| NVD placeholder key sent as a real key | Placeholders (`PASTE_YOUR_*` …) normalise to *unset*; unconfigured providers are never called; `/health` shows provider states | A0-5 |
| Every failure became zeros → "clean"; failed lookups cached for an hour; `if vt:` counted failures as success | `ProviderResult`/`ProviderStatus` (ok · not_found · error · skipped · not_configured) for VT, InternetDB, NVD, Wappalyzer, WiGLE; unknown features are `None` (XGBoost sees NaN), no fabricated `ssl=1.0`/`age=365`; `verdict_status` ok·partial·unknown; no VT answer ⇒ `ml_score=null`, label "Unknown" | A0-1 |
| XGBoost score constant (3 of 19 features); models loaded from CWD-relative paths; baseline aliased as ML | Absolute `MODEL_DIR`; baseline is the headline, XGBoost labelled *experimental*; `ml_status` | A0-2 |
| SSRF: validate-then-re-resolve (rebinding), redirects unchecked | `core/safe_http.py`: all A/AAAA checked, connection pinned to the validated IP, per-hop redirect validation, caps; wired into validation, tech fingerprint, Shodan DNS | A0-4 |
| `/verify` scope self-attested | Off by default; server-side `VERIFY_ALLOWED_HOSTS`; body field ignored; safe fetcher; TLS on; rate limit; append-only `verify_audit` | A0-3 |
| Scan history in RAM only; `summary` dropped; CWD-relative DB | SQLite persistence with `PRAGMA user_version` migrations, absolute DB path, provenance (mock flag, provider outcomes, model versions, feature-schema version) | A0-6 |
| No auth; body-less cross-site POST could start capture; rebinding | Bearer token (stored outside the repo), `Host` allow-list, JSON-only mutations, no credentialed CORS, single-use SSE tickets | A0-8 |
| No limits; blocking inference on the event loop; unbounded scans | `/scan` rate limit, body/batch caps (413), inference in worker threads, scan deadline + provider timeouts | A0-9 |
| Full URLs / internal DNS names sent to VirusTotal; browsing history kept forever; cookies forwarded | `core/privacy.py` (private names never leave; URL stripping + opt-in), header redaction, 30-day retention + `DELETE /network/data`, extension sends hostname only | A0-10 |

## ⚠ Behaviour changes operators will notice
1. **Every route except `/health` now needs a token.** Start the API, run `python -m app.core.auth`, paste the token in the dashboard **Settings** page and the extension popup (**API token**); mitmproxy addon: `TF_API_TOKEN`.
2. **`POST /verify` is OFF by default** (`VERIFY_ENABLED=false`); the lab needs `VERIFY_ENABLED=true`. `authorized_hosts` in the request is ignored.
3. **CVE enrichment needs a real `NVD_API_KEY`** (without one NVD is listed as "not configured", not silently empty).
4. **Scores can be `null` / "Unknown"** when no reputation source answered; the headline is the **baseline** score (it also shifts slightly: the fabricated SSL bonus is gone). The XGBoost score is labelled experimental.
5. **Python 3.12** and the lock files: create a fresh env (`uv venv --python 3.12 venv && uv pip sync requirements-dev.txt`).
6. **Database is migrated in place** on first start (v0→v2); existing rows are kept. The path is now absolute (relative `DATABASE_URL` resolves against `backend/`).
7. Extension: new `storage` permission; scans send only the **hostname** unless "send full URL" is ticked; non-web pages are refused.
8. `RATE_LIMIT_REQUESTS_PER_MINUTE` is now live (per-client `/scan` cap, default 30); network data older than 30 days is purged.

## Acceptance checklist (from the implementation prompt)
- [x] A0-1 respx tests for 401/403/404/429/5xx/timeout per provider; full-outage scan returns `unknown` with every provider failed; UI shows "unavailable"
- [x] A0-2 no UI text claims a "learned multi-source score"; any working directory gives identical results (subprocess test)
- [x] A0-3 body-supplied host refused; host not in config refused; every call writes an audit row
- [x] A0-4 redirects to internal/metadata blocked; a resolver that changes its answer has no effect (real local servers + respx)
- [x] A0-5 with no NVD key NVD is never called and the UI shows "not configured"
- [x] A0-6 history identical after a restart; summary renders
- [x] A0-7 fresh clone passes the CI commands (all run locally; the workflow itself has not run on GitHub yet)
- [x] A0-8 cross-site form POST and a foreign `Host` are rejected (also verified over real HTTP against a scratch DB)
- [x] A0-9 oversized HAR → 413; event loop stays responsive during a blocking model call (lag test)
- [x] A0-10 tests prove private names never reach a provider client; purge test passes

## Deviations, caveats, things to review
- **Extension sends the hostname, not the registered domain** (a Public Suffix List is needed; it arrives with the canonicaliser in A1-6). The backend never sends more than `scheme://host/path` to third parties.
- `ALLOWED_HOSTS` ignores the port (the prompt named `:8000`) so the app works on any local port.
- Reordered A0-4 before A0-3 (A0-3 routes through the fetcher) and A0-5 before A0-1 (needs `not_configured`).
- No live provider call was made at any point. WiGLE's HTTP 412 root cause is still unknown (needs one approved call, A3-5).
- The test suite uses a throwaway DB; an early A0-3 test run wrote a `verify_audit` table (2 rows) into the developer's real `threatfusion.db`. It was removed again (backup of the pre-cleanup file kept in the session scratchpad) and a conftest guard now prevents recurrence.
- `AUDIT_REPORT.md`, `THREATFUSION_MASTER_PROMPT.md` (repo root) and the author's local edit to `frontend/src/api.ts` are **not** part of these commits.
- `gh` is not installed here, so no PR was opened and nothing was pushed.
