# Phase A1 — make enrichment and scoring work

Branch: `a1-enrichment` (stacked on `a0-remediation`; 7 feature commits + docs) · Closes the P1 items of `AUDIT_REPORT.md`.
Verification: `pytest` **682 passed, 1 skipped** (POSIX-only permission test) · frontend `npm test` **24 passed** · `tsc --noEmit` 0 errors (app **and** test projects) · `oxlint` 0 errors (2 pre-existing warnings) · `pip check` clean. `pip-audit` / `npm audit` run in CI (not re-run locally: they query external advisory services). **No live provider call was made at any point** — everything is respx / fixtures / local servers; the UI was checked against a real running server in *mock* mode on a scratch database.

## What this fixes

| Audit finding | Fix | Commit |
|---|---|---|
| Every component re-parsed the typed string its own way; IP / hash targets were never validated; IPs went to VT's *domain* endpoint | `core/targets.py`: one canonical `Target` (punycode host, eTLD+1 from an offline Public Suffix List, IP/hash validation, public URL form); `ScanResult.canonical`; invalid targets are a 400 `stage: "format"` before any provider call | A1-6 |
| A new VirusTotal client per scan/DNS event: its cache never hit, nothing enforced 4/min · 500/day, `Retry-After` ignored | `core/hub.py` (one client per provider for the process), `core/quota.py` (sliding windows with slot *reservation*, bounded queueing, `penalize()`), `core/cache.py` + schema v3 `provider_cache` (answers only), `/ip_addresses/{ip}` | A1-1 |
| NVD: sequential, no deadline (a slow NVD lost *every* result), 403/429/503 treated as final, memory-only cache, first CPE page only, CPEs never looked up | backoff + `Retry-After`, config-driven rate window (50 / 30 s), bounded fan-out under a deadline that keeps finished lookups (`partial:n/m`), persistent cache, CPE 2.2→2.3 conversion + pagination, versioned CPEs merged into one `nvd` outcome | A1-2 |
| `ssl_cert_valid` / `domain_age_days` were placeholders; no registration, certificate or DNS evidence at all | `ingestion/tls.py`, `rdap.py` (IANA bootstrap, WHOIS only where a TLD has no RDAP), `dns_records.py` (A/AAAA/MX/NS/TXT/CAA, SPF, DMARC, hosting ASN) — keyless, three-state, cached, mock + live | A1-3 |
| `EOL_SET` = six strings (WordPress not in it ⇒ the CMS flag could never be 1); confidence always 100; Wappalyzer state leaked versions between sites; regex-warning flood; 1.2 MB unused fingerprint dump | `ingestion/eol.py` (endoflife.date by release cycle), real Wappalyzer confidence, per-page state reset under a lock + worker thread, warning-free lazy fingerprint loading, dump measured and **deleted** | A1-4 |
| Providers awaited one after another; the UI showed nothing until the end | `asyncio.gather` over `[VT] [InternetDB→NVD] [tech→endoflife] [TLS] [RDAP] [DNS]`, process-wide gate, `GET /scan/{id}/events` (SSE; replay + live bus) | A1-5 |
| A score was shown without its evidence | evidence-first UI: live + final per-source chips, "Based on N of M sources", "No findings ≠ safe", per-feature provenance, host-evidence cards | A1-7 |

## ⚠ Behaviour changes operators will notice
1. **Live scans now open a few connections of their own** (all keyless, each switchable): TLS to `<host>:443`; the **registered domain** to the TLD registry's public RDAP (or WHOIS) service; DNS through the system resolver (or `DNS_NAMESERVERS`) plus Team Cymru's DNS ASN map for the first *public* address; a product slug (`php`) to endoflife.date. Private/local names and internal addresses are never sent anywhere. `TLS_ENABLED` / `RDAP_ENABLED` / `DNS_ENABLED` / `EOL_ENABLED` / `RDAP_WHOIS_FALLBACK` turn them off. **Mock mode touches no network at all** (it used to resolve the typed host through the real resolver).
2. **Scores can move**: `ssl_cert_valid` and `domain_age_days` are now real (the baseline rewards a valid certificate by −0.05 and penalises domains < 30 days old), the EOL features come from endoflife.date, and (live) CPE-derived CVEs from InternetDB's CPE list are merged in (highest CVSS first, max 25 per CPE). `NVD_LOOKUP_BY_CPE=false` keeps the old CVE-id-only behaviour. `FEATURE_SCHEMA_VERSION` is **3**.
3. **A real `NVD_API_KEY` is still required**; without one NVD is "not configured".
4. **Provider quotas are enforced**: VirusTotal at `VIRUSTOTAL_REQUESTS_PER_MINUTE=4` / `…_PER_DAY=500` (set both to `0` for a premium key). A scan that would have to wait longer than `VIRUSTOTAL_MAX_QUEUE_SECONDS` (15) reports VirusTotal as `rate_limited` (with `retry_after`) instead of hanging. The windows are in memory (reset on restart).
5. **API (additive only)**: `ScanRequest.scan_id` (optional; reuse ⇒ **409**), `ScanResult.canonical / tls / rdap / dns`, `FeatureCoverage.has_tls/has_rdap/has_dns`, `DetectedTechnology.eol / eol_date / eol_cycle / latest_version / implied` (and a real `confidence`), `TechFingerprintResult.eol_assessed`, `ProviderOutcome.retry_after`, `POST /scan/events-ticket`, `GET /scan/{id}/events`, `DELETE /network/data` also clears the lookup cache. Database migrates **v2 → v3** in place (new `provider_cache` table).
6. The scan **summary** now follows the headline *baseline* label (it used the experimental model's, contradicting the headline).
7. `backend/app/ingestion/wappalyzer_tech.json` is **deleted** (see below); the Wappalyzer data now comes from the engine's bundled file (`WAPPALYZER_DATA_FILE` can point at a newer one).

## Acceptance checklist (from the implementation prompt)
- [x] A1-1 in a 50-scan load test the limit is never exceeded and the cache hits (4 live lookups + 36 cache hits + 10 `rate_limited`; 50 concurrent lookups ⇒ exactly 4 HTTP calls); IP targets use `/ip_addresses`
- [x] A1-2 a 20-CVE fixture finishes within the deadline (and a slow NVD returns what finished); the Log4Shell fixture returns CVSS 10.0
- [x] A1-3 an old domain and a 2-day-old domain produce different ages; an expired certificate gives `ssl_cert_valid = 0` (real TLS handshakes against local servers with generated certificates)
- [x] A1-4 old WordPress / PHP 5.x / AngularJS 1.x fixtures are flagged end-of-life (real Wappalyzer detection of WordPress 4.9.8 + PHP 5.6.40 + AngularJS 1.5.8 → endoflife fixture → `tech_has_eol_cms_version = 1`)
- [x] A1-5 independent providers run together and dependent ones wait (asserted on the event log, deterministically); progress streams over `/scan/{id}/events`
- [x] A1-6 a table test of ~80 canonicalisation variants (scheme, `www.`, trailing dot, IDN, IPv6, case, ports, legacy numeric IPv4, junk); no network
- [x] A1-7 per-source chips, per-feature provenance, "No findings ≠ safe", "based on 4 of 7 sources"

## Deviations, caveats, things to review
- **`wappalyzer_tech.json` was deleted rather than loaded.** The prompt allowed either; I measured it: it cannot be loaded as-is (absent fields are `null`, which crashes the engine) and once repaired it detects *less* than the engine's bundled data (1,186 technologies / 1,732 usable patterns vs 1,137 / 1,884) and lacks the jQuery/AngularJS `scripts` version patterns that end-of-life checks need — "3,965 technologies" is mostly names with no pattern this engine can use.
- **endoflife.date was never called live.** The parser handles the legacy list *and* the v1 `result.releases` shape from my knowledge of the API; the slug table (`ingestion/eol.py`) is built from product names I believe exist — a wrong slug just 404s ⇒ *unknown* (harmless). One approved live call would let me verify the slugs and response shape.
- Likewise **RDAP, the IANA bootstrap, WHOIS, Team Cymru and VirusTotal/NVD responses are fixtures** shaped from the specs/docs, not recorded from live services.
- TLS probes **port 443 only** (a URL on another port is probed on 443); `has_tls = False` means "nothing on :443 speaks TLS".
- The CA/B policy OIDs decide DV/OV/EV; "free DV" is a *heuristic by issuer name* (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services, Cloudflare). It is shown as context, never as a verdict.
- The quota/event/gate state is **per process** (single-process app by design).
- The extension still sends only the hostname (unchanged); it does not use the new endpoints.
- A1-5's SSE is for the dashboard; the fast/slow job-queue redesign is B1.
- Test hygiene: the three host signals and endoflife are **off by default in tests** (they open sockets respx cannot intercept); the VT quota is off by default; conftest resets the hub, the provider cache and the per-client `/scan` limiter before every test.
- Found and fixed along the way (each with a test): the vulnerability chainer asked a local Ollama per CVE, sequentially, outside the scan deadline; the first-use CSV parse of the chainer ran on the event loop and the chainer was rebuilt on every scan; mock mode did real DNS lookups.
- `gh` is not installed here, so no PR was opened and nothing was pushed.
