# ThreatFusion revamp — what was kept, what was cut, what was measured

Branch `revamp`. One commit per task (`revamp(Tn): …`). This file is the record: what was cut and why, what was measured, which
decisions cost something, and what has **not** been verified.

## 1. Keep / cut (T1a)

Rule: a feature stays only if, **in live mode on this machine**, it produces real output from a real source. Otherwise it is deleted —
component, route, API client, backend router, settings, tests and docs (no `display:none`, no feature flag left behind). Anything deleted
is still in git history; each cut is its own commit and can be reverted alone.

| Feature | Verdict | Evidence / reason |
|---|---|---|
| Scan (domain / IP / URL / hash) with live source rows | **keep** | VirusTotal key is set here; InternetDB, TLS, RDAP, DNS, CT, endoflife.date, tech fingerprint are keyless; the URL models are local. |
| Scan result: verdict, two scores, evidence per provider, SHAP | **keep, rebuilt** | *verdict row → evidence table (source · status · value · latency) → collapsed Details* (T1c). |
| Inspector (HTTP payload classifier, HAR / traffic) | **keep** | Real local model, held-out evaluation in its model card. Now a collapsed section under the scan view. |
| Network (alerts, devices, access points) | **keep** | Made real in T2; the "no Npcap" state was checked in a browser on this machine. |
| History | **keep** | Real SQLite rows. |
| Settings: API token, capture interface, provider key *status* | **keep, trimmed** | The key input boxes had a **Save** button that saved nothing (keys live in `backend/.env`): deleted, status kept read-only. The privacy card moved to the Network view's *Erase stored data*. |
| `SiteMeteorsBackground`, `ui/meteors.tsx`, `ui/site-meteors-background.tsx` | **cut** | Decoration. |
| `CommandPalette` (⌘K), `FloatingNav`, `ui/floating-navbar.tsx`, `DashboardLayout` | **cut** | Replaced by one plain top bar. |
| `EvidencePanel`, `ReputationPanel`, `HostSignals`, `LiveSources`, the old `ScanResult` | **cut** | Replaced by the evidence table; their facts are rows you open. Nothing they showed was dropped except prose. |
| Mock / Live toggle, “Mock” badges, health text about synthetic data | **cut** (T3a) | The service refuses to start on mock data; there is nothing to toggle. |
| `MessageCheck`, India report kit (`/india/*`, `app/india/`, `ReportKitPanel`, `lib/india`) | **cut** | The spec says cut unless verified in §5; §5 verifies nothing about it, and its channel details (1930, cybercrime.gov.in, Sanchar Saathi, CERT-In) were never checked live. The brand list (`ml/brands.py`), which includes Indian banks, stays: it feeds the look-alike check. |
| `POST /verify`, `VerifyPanel`, `app/verify/`, `core/audit.py`, `tools/vuln_lab.py`, `VERIFY_*` settings | **cut** | Off by default and scoped to the bundled local lab only; `VERIFY_ENABLED` is not set on this machine, so it produces no real output here. (Reverting `revamp(T1a): cut active verification` restores all of it.) |
| 802.11 deauth sensor | **cut** (T2b) | Needs monitor mode, which most Windows adapters cannot do. |
| WiGLE evidence on alerts | **keep for now** | Pending the one live call that shows whether the HTTP 412 is fixable (see §5). If it still fails it is cut. |
| Scratch files inside `threatfusion/` (`frontend/patch*.cjs`, `rewrite*.cjs`, `screenshot.cjs`, `capture*.py`, `raw_response.json`, `screenshot_*.png`, `backend/result_wordpress.json`, `backend/qa_results.txt`) | **cut** | Not referenced by any tracked file (`revamp(T1a): delete one-off scratch files`). |
| Files **outside** `threatfusion/` (`!DOCTYPE html.txt`, `files.zip`, `files_extracted/`, the large intel CSVs) | **not touched — your decision** | The Exploit-DB / EPSS / KEV CSVs are still read by the attack-chain code (`ml/chaining.py`); the rest looks like scratch but is yours to remove. |

## 2. What each task changed

* **T3 — real values only.** Mock data is refused outside the test suite. A score that was not computed is `None` and shows as “—”,
  never 0. The two scores are named for what they are — **URL model** (calibrated probability from the URL text) and **Provider
  evidence** (a weighted sum of named terms) — and the headline is the higher-risk band of the two, with `driven_by` saying which one.
  Neither score is ever adjusted after it is computed; a `Disagree` tag appears when they are more than 15 points apart.
* **T2 — network layer.** A preflight (`GET /network/preflight`) names the first thing that blocks capture (no scapy, no Npcap, not
  elevated, no interface, no traffic) and its fix; one shared sniffer feeds the DNS, TLS and ARP sensors; correlation raises an alert
  only with corroboration (a blocklist hit or at least two VirusTotal engines) and a reputation gate protects the VirusTotal quota; Wi-Fi
  scanning uses the Windows Native Wifi API and is language-independent; the Network view shows status, the fix, resumable alerts and
  access points.
* **T1 — minimal UI.** Three views (Scan · Network · History) plus a Settings icon; evidence is a table, not a grid of cards; copy cut to
  what helps a decision; tokens `--bg --surface --line --fg --muted --accent --accent-2 --danger --warn --ok`; severity is colour **and**
  text; `prefers-reduced-motion` is respected. The extension popup shows the host, the verdict, the top three reasons and *Open in
  ThreatFusion*, which pre-fills the dashboard's scan form and never starts a scan.

## 3. Measured

**Random-looking DNS names** (`python -m ml.name_heuristic_eval`, 360,330 unique hosts of web pages a crawler visited, PhreshPhish
processed data; benign 148,603, phishing 211,727). A name is flagged when its first label is at least *min length* long and has at
least *min bits/char* of entropy:

| min length | min bits/char | benign flagged | phishing flagged |
|---|---|---|---|
| 12 | 3.4 | 10.97 % | 30.84 % |
| 12 | 3.5 | 7.04 % | 23.89 % |
| 12 | 3.6 | 3.17 % | 16.54 % |
| 14 | 3.5 | 6.60 % | 23.06 % |
| 14 | 3.7 | 1.20 % | 11.45 % |
| **16** | **3.8** | **0.41 %** | **7.93 %** |

The first draft used 12 / 3.6, which flags 3.17 % of benign hosts. The shipped defaults are the last row (`NAME_LABEL_MIN_LENGTH=16`,
`NAME_LABEL_MIN_ENTROPY=3.8`). A label of at least 40 characters, or a name of at least 100, is flagged on its own (benign 0.02 %,
phishing 2.01 %). These are the hosts of crawled pages, not what a device queries over a day, and the live pipeline skips popular names
(Tranco) before this heuristic runs, so the live false-positive rate is lower by an amount this script cannot measure.

**Cost of the "higher band wins" headline.** Taking the higher of two channels can only raise the headline, so it flags more benign
targets than either channel alone: the URL-model channel flags about 1 % of benign hosts at its operating point, and 1.8 % of real login
pages. That is the price of not letting a quiet provider channel hide a phishing-looking URL; the two scores stay visible so the reader can
see which channel fired.

**Wi-Fi scan on this machine:** the Native Wifi API returned 31–57 access points per scan.

**Tests at the end of this branch** — backend `pytest -q`: 1340 passed, 1 skipped (the Verify cut removed its two test files); frontend `npm test`: 123 passed;
extension `node --test`: 13 passed; `npm run build`, `tsc` (app and test configs) clean; `oxlint`: 0 errors, 2 warnings that were already
there (`ui/button.tsx`, `ui/badge.tsx`: fast-refresh only).

## 4. Decisions, and what they cost

* **Mobile layout is not handled.** The master prompt asks for ≥ 360 px; you said mobile optimisation is not needed at all, so the
  dashboard targets desktop widths only.
* **The popup keeps two controls the spec's "nothing else" would remove:** the API token field (the backend rejects every request without
  it; the field opens by itself until a token is saved) and the *Send full URL* checkbox (the URL models read the path, so host-only
  scans see less; host-only stays the default).
* **Wi-Fi / access-point scanning starts only when capture's prerequisites pass.** Without Npcap the Network view says so and shows no
  access points, even though the Native Wifi API itself works here. *Open question:* should the Wi-Fi scanner run on its own?
* **`mock_mode` is still a field in `/health` and in stored scans.** It is always false outside the test suite and the dashboard ignores
  it; removing it means a schema and database column change, left for you to decide.
* **The page loads Inter and JetBrains Mono from Google Fonts**, so opening the dashboard contacts Google. Self-hosting the two fonts
  needs a download that has not been approved.

## 5. Not verified (needs you, a key, a download or another machine)

* The §5 manual checklist — it needs Windows with Npcap installed and the backend run as Administrator. Not run here.
* Live responses of the reputation channels (crt.sh, URLhaus, ThreatFox, Safe Browsing, AbuseIPDB, urlscan, OTX, GreyNoise, PhishTank,
  the Tranco list, endoflife.date): the tests use mocked responses only, and most of those channels need keys that are not set here.
  The spec asks for **one** live call per channel; none was made without your approval.
* The WiGLE HTTP 412 — needs one approved live call to see whether it is fixable.
* The JA4 fingerprint against FoxIO's sample captures (needs a download), and the real file format of abuse.ch's SSLBL JA3 list.
* ARP spoof detection against a real spoofer (needs a lab setup).
* The extension loaded in a real browser (the logic is unit-tested; the popup, service worker and banner were not loaded).
