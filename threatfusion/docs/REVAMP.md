# ThreatFusion revamp — what was kept, what was cut, and why

Branch `revamp`. One commit per task (`revamp(Tn): …`). This file is the record: decisions first, then what was measured.

## 1. Keep / cut (T1a)

Rule: a feature stays only if, **in live mode on this machine**, it produces real output from a real source. Otherwise it is deleted — component,
route, API client, backend router, settings, tests and docs (no `display:none`, no feature flag left behind). Anything deleted is still in git
history; each cut below is its own commit and can be reverted alone.

| Feature | Verdict | Evidence / reason |
|---|---|---|
| Scan (domain / IP / URL / hash) with live source chips | **keep** | VirusTotal key is set here; InternetDB, TLS, RDAP, DNS, CT, endoflife.date, tech fingerprint are keyless; the URL models are local. |
| Scan result: verdict, two scores, evidence per provider, SHAP | **keep** | Rebuilt as *verdict row → evidence table → collapsed details* (T1c). |
| Inspector (HTTP payload classifier, HAR / traffic) | **keep** | Real local model, held-out evaluation in the model card. |
| Network (alerts, devices, access points) | **keep** | Made real in T2; the "no Npcap" state was checked in a browser on this machine. |
| History | **keep** | Real SQLite rows. |
| Settings: API token, capture interface, provider key *status* | **keep, trimmed** | The key input boxes had a **Save** button that saved nothing (keys live in `backend/.env`): deleted, status kept read-only. |
| `SiteMeteorsBackground`, `ui/meteors.tsx`, `ui/site-meteors-background.tsx` | **cut** | Decoration. |
| `CommandPalette` (⌘K) | **cut** | Duplicated the navigation. |
| `FloatingNav`, `DashboardLayout` | **cut** (T1c) | Replaced by one plain top bar. |
| Mock / Live toggle, “Mock” badges, health text about synthetic data | **cut** (T3a) | The service refuses to start on mock data; there is nothing to toggle. |
| `MessageCheck`, India report kit (`/india/*`, `app/india/`, `ReportKitPanel`, `lib/india`) | **cut** | The spec says cut unless verified in §5; §5 verifies nothing about it, and its channel details (1930, cybercrime.gov.in, Sanchar Saathi, CERT-In) were never checked live. The brand list (`ml/brands.py`), which includes Indian banks, stays: it feeds the look-alike check. |
| `POST /verify`, `VerifyPanel`, `app/verify/`, `core/audit.py`, `tools/vuln_lab.py` | **cut** | Off by default and scoped to the bundled local lab only; `VERIFY_ENABLED` is not set on this machine, so it produces no real output here. (Reverting `revamp(T1a): cut active verification` restores all of it.) |
| 802.11 deauth sensor | **cut** (T2b) | Needs monitor mode, which most Windows adapters cannot do. |
| WiGLE evidence on alerts | **keep for now** | Pending the one live call that shows whether the HTTP 412 is fixable (see §4). If it still fails it is cut. |
| Root junk inside `threatfusion/`: `frontend/patch*.cjs`, `rewrite*.cjs`, `screenshot.cjs`, `capture*.py`, `raw_response.json`, `screenshot_*.png`, `backend/result_wordpress.json`, `backend/qa_results.txt` | **cut** | One-off scratch files. |
| Files **outside** `threatfusion/` (`!DOCTYPE html.txt`, `files.zip`, `files_extracted/`, the large intel CSVs) | **not touched — needs your decision** | The Exploit-DB / EPSS / KEV CSVs are still read by the attack-chain code (`ml/chaining.py`); the rest looks like scratch but is yours to remove. |

