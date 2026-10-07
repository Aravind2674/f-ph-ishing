# ThreatFusion — Master Prompt: Minimal Revamp · Working Network Layer · Real-Data Scan

> Paste this whole file into Claude Code / Copilot at the repo root (`f-ph-ishing/`).
> Read `AI_CONTEXT.md` §15–§20 and `IMPLEMENTATION_REPORT.md` §5 first; they are the ground truth for what exists.

---

## 0. Role, rules, definition of done

You are a senior full-stack + network-security engineer finishing **ThreatFusion** (FastAPI · React 19/Vite/Tailwind 3 · scapy · XGBoost/char-CNN). Work on a new branch `revamp` off `main`. One commit per numbered task, message `revamp(Tn): …`.

Hard rules:
1. **No fabricated values anywhere.** Every number on screen comes from a provider response, a local feed, a captured packet, or a model inference on this request. If a value is unknown, show `—` with the reason. Never substitute a constant, a random number, a mock, or an adjusted score.
2. **Never alter a score after it is computed.** No clamping one score above another, no "boost" when channels disagree. Disagreement is shown, not hidden.
3. **Delete, don't hide.** A removed feature loses its component, route, API client function, backend router, settings, tests and docs. No `display:none`, no feature flags left behind.
4. Keep existing security invariants: Bearer auth, single-use SSE tickets, `SafeFetcher` for user targets, `privacy.py` filters, three-state `ProviderResult`, train=serve feature code.
5. Windows 11 is the primary runtime (Python 3.12, Npcap). POSIX must still work.

Done = `pytest -q` green · `npm run build && npm test && npm run lint` green · `node --test extension/tests/` green · manual checklist in §5 passes on a real Windows machine with Npcap installed and the backend run as Administrator.

---

## T1 — Minimal revamp (frontend + extension)

### 1a. Feature cut — keep only what returns real data end-to-end
Rule: a feature **stays** only if, in live mode on this machine, it produces real output from a real source. Otherwise delete it (rule 3). Audit every component against that rule and write the keep/cut table in `docs/REVAMP.md` before deleting.

Expected outcome (verify, don't assume):

| Keep | Cut |
|---|---|
| Scan (domain / IP / URL / hash) + live source chips | `SiteMeteorsBackground`, `meteors.tsx`, `site-meteors-background.tsx` |
| Scan result: verdict, scores, evidence per provider, SHAP top-features | `CommandPalette` (duplicates nav) |
| Inspector (payload classifier — real model) | `VerifyPanel` + `POST /verify` **if** it stays localhost-only/off-by-default with no real use; otherwise keep but move under Inspector |
| Network (after T2 makes it real) | `MessageCheck` / India report-kit (contact details never verified live) — cut unless verified in §5 |
| History | Mock/Live toggle, "Mock" badges, `FloatingNav` health badge text about synthetic data |
| Settings: API token + provider key status only | `Dot11Sensor` UI, WiGLE UI (until T2 fixes them), any "experimental"/"not yet validated" panels with no data |
| | Root junk (ask before deleting files outside `threatfusion/`): `frontend/patch*.cjs`, `rewrite*.cjs`, `screenshot.cjs`, `threatfusion/capture*.py`, `raw_response.json`, `screenshot_*.png`, `result_wordpress.json`, `qa_results.txt` |

### 1b. Copy — cut every sentence that doesn't help a decision
- Delete: intro banners ("Three tools, one workflow…"), section hints ("reputation + neural URL risk"), card subtitles that describe the implementation, step numbers `01/02/03`, "Fusing signals…", explanatory paragraphs in Settings, tooltips that restate the label.
- Labels ≤ 3 words. Buttons are verbs (`Scan`, `Start`, `Stop`, `Export`). Empty states: one line max (`No scans yet`).
- Errors: what failed + the fix, one line (`Npcap not found — install from npcap.com, tick "WinPcap API-compatible mode"`).
- Remove code comments in `.tsx` that narrate design history ("Replaces the radar/HUD scope experiment…"). Keep comments that explain non-obvious logic.

### 1c. Layout & visual system
- Three top-level views only: **Scan · Network · History** (+ Settings as an icon). Plain top bar, no floating nav, no ambient animation. Framer-motion only for list insertions; respect `prefers-reduced-motion`.
- Dark, high-contrast, one accent. Tokens in `index.css` (`--bg`, `--surface`, `--line`, `--fg`, `--muted`, `--accent` gold `#E3B341`, `--accent-2` teal `#2DD4BF`, `--danger`, `--warn`, `--ok`). Severity uses colour **and** text.
- Typography: Inter for UI, JetBrains Mono for values/hashes/IPs. Numbers `tabular-nums`.
- Scan view = input → verdict row → evidence table. Evidence is a table (source · status · value · latency), not a grid of cards. Collapsible "Details" for SHAP and raw JSON.
- Mobile ≥ 360 px, no horizontal scroll.
- Extension popup: target, verdict, top 3 reasons, "Open in ThreatFusion". Nothing else.

References for tone/density (read, don't copy code): urlscan.io result page, IntelOwl job view (`github.com/intelowlproject/IntelOwl`), shadcn/ui `table`, `badge`, `tabs` primitives already in `components/ui/`.

---

## T2 — Network layer that actually works

Current state (see `IMPLEMENTATION_REPORT.md` §5.1): sensors exist and parse synthetic PCAPs, but `start()` never runs preflight, `TlsSensor` is not registered, DNS responses/SNI aren't correlated, no reputation gate, WiFi/WiGLE are unreliable, nothing was tested on real capture. Fix all of it.

### 2a. Capture bring-up (Windows-first)
- `NetworkMonitorService.start()` calls `run_preflight()` **first**. If the state is not capturable, start no packet sensors, set `running=false`, return the preflight (state, reason, fix). Never report "running" with zero packets.
- Preflight checks, each with a one-line fix: scapy importable · Npcap present (`%SystemRoot%\System32\Npcap\wpcap.dll`) · WinPcap-compatible mode · process elevated (`ctypes.windll.shell32.IsUserAnAdmin()`) · interface opens.
- Interface selection: if `NETWORK_CAPTURE_INTERFACE` empty, pick the interface carrying the default route (`scapy.all.conf.route.route("0.0.0.0")[0]`), fall back to the first of `get_working_ifaces()` with an IPv4 address that isn't loopback/virtual (skip Hyper-V, WSL, VirtualBox, VMware, Npcap Loopback). Expose `GET /network/interfaces` and let Settings pick one.
- After start, `effective_state()` must flip to `capturing` only after ≥1 real packet within 10 s; otherwise `no_traffic` with reason.
- `/network/status` returns: `running`, `capture` (preflight dict), per-sensor `{available, running, packets, events, last_event_at, reason}`, `dropped_events`, `alert_count`, `device_count`, `scope_note`.
- Reference: scapy Windows troubleshooting (`scapy.readthedocs.io/en/latest/troubleshooting.html`), Npcap guide (`npcap.com/guide/`).

### 2b. Sensors
- Register all real sensors: `ArpSensor`, `DnsSensor` (queries **and** responses), `TlsSensor` (ClientHello → SNI/JA3/JA4), `WifiScanner`.
- **Drop `Dot11Sensor`** (needs monitor mode; most Windows NICs can't). If kept, it must report `unsupported` from a real capability probe, never silently run.
- One shared `AsyncSniffer` per interface with a BPF filter `arp or udp port 53 or (tcp dst port 443 and tcp[((tcp[12]&0xf0)>>2)]=0x16)`; fan packets out to parsers. No per-sensor duplicate sniffers.
- Event queue bounded (`maxsize=10_000`), `put_nowait` from threads; on full, increment `dropped_events` (exposed in status). Consumer never blocks the loop.
- start/stop idempotent; test start→stop ×10 leaves zero threads and zero open handles.

### 2c. Correlation that produces real alerts
- Domain→IP map from DNS responses (respect TTL, cap 50k entries LRU). SNI and DNS names feed the same path.
- **Reputation gate** (`network/reputation_gate.py`), order per name: private/local filter (`privacy.py`) → TTL cache by registered domain (eTLD+1) → in-flight de-dup → local feeds (Tranco top-1M = skip; OpenPhish / PhishTank / URLhaus / ThreatFox / SSLBL hit = alert) → URL-text model (local, free) → VirusTotal only if model ≥ threshold, under a **separate network VT budget** (default 1/min) so monitoring can't starve user scans. Test: 1,000-query burst ⇒ ≤ budget VT calls.
- Known-bad JA3: load `https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv` into `core/feeds.py` (same refresh/shrink-guard rules). Mark severity Medium max — abuse.ch warns these aren't FP-tested. No invented fingerprints.
- JA4: cross-check `tls_hello.py` against FoxIO's Python implementation (`github.com/FoxIO-LLC/ja4`, `python/`) on their sample PCAPs; add those as fixtures. JA4 (TLS client) is BSD-3; don't ship other JA4+ methods.
- ARP: alert on IP→MAC change for the gateway, gratuitous-ARP flood, one MAC claiming many IPs. Baseline learned per device (`baseline_store.py`); no alert during warm-up (`BASELINE_MIN_OBSERVATIONS`).
- Heuristics only where measurable: NXDOMAIN burst per device, long/high-entropy labels (DGA-ish, unsupervised), beaconing (low-jitter periodic contacts to one host). Each alert carries the evidence that triggered it.

### 2d. Wi-Fi
- `netsh wlan show networks mode=bssid` — parse with locale-independent logic (match by line order/BSSID regex, not English labels) or use the Native Wifi API via `ctypes` (`WlanGetNetworkBssList`).
- Windows 11 24H2+: netsh/WLAN API requires **Location services ON** for desktop apps. Detect the "access is denied"/location error and surface: `Turn on Location for desktop apps (Settings → Privacy → Location)`.
- Rogue/evil-twin rules: group BSSIDs by SSID + same OUI / adjacent MACs as one network; alert on same SSID with different security mode, unexpected OUI, or new channel. User can mark an AP "known" (stored). Report FP rate on your own network in `docs/REVAMP.md`.
- WiGLE: fix the 412 (BSSID must be `aa:bb:cc:dd:ee:ff` lowercase colon form; verify with one live call). If still failing, cut it.

### 2e. UI
- Network view: status strip (state · interface · packets/s · dropped) → Start/Stop → alert table (time · severity · type · device · summary) → click row for evidence. Device list tab.
- When not capturing, show the preflight reason + fix only. No empty decorative widgets.
- SSE: keep fresh-ticket-per-reconnect (already in `api.ts`); add `Last-Event-ID` backfill server-side (ring buffer of last 500 alert ids) so reconnects don't miss alerts. Show connection state.

Reference projects (patterns, not code): Zeek (DNS/TLS log fields), Suricata EVE `tls`/`dns` events, nzyme (Wi-Fi monitoring & bandit/rogue logic), arpwatch (ARP change semantics), FoxIO JA4.

---

## T3 — Scan feature: real values only

### 3a. Kill synthetic data in the serving path
- `USE_MOCK_DATA` default → `False`. If `True` outside pytest (`"PYTEST_CURRENT_TEST" not in os.environ`), refuse to start with a clear error. Tests keep using mock/respx.
- Remove every `mock` field/badge from responses rendered in the UI. `ScanResult.mock_mode` stays in the schema only for tests.
- Audit `features.py`, `scan.py`, `exposure.py`, `chaining.py`, `ingestion/*` for constants standing in for missing data (e.g. default ages, default CVSS, "0 ports" when Shodan failed). Each becomes `None` + reason.
- Verify each reputation channel with **one** live call and fix field names (crt.sh, URLhaus, ThreatFox, Safe Browsing, AbuseIPDB, urlscan, OTX, GreyNoise, PhishTank dump, Tranco zip, endoflife.date). Record the verified response shape as a fixture. Channels without a key are hidden from the UI, not shown as "not configured".

### 3b. Fix the score labels (currently wrong)
`RiskScorePanel` says "XGBoost · VirusTotal signals only · not yet validated". That's stale: since A2, `ml_score` is the **stacked URL-text fusion** (tree + char-CNN), evaluated on a time-ordered, host-disjoint test set (PR-AUC 0.969 vs 0.824 for the lexical baseline — `ml/results/report.md`). The provider `baseline_score` is a separate weighted sum over provider evidence. They measure different things.
- Rename: `URL model` (score, calibrated, with "at 1 % prevalence" what-if from `url_risk.at_prevalence`) and `Provider evidence` (baseline weighted sum). Subtitles ≤ 5 words.

### 3c. When baseline > model on a scan — honest handling
Do **not** raise the model's number. Instead:
- Compute `agreement = |ml − baseline| ≤ 15` and expose it.
- **Headline verdict** = the higher-risk band of the two channels, with a `driven_by` field (`url_model` | `provider_evidence` | `both`). This is a standard max-of-evidence rule for detection (a hit from either channel should not be averaged away), it's transparent, and it's justified in the report.
- UI: when `driven_by = provider_evidence`, show `Flagged by provider evidence — URL text looks benign` plus the top provider reasons. When channels disagree, show the two numbers side by side with a `Disagree` tag.
- Optional, data-backed: log disagreement cases (feedback table) and, if the baseline is right more often on some slice, retrain/re-calibrate the fusion with provider features (B7) and re-run `python -m ml.evaluate --report`. Any improvement must show up in the report, not in a display rule.

### 3d. Tests
- `test_revamp_no_fabrication.py`: with every provider erroring, every numeric field in `ScanResult` except URL-model outputs is `None`.
- `test_revamp_verdict.py`: headline = max band; `driven_by` correct; ml/baseline values equal their raw computed values (never modified).
- Frontend view-model test: `—` rendered for `null`, never `0`.

---

## 4. Order of work
T3a → T3b/c → T2a → T2b → T2c → T2d → T2e → T1a → T1b → T1c → docs (`AI_CONTEXT.md`, `ROADMAP.md`, `docs/REVAMP.md`). Run the full test suite after each task.

## 5. Manual acceptance (real Windows machine, backend as Administrator, Npcap installed)
- [ ] Without Npcap: Network shows `Npcap not found` + fix; nothing claims to be running.
- [ ] Not elevated: shows `Run as Administrator`.
- [ ] With both: status reaches `capturing` within 10 s; packets/s > 0 while browsing.
- [ ] `nslookup example.com` appears as a DNS event; visiting an OpenPhish-listed host (from the live feed, in a VM) raises an alert within 5 s.
- [ ] HTTPS visit produces SNI + JA3/JA4; a JA4 value matches FoxIO's tool on the same PCAP.
- [ ] `arpspoof`/Bettercap against your own lab VM triggers a gateway-MAC-change alert; normal use for 30 min raises none.
- [ ] Wi-Fi list populates; Location-off case shows the fix line.
- [ ] Kill/restart backend while the page is open → SSE reconnects, no missed alerts.
- [ ] Scan `google.com`, a fresh OpenPhish URL, an IP, a hash: every number traceable to a source in the evidence table; disconnect network → values become `—` with reasons.
- [ ] No remaining text longer than one line outside the evidence table; no decorative animation.
