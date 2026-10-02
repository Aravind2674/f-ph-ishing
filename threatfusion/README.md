# ThreatFusion

**ML-Based Risk Fusion for Web & Network Attack Surface Analysis**

A unified threat-intelligence platform that aggregates signals from VirusTotal,
Shodan/InternetDB, NVD/CVE databases, and web technology fingerprinting — then
uses a trained ML model to fuse these into a single explainable risk score.

## Quick Start

### Prerequisites
- **Python 3.12** (the version the dependency lock and CI are built for)
- Node.js 22+ (for frontend)

### Backend Setup
Dependencies are **exactly pinned** (`requirements.txt` is a compiled lock; the
hand-edited inputs are `requirements.in`, `requirements-ml.in`, `requirements-dev.in`).
Use a virtual environment — mixing in other packages is what previously broke
`import shap` (numba vs NumPy).
```bash
cd backend
pip install uv                          # or use plain pip + venv
uv venv --python 3.12 venv              # creates backend/venv (git-ignored)
uv pip sync requirements-dev.txt --python venv/Scripts/python.exe   # Windows
#   Linux/macOS: --python venv/bin/python
# The app runs in mock mode by default — no API keys needed
venv/Scripts/python.exe -m uvicorn app.main:app --reload   # run from backend/
```
- `requirements.txt` = runtime only · `requirements-ml.txt` = + training/eval tooling ·
  `requirements-dev.txt` = + tests and audit tools.
- Regenerate a lock after editing an `.in` file, e.g.
  `uv pip compile requirements.in -o requirements.txt --python-version 3.12 --universal`
  (see the header of each lock file for its exact command).
- Linux CI/servers: install CPU `torch` first
  (`pip install torch==<pin> --index-url https://download.pytorch.org/whl/cpu`); the lock
  intentionally omits the CUDA wheels.
- Run the server **from `backend/`**: `.env`, the SQLite path and model paths are currently
  relative to the working directory (made absolute in a later hardening step).
- **API token.** Every route except `/health` needs `Authorization: Bearer <token>`. The token is
  generated on first start and stored outside the repo (Windows: `%APPDATA%\ThreatFusionpi_token`;
  else `~/.config/threatfusion/api_token`). Print it with `python -m app.core.auth`, then paste it on the
  dashboard's **Settings** page and in the extension popup (**API token**); for the mitmproxy addon set
  `TF_API_TOKEN`. Requests must also use a local `Host` header (`ALLOWED_HOSTS`) and mutating requests must
  be `Content-Type: application/json`.
- Active verification (`POST /verify`) is **off by default** — see `VERIFY_ENABLED` / `VERIFY_ALLOWED_HOSTS`
  in `.env.example`.
- Model files are checked against `ml/models/manifest.json` (SHA-256) at load time.
  After retraining run `python -m ml.hash_models` from `threatfusion/` and commit the
  new manifest; `MODEL_HASH_STRICT=false` relaxes only the "unlisted file" rule.

Visit `http://localhost:8000/docs` for the interactive API documentation.

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### Running Tests
```bash
cd backend
pytest -v
```

## Going Live

To switch from demo mode (mock data) to live mode with real threat intelligence:

1. **Add your API keys** to `backend/.env`:
   ```
   VIRUSTOTAL_API_KEY=your_real_key_here
   SHODAN_API_KEY=your_real_key_here
   NVD_API_KEY=your_real_key_here
   ```

2. **Flip the mock switch** in `backend/.env`:
   ```
   USE_MOCK_DATA=false
   ```

That's it. No code changes needed — the same function signatures and response
shapes are used in both modes.

## Network Layer (real-time defensive monitoring)

The **Network Layer** continuously watches a WiFi/LAN you control and raises
scored alerts in real time. It reuses the App-Layer scoring pipeline for
**cross-layer correlation** (a monitored device contacting an App-Layer-flagged
domain), folds in a real **WiGLE** public-history lookup for suspected rogue
APs, and learns a **per-device behavioural baseline** from real observed
traffic. Open the **Network** tab in the dashboard for the live alert feed
(Screen A) and per-alert evidence breakdown (Screen B).

> No-compromise design: every value in an alert comes from a real captured
> signal, a real WiGLE/VirusTotal lookup, or a baseline computed from real
> observed traffic. When a signal is unavailable (no key, monitor mode
> unsupported, API offline) the layer degrades honestly and records *why* in
> the alert evidence — it never fabricates a value.

### What real capture requires (Windows)

Packet/DNS/ARP capture uses **scapy + [Npcap](https://npcap.com/)** and must
run in an **elevated (Administrator)** process.

1. Install [Npcap](https://npcap.com/#download) (tick *"Install Npcap in
   WinPcap API-compatible Mode"*). For deauth detection also tick
   *"Support raw 802.11 traffic (and monitor mode)"* — only useful with a
   monitor-mode-capable adapter (see the capability matrix below).
2. `pip install -r requirements.txt` (adds `scapy`).
3. Configure `backend/.env` (see `.env.example`):
   ```
   # cross-layer correlation needs live VirusTotal
   USE_MOCK_DATA=false
   VIRUSTOTAL_API_KEY=your_real_key_here
   # rogue-AP signal (register at https://wigle.net/account)
   WIGLE_API_NAME=your_wigle_api_name
   WIGLE_API_TOKEN=your_wigle_api_token
   # optional capture tuning
   NETWORK_CAPTURE_INTERFACE=        # blank = scapy default; list with the command below
   NETWORK_MONITOR_INTERFACE=        # monitor-mode adapter for deauth (blank disables it)
   NETWORK_GATEWAY_IP=192.168.1.1    # emphasises ARP spoofing against the gateway
   NETWORK_MONITORED_SSIDS=MyHomeWiFi
   NETWORK_AUTO_START=false          # true = begin capturing on API boot
   ```
   List interface names on Windows:
   ```powershell
   python -c "from scapy.all import get_windows_if_list as g; [print(i['name']) for i in g()]"
   ```
4. Start the backend **as Administrator**, then either set
   `NETWORK_AUTO_START=true` or click **Start capture** in the Network tab
   (POST `/network/monitor/start`).

### Capability matrix (honest limits)

| Signal | Real on Windows? | Mechanism |
|--------|------------------|-----------|
| ARP spoofing / MITM, new device | ✅ | scapy + Npcap passive ARP sniff |
| DNS observation → cross-layer hit | ✅ | scapy sniff UDP/53 → App-Layer pipeline |
| Rogue / evil-twin AP + WiGLE | ✅ | native `netsh wlan` scan (no monitor mode) |
| Per-device behavioural baseline | ✅ | learned from the real DNS/flows above |
| Deauth / disassoc flood | ⚠️ hardware-dependent | needs 802.11 **monitor mode**; most consumer Windows WiFi drivers don't expose raw 802.11. The detector is real and degrades honestly (visible in `/network/status`) when monitor mode is unavailable — it never fabricates deauth frames. |

### Network API

| Endpoint | Purpose |
|----------|---------|
| `GET /network/status` | Honest per-sensor health (available / running / reason) |
| `GET /network/alerts` | Scored alerts, newest first (`?severity=High`) |
| `GET /network/alerts/{id}` | One alert's full evidence breakdown |
| `GET /network/devices` | Learned per-device baselines |
| `GET /network/stream` | **SSE** live alert feed |
| `POST /network/monitor/start` \| `stop` | Begin / end real capture |

## Project Structure
```
threatfusion/
├── backend/           # FastAPI backend
│   ├── app/
│   │   ├── api/       # Route handlers (scan, health, network)
│   │   ├── core/      # Config, logging
│   │   ├── ingestion/ # API client wrappers
│   │   ├── ml/        # Feature eng, scoring, model
│   │   ├── network/   # Network Layer: sensors, enrichment, correlation, service
│   │   └── models/    # Pydantic schemas
│   └── tests/
├── ml/                # Training & evaluation scripts
│   ├── data/          # Labeled datasets
│   ├── models/        # Saved model artifacts
│   └── results/       # Evaluation outputs
├── frontend/          # React dashboard
├── extension/         # Browser extension
└── docs/              # Architecture & roadmap
```

## Research Question

> Does a learned fusion model produce more accurate attack-surface risk
> scores than a naive rule-based/weighted-sum heuristic baseline, when
> trained on correlated multi-source security signals?

## License

This project is developed as a final-year university project.
