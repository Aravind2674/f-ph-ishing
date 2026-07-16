# PROMPT — Build ThreatFusion now with placeholder API keys

---

Use this together with `threatfusion_master_prompt.md` (paste both into the
same Claude Code session, this one second). This prompt's only job is to
make sure the entire project is fully buildable, runnable, and testable
**today**, before real API keys exist — so I can paste real keys in later
with zero code changes.

## Requirements

1. **Build everything now.** Do not wait for real API keys or ask me to
   provide them. Every ingestion client (VirusTotal, Shodan, NVD/CVE,
   tech-fingerprint) must work in one of two modes, controlled by a single
   `.env` flag `USE_MOCK_DATA=true|false`:
   - `true` (default): return realistic mocked/synthetic responses shaped
     exactly like the real API's JSON schema, so every downstream layer
     (feature engineering, scoring, frontend) works end-to-end right now.
   - `false`: make real HTTP calls using keys from `.env`.

2. **Placeholder `.env` setup.** Create `.env.example` AND a working `.env`
   (with `USE_MOCK_DATA=true` and placeholder key strings like
   `PASTE_YOUR_VIRUSTOTAL_KEY_HERE`) so the app runs immediately after
   `pip install -r requirements.txt` with no manual setup. When I later
   paste in real keys and flip `USE_MOCK_DATA=false`, nothing else should
   need to change — same function signatures, same response shape.

3. **Mock data must be realistic, not lazy.** For each source, base the
   mock responses on that API's actual documented response schema (VT's
   `/api/v3/domains/{domain}` shape, Shodan InternetDB's actual JSON
   fields, NVD's CVE object structure) — pull a couple of real example
   responses from each service's public API docs and use those as the
   mock fixtures. This matters because the ML feature engineering and
   evaluation results need to be meaningful even before real keys arrive.

4. **Make the mock/real switch loud, not silent.** Log a clear warning on
   startup if `USE_MOCK_DATA=true` ("⚠ Running with MOCK data — set
   USE_MOCK_DATA=false and add real API keys in .env for live results")
   so it's never ambiguous during a demo which mode is active.

5. **Fully working end-to-end today, with mock data:**
   - `POST /scan` returns real (mocked-but-realistic) fused results
   - The ML fusion model trains on the synthesized labeled dataset (per
     the main master prompt's Phase 5 instructions) and produces real
     baseline-vs-ML evaluation numbers — this doesn't depend on live
     external APIs at all, since it's a one-time training step on a
     downloaded dataset
   - Frontend dashboard and browser extension both work against the mock
     backend, so the whole product is demoable right now

6. **Document the swap-over.** In `README.md`, add a short "Going live"
   section: exactly which two things to do (paste keys into `.env`, flip
   `USE_MOCK_DATA` to `false`) to move from demo mode to live mode.

Proceed phase by phase as instructed in the main master prompt, applying
this mock/live pattern to every ingestion client as you build it.
