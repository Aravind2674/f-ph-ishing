"""
ThreatFusion – Ingestion Layer
===============================

This package contains **async client wrappers** for every external data
source that ThreatFusion consumes:

* ``virustotal`` – VirusTotal v3 API (domain / URL / file‑hash reputation).
* ``shodan``     – Shodan InternetDB (free) and full API (paid) for port /
                   service / CVE enumeration on IP addresses.
* ``cve``        – NIST NVD API v2 for hydrating CVE IDs into full
                   descriptions, CVSS scores, and severity labels.
* ``techfingerprint`` – HTTP‑header and script‑tag analysis to detect web
                        technologies (inspired by Wappalyzer).

Design decisions
----------------
* Every client is **async** (``httpx.AsyncClient``) so the orchestrator can
  fan‑out requests to all sources concurrently via ``asyncio.gather``.
* Every client accepts a ``use_mock: bool`` flag.  When ``True`` the client
  returns deterministic synthetic data, enabling full‑stack development and
  testing without burning API quotas.
* Clients return **normalised Pydantic models** (defined in
  ``app.models.schemas``) rather than raw JSON, so downstream code never
  touches untyped dicts.
"""
