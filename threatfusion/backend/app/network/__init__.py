"""ThreatFusion – Network Layer
================================

Defensive, real-time monitoring of a WiFi/LAN the operator controls.

This package sits *alongside* the existing App Layer (domain/IP threat
intelligence) and reuses its scoring pipeline verbatim for cross-layer
correlation.  Nothing in here fabricates data: every value that reaches an
alert is derived from a real captured signal (packet / DNS / ARP / 802.11),
a real WiGLE lookup, a real VirusTotal-backed App-Layer sub-score, or a
baseline computed from real observed traffic.  When a signal is unavailable
the layer degrades honestly and records *why* in the alert evidence.

Sub-modules
-----------
* ``models``          – Pydantic contracts for events, profiles and alerts.
* ``sensor``          – real capture sensors (ARP, DNS, WiFi scan, 802.11).
* ``enrichment``      – App-Layer reuse adapter + real WiGLE client.
* ``baseline_store``  – rolling per-device behaviour profiles (SQLite).
* ``correlation``     – the fusion scoring engine.
* ``service``         – orchestration + SSE broadcast.
"""
