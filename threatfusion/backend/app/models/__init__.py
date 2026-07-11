"""
ThreatFusion – Data Models Package
===================================

This package contains all Pydantic v2 data models that define the
**data contracts** flowing through the system:

* **Request schemas** – validated input from the frontend / API callers.
* **Response schemas** – structured output returned by the API.
* **Intermediate schemas** – normalised results from each data source
  (VirusTotal, Shodan, NVD, tech‑fingerprinting) plus the engineered
  feature vector consumed by the ML pipeline.

Design decision: every piece of data that crosses a boundary (HTTP, queue,
model inference) is typed as a Pydantic model so we get runtime validation,
automatic OpenAPI docs, and self‑documenting code – all critical for a
project that will be defended in a viva.
"""
