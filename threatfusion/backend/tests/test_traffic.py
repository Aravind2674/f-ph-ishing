"""Tests for the Phase 3 traffic-capture analysis layer."""

import pytest

from app.recon.traffic import CapturedRequest, extract_values, parse_har


# ── HAR fixture (shape as exported by Burp / DevTools / ZAP) ─────────────────
HAR = {
    "log": {
        "version": "1.2",
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://shop.test/item?id=42&sort=price",
                    "headers": [{"name": "Host", "value": "shop.test"}],
                }
            },
            {
                "request": {
                    "method": "GET",
                    "url": "https://shop.test/item?id=1%27%20OR%20%271%27%3D%271",
                    "headers": [{"name": "Host", "value": "shop.test"}],
                }
            },
            {
                "request": {
                    "method": "POST",
                    "url": "https://shop.test/login",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "postData": {
                        "mimeType": "application/json",
                        "text": "{\"user\": \"admin\", \"q\": \"<script>alert(1)</script>\"}",
                    },
                }
            },
        ],
    }
}


# ── Unit: HAR parsing + value extraction (no model needed) ───────────────────
def test_parse_har_extracts_requests():
    reqs = parse_har(HAR)
    assert len(reqs) == 3
    assert reqs[0].method == "GET"
    assert reqs[2].method == "POST"
    assert reqs[2].content_type == "application/json"


def test_extract_values_covers_query_path_and_json_body():
    reqs = parse_har(HAR)
    # Query params + path.
    locs0 = dict(extract_values(reqs[0]))
    assert "1%27" not in "".join(locs0)  # sanity
    assert any(loc.startswith("query:id") for loc, _ in extract_values(reqs[0]))
    # JSON body values are flattened to body:<path>.
    body_vals = extract_values(reqs[2])
    joined = " ".join(f"{loc}={val}" for loc, val in body_vals)
    assert "body:user" in joined and "admin" in joined
    assert "<script>" in joined


def test_parse_har_skips_malformed_entries():
    bad = {"log": {"entries": [{"request": {}}, {"nope": 1}]}}
    assert parse_har(bad) == []


# ── Integration: endpoint (skips cleanly if classifier untrained) ────────────
def test_traffic_endpoint_batch_flags_sqli(client):
    payload = {
        "requests": [
            {"method": "GET", "url": "https://x.test/p?id=1' OR '1'='1", "headers": {}},
            {"method": "GET", "url": "https://x.test/p?id=42", "headers": {}},
        ]
    }
    resp = client.post("/traffic/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    if not data.get("model_loaded"):
        pytest.skip("vuln classifier checkpoint not trained in this environment")
    assert data["analyzed"] == 2
    assert data["flagged"] >= 1
    assert data["findings"][0]["is_attack"] is True


def test_traffic_endpoint_har(client):
    resp = client.post("/traffic/analyze", json={"har": HAR})
    data = resp.json()
    if not data.get("model_loaded"):
        pytest.skip("vuln classifier checkpoint not trained in this environment")
    assert data["analyzed"] == 3
    # The SQLi and XSS requests should be flagged; the benign one should not.
    assert data["flagged"] >= 2


def test_traffic_endpoint_empty(client):
    resp = client.post("/traffic/analyze", json={"requests": []})
    data = resp.json()
    if not data.get("model_loaded"):
        pytest.skip("vuln classifier checkpoint not trained in this environment")
    assert data["analyzed"] == 0
