"""Tests for the Phase 2 ``POST /analyze`` request-analysis endpoint."""


def test_analyze_endpoint_responds(client):
    """Endpoint returns a well-formed AnalyzeResponse for a SQLi payload."""
    response = client.post("/analyze", json={"text": "id=1' OR '1'='1"})
    assert response.status_code == 200
    data = response.json()
    assert "success" in data
    assert "model_loaded" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_analyze_flags_sqli_when_model_loaded(client):
    """When the classifier is trained, a clear SQLi payload is flagged."""
    response = client.post("/analyze", json={"text": "1' OR '1'='1' UNION SELECT password FROM users-- "})
    data = response.json()
    if not data.get("model_loaded"):
        import pytest
        pytest.skip("vuln classifier checkpoint not trained in this environment")
    assert data["success"] is True
    assert data["findings"], "expected at least one finding"
    worst = data["findings"][0]
    assert worst["is_attack"] is True
    assert worst["label"] in {"sqli", "xss", "cmdi", "path-traversal"}


def test_analyze_passes_benign_value(client):
    """A benign parameter value is not flagged as an attack."""
    response = client.post("/analyze", json={"text": "city=Barcelona"})
    data = response.json()
    if not data.get("model_loaded"):
        import pytest
        pytest.skip("vuln classifier checkpoint not trained in this environment")
    # The full string + the param value should both resolve benign.
    assert all(not f["is_attack"] for f in data["findings"])
    assert data["summary"] == "No injection patterns detected."
