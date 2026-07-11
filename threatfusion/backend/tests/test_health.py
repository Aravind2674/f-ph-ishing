"""Tests for the health check endpoint."""

def test_health_endpoint(client):
    """Health endpoint should return status, version, and mock mode flag."""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'healthy'
    assert 'version' in data
    assert 'mock_mode' in data
