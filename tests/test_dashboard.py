from fastapi.testclient import TestClient

from web.app import app


client = TestClient(app)


def test_health_returns_ok():
    r = client.get('/api/health')
    assert r.status_code == 200
    assert r.json().get('status') == 'ok'


def test_agents_status_returns_agents():
    r = client.get('/api/agents/status')
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert any(a.get('name') == 'Scope Guard' for a in data)


def test_dashboard_unknown_target_returns_empty_clean_response():
    r = client.get('/api/dashboard/definitely-unknown-target-xyz')
    assert r.status_code == 200
    data = r.json()
    assert data['target'] == 'definitely-unknown-target-xyz'
    assert data['stats']['targets'] == 0
    assert data['stats']['live_targets'] == 0
    assert data['stats']['endpoints'] == 0
    assert data['stats']['findings'] == 0
    assert data['stats']['evidence_items'] == 0
    assert data['attack_surface'] == []
    assert data['top_findings'] == []
    assert data['recent_findings'] == []
    assert data['live_requests'] == []
    assert data['recent_activity'] == []
