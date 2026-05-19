import pytest
from app.core.config import settings

async def get_admin_headers(client):
    """Helper to register and login as admin to get auth headers."""
    # Perform first run setup
    await client.post("/api/auth/setup", json={
        "gateway_token": settings.GATEWAY_TOKEN,
        "username": "admin",
        "password": "securepassword123"
    })
    
    # Login
    response = await client.post("/api/auth/login", json={
        "username": "admin",
        "password": "securepassword123"
    })
    token = response.json()["session_token"]
    return {"X-Session-Token": token}

@pytest.mark.asyncio
async def test_admin_stats(client):
    headers = await get_admin_headers(client)
    
    # Get stats
    response = await client.get("/stats", headers=headers)
    assert response.status_code == 200
    stats = response.json()
    assert stats["gateway_status"] == "online"
    assert "event_telemetry" in stats
    assert "automated_remediations" in stats

@pytest.mark.asyncio
async def test_admin_config_rules(client):
    headers = await get_admin_headers(client)
    
    # Read rules (default should fallback)
    response = await client.get("/api/rules", headers=headers)
    assert response.status_code == 200
    assert "rules_yaml" in response.json()
    
    # Update rules with invalid YAML
    response = await client.post("/api/rules", headers=headers, json={
        "rules_yaml": "invalid: - yaml: :"
    })
    assert response.status_code == 400
    
    # Update rules with valid YAML
    valid_rules = """
rules:
  - name: "Test Rule"
    match:
      severity: "CRITICAL"
    handlers:
      - "logger"
"""
    response = await client.post("/api/rules", headers=headers, json={
        "rules_yaml": valid_rules
    })
    assert response.status_code == 200
    assert response.json()["status"] == "success"

@pytest.mark.asyncio
async def test_admin_config_env(client):
    headers = await get_admin_headers(client)
    
    # Get environment configurations
    response = await client.get("/api/config", headers=headers)
    assert response.status_code == 200
    config = response.json()
    assert "GATEWAY_TOKEN" in config
    assert "DB_FILE" in config

@pytest.mark.asyncio
async def test_admin_nodes(client):
    headers = await get_admin_headers(client)
    
    # Get node aliases
    response = await client.get("/api/nodes", headers=headers)
    assert response.status_code == 200
    assert "nodes" in response.json()
    
    # Ping simulation node
    response = await client.post("/api/nodes/ping", headers=headers, json={
        "host_alias": "DEFAULT (Main SSH Host)"
    })
    assert response.status_code == 200
    assert "status" in response.json()

@pytest.mark.asyncio
async def test_admin_logs(client):
    headers = await get_admin_headers(client)
    
    # Get infra logs
    response = await client.get("/api/logs?file=infra_events", headers=headers)
    assert response.status_code == 200
    assert "lines" in response.json()
