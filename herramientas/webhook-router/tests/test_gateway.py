import pytest
import time
from app.core.config import settings

@pytest.mark.asyncio
async def test_webhook_ingress_rejection(client):
    """Verifies that requests with incorrect credentials are denied (HTTP 403)."""
    response = await client.post("/webhook", json={
        "token": "wrong_token",
        "source": "host-1",
        "service": "postgres",
        "severity": "CRITICAL",
        "message": "DB connection timeout",
        "timestamp": int(time.time())
    })
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_webhook_ingress_acceptance(client):
    """Verifies that valid webhook calls are immediately accepted (HTTP 202)."""
    response = await client.post(
        "/webhook", 
        headers={"X-Gateway-Token": settings.GATEWAY_TOKEN},
        json={
            "token": "",
            "source": "host-1",
            "service": "postgres",
            "severity": "WARNING",
            "message": "High memory consumption",
            "timestamp": int(time.time())
        }
    )
    assert response.status_code == 202
    res_data = response.json()
    assert res_data["status"] == "accepted"
    assert res_data["details"]["service"] == "postgres"
    assert res_data["details"]["severity"] == "WARNING"
