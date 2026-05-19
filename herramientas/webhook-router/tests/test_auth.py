import pytest
from app.core.config import settings

@pytest.mark.asyncio
async def test_auth_flow(client):
    # 1. Check initially not initialized
    response = await client.get("/api/auth/status")
    assert response.status_code == 200
    assert response.json() == {"initialized": False}

    # 2. Perform setup with incorrect token
    response = await client.post("/api/auth/setup", json={
        "gateway_token": "wrong_token",
        "username": "admin",
        "password": "securepassword123"
    })
    assert response.status_code == 401

    # 3. Perform setup with correct token
    response = await client.post("/api/auth/setup", json={
        "gateway_token": settings.GATEWAY_TOKEN,
        "username": "admin",
        "password": "securepassword123"
    })
    assert response.status_code == 200
    assert "initialized successfully" in response.json()["message"]

    # 4. Verify system is now initialized
    response = await client.get("/api/auth/status")
    assert response.status_code == 200
    assert response.json() == {"initialized": True}

    # 5. Login with incorrect password
    response = await client.post("/api/auth/login", json={
        "username": "admin",
        "password": "wrongpassword"
    })
    assert response.status_code == 401

    # 6. Login with correct credentials
    response = await client.post("/api/auth/login", json={
        "username": "admin",
        "password": "securepassword123"
    })
    assert response.status_code == 200
    login_data = response.json()
    assert "session_token" in login_data
    assert login_data["username"] == "admin"
    assert login_data["role"] == "admin"

    session_token = login_data["session_token"]
    headers = {"X-Session-Token": session_token}

    # 7. Get profile with valid token
    response = await client.get("/api/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"username": "admin", "role": "admin"}

    # 8. Create a new user (Viewer)
    response = await client.post("/api/auth/users", headers=headers, json={
        "username": "operator1",
        "password": "operatorpassword",
        "role": "viewer"
    })
    assert response.status_code == 200

    # 9. List users (Requires Admin)
    response = await client.get("/api/auth/users", headers=headers)
    assert response.status_code == 200
    users = response.json()
    assert len(users) == 2
    assert any(u["username"] == "operator1" and u["role"] == "viewer" for u in users)

    # 10. Update operator1's role to operator
    response = await client.put("/api/auth/users/operator1/role", headers=headers, json={
        "role": "operator"
    })
    assert response.status_code == 200

    # 11. Login as operator1
    response = await client.post("/api/auth/login", json={
        "username": "operator1",
        "password": "operatorpassword"
    })
    assert response.status_code == 200
    op_login_data = response.json()
    assert op_login_data["role"] == "operator"

    # 12. Try listing users as operator1 (Should fail, requires Admin)
    op_headers = {"X-Session-Token": op_login_data["session_token"]}
    response = await client.get("/api/auth/users", headers=op_headers)
    assert response.status_code == 403

    # 13. Logout admin
    response = await client.post("/api/auth/logout", headers=headers)
    assert response.status_code == 200

    # 14. Access profile with old admin token (Should fail)
    response = await client.get("/api/auth/me", headers=headers)
    assert response.status_code == 401
