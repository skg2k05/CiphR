import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.models import APIKey
from app.core.auth import _hash_api_key
from tests.conftest import TestingSessionLocal

@pytest.mark.asyncio
async def test_auth_missing_header():
    # Create a fresh client without the default headers
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/samples")
        assert response.status_code == 401
        assert "Missing API Key" in response.json()["detail"]

@pytest.mark.asyncio
async def test_auth_invalid_key():
    async with AsyncClient(
        transport=ASGITransport(app=app), 
        base_url="http://test",
        headers={"X-API-Key": "completely_invalid_key"}
    ) as client:
        response = await client.get("/api/v1/samples")
        assert response.status_code == 401
        assert "Invalid API Key" in response.json()["detail"]

@pytest.mark.asyncio
async def test_auth_revoked_key():
    # Insert a revoked key
    revoked_raw = "revoked_mock_key"
    async with TestingSessionLocal() as session:
        revoked_key = APIKey(
            name="revoked", 
            key_hash=_hash_api_key(revoked_raw), 
            is_active=False
        )
        session.add(revoked_key)
        await session.commit()
        
    async with AsyncClient(
        transport=ASGITransport(app=app), 
        base_url="http://test",
        headers={"X-API-Key": revoked_raw}
    ) as client:
        response = await client.get("/api/v1/samples")
        assert response.status_code == 401
        assert "inactive or revoked" in response.json()["detail"]

@pytest.mark.asyncio
async def test_health_is_public():
    # Health endpoint should not require authentication
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

@pytest.mark.asyncio
async def test_valid_key_updates_last_used():
    valid_raw = "test_mock_key"
    async with AsyncClient(
        transport=ASGITransport(app=app), 
        base_url="http://test",
        headers={"X-API-Key": valid_raw}
    ) as client:
        response = await client.get("/api/v1/samples")
        assert response.status_code == 200
        
    # Check that last_used_at was updated
    from sqlalchemy.future import select
    async with TestingSessionLocal() as session:
        result = await session.execute(
            select(APIKey).filter(APIKey.key_hash == _hash_api_key(valid_raw))
        )
        key = result.scalars().first()
        assert key is not None
        assert key.last_used_at is not None
