import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_health_endpoint(async_client: AsyncClient):
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "ciphR-backend"

@pytest.mark.asyncio
async def test_get_campaigns_empty(async_client: AsyncClient):
    response = await async_client.get("/api/v1/campaigns")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert len(data["items"]) == 0

@pytest.mark.asyncio
async def test_get_samples_empty(async_client: AsyncClient):
    response = await async_client.get("/api/v1/samples")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert len(data["items"]) == 0
