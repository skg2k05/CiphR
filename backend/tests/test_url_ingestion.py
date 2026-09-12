import pytest
import os
import shutil
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Response, RequestError, TimeoutException
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.db.database import get_db, Base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Setup test database
TEST_DB_URL = "sqlite+aiosqlite:///./test_url_ingestion.db"
engine = create_async_engine(TEST_DB_URL, echo=False)
TestingSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def override_get_db():
    async with TestingSessionLocal() as session:
        yield session

client = TestClient(app)

# Helper to provide a valid API key header
headers = {"X-API-Key": "test_api_key"}

import io
import zipfile

def create_dummy_apk():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr("AndroidManifest.xml", b"dummy")
    return buf.getvalue()

dummy_apk_content = create_dummy_apk()

@pytest.fixture(autouse=True)
async def setup_teardown():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Ensure upload dir exists
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    
    # Create the test API key in db directly
    from app.db.models import APIKey
    from app.core.auth import _hash_api_key
    async with TestingSessionLocal() as session:
        key_hash = _hash_api_key("test_api_key")
        session.add(APIKey(key_hash=key_hash, name="test"))
        await session.commit()
        
    app.dependency_overrides[get_db] = override_get_db
        
    yield
    
    app.dependency_overrides.clear()
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()
    
    if os.path.exists("./test_url_ingestion.db"):
        try:
            os.remove("./test_url_ingestion.db")
        except PermissionError:
            pass

# A. Existing APK upload still works.
@pytest.mark.asyncio
async def test_existing_apk_upload():
    file_content = dummy_apk_content
    files = {"file": ("test.apk", file_content, "application/vnd.android.package-archive")}
    response = client.post("/api/v1/samples/upload", files=files, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["source_type"] == "upload"
    assert data["source_url"] is None

class AsyncIterMock:
    def __init__(self, items):
        self.items = items
    async def __aiter__(self):
        for item in self.items:
            yield item

class MockResponse:
    def __init__(self, status_code=200, headers=None, content=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content
    def aiter_bytes(self, chunk_size=8192):
        return AsyncIterMock([self.content])
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

class MockAsyncClient:
    def __init__(self, mock_responses):
        self.mock_responses = mock_responses
        self.request_count = 0
    def stream(self, method, url, **kwargs):
        resp = self.mock_responses[self.request_count]
        self.request_count += 1
        return resp
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

# Setup patchers
@pytest.fixture
def mock_dns_safe():
    with patch('socket.getaddrinfo') as mock_gai:
        # Resolve to a safe public IP by default
        mock_gai.return_value = [(2, 1, 6, '', ('93.184.216.34', 80))]
        yield mock_gai

@pytest.fixture
def mock_dns_loopback():
    with patch('socket.getaddrinfo') as mock_gai:
        mock_gai.return_value = [(2, 1, 6, '', ('127.0.0.1', 80))]
        yield mock_gai

@pytest.fixture
def mock_dns_private():
    with patch('socket.getaddrinfo') as mock_gai:
        mock_gai.return_value = [(2, 1, 6, '', ('10.0.0.1', 80))]
        yield mock_gai

@pytest.fixture
def mock_dns_fail():
    with patch('socket.getaddrinfo') as mock_gai:
        import socket
        mock_gai.side_effect = socket.gaierror("Name or service not known")
        yield mock_gai


@pytest.mark.asyncio
async def test_url_ingestion_valid(mock_dns_safe):
    mock_responses = [MockResponse(200, {"Content-Type": "application/vnd.android.package-archive"}, dummy_apk_content)]
    
    with patch('httpx.AsyncClient', return_value=MockAsyncClient(mock_responses)):
        req = {"url": "https://example.com/app.apk"}
        response = client.post("/api/v1/samples/url", json=req, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["source_type"] == "url"
        assert data["source_url"] == "https://example.com/app.apk"
        assert data["filename"] == "app.apk"

@pytest.mark.asyncio
async def test_url_ingestion_unsupported_scheme():
    req = {"url": "file:///etc/passwd"}
    response = client.post("/api/v1/samples/url", json=req, headers=headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_SCHEME"

@pytest.mark.asyncio
async def test_url_ingestion_loopback(mock_dns_loopback):
    req = {"url": "http://example.com/app.apk"}
    response = client.post("/api/v1/samples/url", json=req, headers=headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "BLOCKED_DESTINATION"

@pytest.mark.asyncio
async def test_url_ingestion_private(mock_dns_private):
    req = {"url": "http://internal-server.local/app.apk"}
    response = client.post("/api/v1/samples/url", json=req, headers=headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "BLOCKED_DESTINATION"

@pytest.mark.asyncio
async def test_url_ingestion_dns_fail(mock_dns_fail):
    req = {"url": "http://does-not-exist.com/app.apk"}
    response = client.post("/api/v1/samples/url", json=req, headers=headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "DNS_FAILURE"

@pytest.mark.asyncio
async def test_url_ingestion_excessive_redirects(mock_dns_safe):
    mock_responses = [MockResponse(302, {"Location": "/redirect"}) for _ in range(5)]
    
    with patch('httpx.AsyncClient', return_value=MockAsyncClient(mock_responses)):
        req = {"url": "https://example.com/app.apk"}
        response = client.post("/api/v1/samples/url", json=req, headers=headers)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "TOO_MANY_REDIRECTS"

@pytest.mark.asyncio
async def test_url_ingestion_oversized(mock_dns_safe):
    # Mock settings
    with patch('app.services.url_ingestion_service.settings.MAX_APK_SIZE_BYTES', 100):
        mock_responses = [MockResponse(200, {}, b"0" * 200)]
        with patch('httpx.AsyncClient', return_value=MockAsyncClient(mock_responses)):
            req = {"url": "https://example.com/app.apk"}
            response = client.post("/api/v1/samples/url", json=req, headers=headers)
            assert response.status_code == 400
            assert response.json()["error"]["code"] == "FILE_TOO_LARGE"

@pytest.mark.asyncio
async def test_url_ingestion_html_content(mock_dns_safe):
    mock_responses = [MockResponse(200, {"Content-Type": "text/html; charset=utf-8"}, b"<html></html>")]
    
    with patch('httpx.AsyncClient', return_value=MockAsyncClient(mock_responses)):
        req = {"url": "https://example.com/app.apk"}
        response = client.post("/api/v1/samples/url", json=req, headers=headers)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_CONTENT"

@pytest.mark.asyncio
async def test_url_ingestion_invalid_zip(mock_dns_safe):
    # Not a zip file header
    mock_responses = [MockResponse(200, {}, b"NOT A ZIP FILE")]
    
    with patch('httpx.AsyncClient', return_value=MockAsyncClient(mock_responses)):
        req = {"url": "https://example.com/app.apk"}
        response = client.post("/api/v1/samples/url", json=req, headers=headers)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_APK"

@pytest.mark.asyncio
async def test_temporary_files_cleaned_up(mock_dns_safe):
    mock_responses = [MockResponse(200, {}, b"NOT A ZIP FILE")]
    
    with patch('httpx.AsyncClient', return_value=MockAsyncClient(mock_responses)):
        req = {"url": "https://example.com/app.apk"}
        initial_files = os.listdir(settings.UPLOAD_DIR)
        response = client.post("/api/v1/samples/url", json=req, headers=headers)
        assert response.status_code == 400
        final_files = os.listdir(settings.UPLOAD_DIR)
        # Should be exactly the same (temp file removed on error)
        assert len(initial_files) == len(final_files)

