import pytest
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.main import app
from app.db.database import Base, get_db

# Use a file-based test database to support true connection pooling and WAL mode
# This is necessary for concurrent transaction isolation in tests without deadlocking SQLite.
TEST_DATABASE_URL = "sqlite+aiosqlite:///test_ciph_r.db"

engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    future=True,
    pool_size=5,
    max_overflow=10,
    connect_args={"check_same_thread": False},
)

TestingSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with TestingSessionLocal() as session:
        yield session

app.dependency_overrides[get_db] = override_get_db

from sqlalchemy import text
from app.db.models import APIKey

@pytest.fixture(scope="session", autouse=True)
async def setup_database():
    async with engine.begin() as conn:
        # Enable WAL mode for true concurrent reads/writes during tests
        await conn.execute(text("PRAGMA journal_mode=WAL;"))
        await conn.execute(text("PRAGMA synchronous=NORMAL;"))
        
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        
        # Insert a mock API key for testing authentication
        import hashlib
        key_hash = hashlib.sha256("test_mock_key".encode("utf-8")).hexdigest()
        await conn.execute(text(
            f"INSERT INTO api_keys (id, key_hash, name, is_active, created_at) "
            f"VALUES ('123e4567-e89b-12d3-a456-426614174000', '{key_hash}', 'test_key', 1, '2026-09-09 12:00:00')"
        ))
        
    yield
    
    # Cleanup test DB file
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    import os
    try:
        os.remove("test_ciph_r.db")
    except OSError:
        pass

@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": "test_mock_key"}) as ac:
        yield ac
