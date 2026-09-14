import hashlib
import secrets
from fastapi import Security, HTTPException, status, Depends
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update
from sqlalchemy.sql import func
from datetime import datetime, timezone

from app.db.database import get_db
from app.db.models import APIKey
from app.core.logging import logger

# We use X-API-Key as the standard header for API authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def _hash_api_key(api_key: str) -> str:
    """Creates a SHA-256 hash of the API key for secure storage and comparison."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

async def get_api_key(
    api_key: str = Security(api_key_header),
    auth_db: AsyncSession = Depends(get_db, use_cache=False)
) -> APIKey:
    """
    FastAPI dependency to validate the incoming API key.
    Rejects missing, malformed, or inactive keys.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key. Please provide it in the X-API-Key header.",
        )
        
    # Hash the provided key to lookup in the database securely
    key_hash = _hash_api_key(api_key)
    
    try:
        # Secure lookup by hash using a dedicated isolated session
        result = await auth_db.execute(select(APIKey).filter(APIKey.key_hash == key_hash))
        db_api_key = result.scalars().first()
        
        if not db_api_key:
            # Avoid logging the raw API key ever
            logger.warning("Attempted access with invalid API key.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key",
            )
            
        if not db_api_key.is_active:
            logger.warning(f"Attempted access with revoked/inactive API key (ID: {db_api_key.id}).")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API Key is inactive or revoked",
            )
            
        # Update last used timestamp efficiently
        await auth_db.execute(
            update(APIKey)
            .where(APIKey.id == db_api_key.id)
            .values(last_used_at=datetime.now(timezone.utc))
        )
        await auth_db.commit()
        
        # Ensure the returned object has the updated field instantly
        db_api_key.last_used_at = datetime.now(timezone.utc)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process API key authentication: {e}")
        await auth_db.rollback()
        # Fallback response so we don't leak DB errors to the client on auth failure
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed due to internal error"
        )
    finally:
        # CRITICAL: We explicitly close this dedicated session immediately.
        # This prevents the auth read/write transaction from holding SQLite locks
        # while the downstream endpoint executes long-running operations (like file uploads),
        # entirely eliminating the concurrent SQLite timeout issues.
        await auth_db.close()
        
    return db_api_key
