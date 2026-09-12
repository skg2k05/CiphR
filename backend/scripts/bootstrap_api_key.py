import asyncio
import secrets
import argparse
import sys
import os

# Add parent directory to path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import AsyncSessionLocal
from app.db.models import APIKey
from app.core.auth import _hash_api_key

async def create_api_key(name: str):
    # Generate cryptographically secure random key
    raw_key = secrets.token_urlsafe(32)
    key_hash = _hash_api_key(raw_key)
    
    async with AsyncSessionLocal() as db:
        new_key = APIKey(
            name=name,
            key_hash=key_hash,
            is_active=True
        )
        db.add(new_key)
        await db.commit()
        
    print(f"\nAPI Key created successfully for '{name}'.")
    print("\n" + "="*50)
    print("THIS IS YOUR ONLY CHANCE TO COPY THIS KEY")
    print("="*50)
    print(f"\n{raw_key}\n")
    print("="*50)
    print("Store it securely. The database only stores the SHA-256 hash.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootstrap a new API key for CiphR.")
    parser.add_argument("name", help="A descriptive name for the API key (e.g., 'dev-admin')")
    args = parser.parse_args()
    
    asyncio.run(create_api_key(args.name))
