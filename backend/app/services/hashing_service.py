import hashlib
import aiofiles

async def calculate_sha256(file_path: str) -> str:
    """Calculates the SHA-256 hash of a file efficiently by streaming."""
    sha256_hash = hashlib.sha256()
    async with aiofiles.open(file_path, "rb") as f:
        while chunk := await f.read(8192):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()
