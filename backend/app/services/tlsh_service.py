import hashlib
from app.core.logging import logger

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False
    logger.warning("python-tlsh not available. Using mock/fallback TLSH implementation.")


def calculate_tlsh(file_path: str) -> str:
    """Calculates the TLSH of a file. Returns a mock if library is missing."""
    if TLSH_AVAILABLE:
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                return tlsh.hash(data)
        except Exception as e:
            logger.error(f"TLSH generation failed: {e}")
            return "ERROR_GENERATING_TLSH"
    else:
        # Generate a deterministic mock hash based on SHA256 just for testing correlation
        with open(file_path, 'rb') as f:
            data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
            # MOCK_TLSH prefixed so it's clear
            return f"MOCK_TLSH_{sha256[:30]}"

def compare_tlsh(hash1: str, hash2: str) -> int:
    """Compares two TLSH hashes and returns a difference score (lower is more similar)."""
    if not hash1 or not hash2 or hash1.startswith("ERROR") or hash2.startswith("ERROR"):
        return 9999  # very different

    if TLSH_AVAILABLE and not hash1.startswith("MOCK") and not hash2.startswith("MOCK"):
        try:
            return tlsh.diff(hash1, hash2)
        except Exception:
            return 9999
    else:
        # Mock comparison for tests
        if hash1 == hash2:
            return 0
        return 9999
