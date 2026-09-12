import hashlib
import os
from app.core.logging import logger

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False
    logger.warning("python-tlsh not available in this environment. TLSH hashing will be skipped.")

def calculate_tlsh(file_path: str) -> str:
    """Calculates the genuine TLSH of a file. Returns an error string if library is missing or file is too small."""
    if not TLSH_AVAILABLE:
        return "ERROR_TLSH_UNAVAILABLE"
        
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found for TLSH generation: {file_path}")
            return "ERROR_FILE_NOT_FOUND"
            
        file_size = os.path.getsize(file_path)
        if file_size < 50:
            logger.warning(f"File too small for TLSH (must be >= 50 bytes): {file_path}")
            return "ERROR_FILE_TOO_SMALL"
            
        with open(file_path, 'rb') as f:
            data = f.read()
            hash_str = tlsh.hash(data)  # type: ignore
            if not hash_str:
                return "ERROR_GENERATING_TLSH"
            return hash_str
            
    except Exception as e:
        logger.error(f"TLSH generation failed: {e}")
        return "ERROR_GENERATING_TLSH"

def compare_tlsh(hash1: str, hash2: str) -> int:
    """Compares two genuine TLSH hashes and returns a difference score (lower is more similar)."""
    if not TLSH_AVAILABLE:
        return 9999
        
    if not hash1 or not hash2 or hash1.startswith("ERROR") or hash2.startswith("ERROR"):
        return 9999  # very different

    try:
        return tlsh.diff(hash1, hash2)  # type: ignore
    except ValueError as e:
        logger.error(f"TLSH difference calculation failed (invalid hash): {e}")
        return 9999
    except Exception as e:
        logger.error(f"TLSH difference calculation failed: {e}")
        return 9999
