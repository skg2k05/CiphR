import hashlib
from typing import Optional
from androguard.core.apk import APK
from app.core.logging import logger


def extract_certificate_fingerprint(apk_obj: APK) -> Optional[str]:
    """Extracts a SHA-256 fingerprint of the APK's signing certificate."""
    try:
        certs = apk_obj.get_certificates()
        if not certs:
            return None
            
        # Get the first certificate's DER data
        cert = certs[0]
        der_data = cert.dump()
        
        fingerprint = hashlib.sha256(der_data).hexdigest()
        return fingerprint
    except Exception as e:
        logger.error(f"Failed to extract certificate fingerprint: {e}")
        return None
