import hashlib
from typing import Optional, Dict, Any
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


def extract_certificate_details(apk_obj: APK) -> Dict[str, Any]:
    """
    Extracts structured certificate metadata including fingerprint,
    issuer, subject, and whether a debug/testkey signing certificate was used.
    """
    details: Dict[str, Any] = {
        "fingerprint": None,
        "is_debug": False,
        "issuer": None,
        "subject": None
    }
    try:
        certs = apk_obj.get_certificates()
        if not certs:
            return details

        cert = certs[0]
        der_data = cert.dump()
        details["fingerprint"] = hashlib.sha256(der_data).hexdigest()

        if hasattr(cert, "issuer") and cert.issuer:
            details["issuer"] = cert.issuer.human_friendly
        if hasattr(cert, "subject") and cert.subject:
            details["subject"] = cert.subject.human_friendly

        # Check for common debug/testkey certificates
        combined_dn = f"{details.get('issuer') or ''} {details.get('subject') or ''}".lower()
        if "android debug" in combined_dn or "testkey" in combined_dn:
            details["is_debug"] = True

    except Exception as e:
        logger.error(f"Error parsing certificate details: {e}")

    return details
