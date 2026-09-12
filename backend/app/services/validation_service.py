import zipfile
from app.core.exceptions import CiphRException
from app.core.config import settings
from app.core.logging import logger

def validate_apk_file(filename: str, file_path: str, size: int):
    """Validates an uploaded APK file for basic integrity."""
    # 1. Extension check
    if not filename.lower().endswith(".apk"):
        raise CiphRException("INVALID_EXTENSION", "File must have an .apk extension.")
        
    # 2. Size check
    if size > settings.MAX_APK_SIZE_BYTES:
        raise CiphRException("FILE_TOO_LARGE", f"File exceeds maximum size of {settings.MAX_APK_SIZE_MB}MB.")
        
    # 3. ZIP Structure check
    try:
        with zipfile.ZipFile(file_path, 'r') as apk_zip:
            # Check for path traversal inside the zip
            for info in apk_zip.infolist():
                if ".." in info.filename or info.filename.startswith("/"):
                    logger.warning(f"Suspicious path in ZIP: {info.filename}")
                    raise CiphRException("MALFORMED_APK", "Suspicious entries found in APK structure.")
            
            # Simple check for AndroidManifest.xml (must be present in valid APK)
            if "AndroidManifest.xml" not in apk_zip.namelist():
                raise CiphRException("INVALID_APK", "Missing AndroidManifest.xml in the APK structure.")
                
    except zipfile.BadZipFile:
        raise CiphRException("INVALID_APK", "The file is not a valid ZIP/APK archive.")
    except CiphRException:
        raise
    except Exception as e:
        logger.error(f"Unexpected validation error: {e}")
        raise CiphRException("VALIDATION_ERROR", "An error occurred during file validation.")
    
    return True
