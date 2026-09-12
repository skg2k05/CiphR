import os
import aiofiles
import uuid
from fastapi import UploadFile
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.db.models import Sample
from app.services.hashing_service import calculate_sha256
from app.services.validation_service import validate_apk_file
from app.core.exceptions import CiphRException
from app.core.logging import logger

async def process_upload(
    file: UploadFile,
    source: str,
    submitted_by: str,
    db: AsyncSession
) -> Sample:
    """Handles the saving, hashing, and initial db record for an uploaded APK."""
    
    filename = file.filename or "unknown.apk"
    temp_id = str(uuid.uuid4())
    temp_filename = f"{temp_id}_{filename}"
    temp_filepath = os.path.join(settings.UPLOAD_DIR, temp_filename)
    
    # Save file efficiently
    size = 0
    try:
        async with aiofiles.open(temp_filepath, 'wb') as out_file:
            while chunk := await file.read(8192):
                size += len(chunk)
                if size > settings.MAX_APK_SIZE_BYTES:
                    # Early termination
                    os.remove(temp_filepath)
                    raise CiphRException("FILE_TOO_LARGE", f"File exceeds maximum size of {settings.MAX_APK_SIZE_MB}MB.")
                await out_file.write(chunk)
                
        # Validate
        validate_apk_file(filename, temp_filepath, size)
        
        # Hash
        sha256 = await calculate_sha256(temp_filepath)
        
        # Check duplicate
        result = await db.execute(select(Sample).filter(Sample.sha256 == sha256))
        existing_sample = result.scalars().first()
        
        if existing_sample:
            # Clean up the new duplicate file
            os.remove(temp_filepath)
            logger.info(f"Duplicate sample uploaded: {sha256}")
            return existing_sample

        # Rename file to hash for permanent storage
        permanent_filename = f"{sha256}.apk"
        permanent_filepath = os.path.join(settings.UPLOAD_DIR, permanent_filename)
        
        # Handle case where file might already exist on disk but not in DB
        if os.path.exists(permanent_filepath):
            os.remove(temp_filepath)
        else:
            os.rename(temp_filepath, permanent_filepath)
        
        # Create database record
        new_sample = Sample(
            filename=filename,
            sha256=sha256,
            size=size,
            source=source,
            submitted_by=submitted_by,
            status='QUEUED',
            storage_path=permanent_filepath
        )
        
        db.add(new_sample)
        try:
            await db.commit()
            await db.refresh(new_sample)
        except IntegrityError:
            await db.rollback()
            # A concurrent upload succeeded, retrieve it
            result = await db.execute(select(Sample).filter(Sample.sha256 == sha256))
            existing_sample = result.scalars().first()
            if existing_sample:
                if os.path.exists(temp_filepath):
                    os.remove(temp_filepath)
                logger.info(f"Duplicate sample handled via concurrent commit: {sha256}")
                return existing_sample
            raise CiphRException("UPLOAD_FAILED", "Failed to resolve concurrent upload race condition.")
        
        logger.info(f"Successfully processed new sample: {sha256}")
        return new_sample

    except CiphRException:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise
    except Exception as e:
        logger.error(f"Error during upload processing: {e}")
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise CiphRException("UPLOAD_FAILED", "An unexpected error occurred during upload processing.", status_code=500)
