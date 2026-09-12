import uuid
from fastapi import HTTPException

def validate_uuid(id_string: str, resource_name: str = "Resource"):
    """
    Validates if the provided string is a valid UUID.
    Raises an HTTP 404 Not Found if malformed to prevent 500 DB errors.
    """
    try:
        uuid.UUID(id_string)
        return True
    except ValueError:
        raise HTTPException(status_code=404, detail=f"{resource_name} not found")
