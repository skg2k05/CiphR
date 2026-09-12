from pydantic import BaseModel
from typing import Generic, TypeVar, List, Optional
from datetime import datetime

T = TypeVar('T')

class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    size: int

class ErrorModel(BaseModel):
    code: str
    message: str

class ErrorResponse(BaseModel):
    error: ErrorModel
