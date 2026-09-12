from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime
from app.schemas.analysis import AnalysisResponse
from app.schemas.finding import FindingResponse

class SampleBase(BaseModel):
    filename: str
    sha256: str
    size: Optional[int] = None
    source: Optional[str] = None
    submitted_by: Optional[str] = None

class SampleCreate(SampleBase):
    pass

class SampleResponse(SampleBase):
    id: str
    status: str
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class SampleDetailResponse(SampleResponse):
    analysis: Optional[AnalysisResponse] = None
    findings: List[FindingResponse] = []
    
    model_config = ConfigDict(from_attributes=True)
