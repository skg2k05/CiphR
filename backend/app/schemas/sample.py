from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime
from app.schemas.analysis import AnalysisResponse
from app.schemas.finding import FindingResponse
from app.schemas.threat_decision import ThreatDecisionResponse

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
    
    source_type: str = "upload"
    source_url: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

class UrlAnalysisRequest(BaseModel):
    url: str

class SampleDetailResponse(SampleResponse):
    analysis: Optional[AnalysisResponse] = None
    findings: List[FindingResponse] = []
    threat_decision: Optional[ThreatDecisionResponse] = None
    
    model_config = ConfigDict(from_attributes=True)
