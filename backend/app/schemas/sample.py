from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime
from app.schemas.analysis import AnalysisResponse
from app.schemas.finding import FindingResponse
from app.schemas.campaign import CampaignResponse

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
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

class RelatedSampleItem(BaseModel):
    sample_id: str
    filename: str
    sha256: str
    relationship: str
    confidence: float
    reason: Optional[str] = None
    campaign_id: Optional[str] = None
    campaign_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class RelatedSamplesResponse(BaseModel):
    sample_id: str
    total: int
    items: List[RelatedSampleItem] = []

class SampleDetailResponse(SampleResponse):
    analysis: Optional[AnalysisResponse] = None
    findings: List[FindingResponse] = []
    campaigns: List[CampaignResponse] = []
    related_samples: List[RelatedSampleItem] = []
    related_sample_count: int = 0
    
    model_config = ConfigDict(from_attributes=True)
