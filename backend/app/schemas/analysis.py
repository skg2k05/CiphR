from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class AnalysisBase(BaseModel):
    status: str
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    tlsh: Optional[str] = None
    certificate_fingerprint: Optional[str] = None
    risk_score: Optional[int] = None
    risk_factors: Optional[list] = None
    activities: Optional[list] = None
    services: Optional[list] = None
    receivers: Optional[list] = None
    dex_data: Optional[dict] = None
    threat_narrative: Optional[str] = None

class AnalysisCreate(AnalysisBase):
    sample_id: str

class AnalysisResponse(AnalysisBase):
    id: str
    sample_id: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
