from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class FindingBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    category: Optional[str] = None
    evidence: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    confidence: Optional[float] = None

class FindingCreate(FindingBase):
    sample_id: str

class FindingResponse(FindingBase):
    id: str
    sample_id: str

    model_config = ConfigDict(from_attributes=True)
