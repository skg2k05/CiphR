from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime

class CampaignBase(BaseModel):
    name: str
    description: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    status: str = 'ACTIVE'
    intelligence_summary: Optional[dict] = None

class CampaignCreate(CampaignBase):
    pass

class CampaignResponse(CampaignBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class CampaignGraphNode(BaseModel):
    id: str
    type: str
    label: str

class CampaignGraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    confidence: float
    signals: Optional[list] = None

class CampaignGraph(BaseModel):
    nodes: List[CampaignGraphNode]
    edges: List[CampaignGraphEdge]

class CampaignDetailResponse(CampaignResponse):
    graph: Optional[CampaignGraph] = None
