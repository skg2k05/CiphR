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
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sample_count: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

class CampaignGraphNode(BaseModel):
    id: str
    type: str
    label: str
    metadata: Optional[dict] = None

class CampaignGraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    confidence: float
    signals: Optional[list] = None

class CampaignGraph(BaseModel):
    nodes: List[CampaignGraphNode]
    edges: List[CampaignGraphEdge]

class CampaignTimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str
    title: str
    description: str
    sample_id: Optional[str] = None
    data: Optional[dict] = None

class CampaignTimelineResponse(BaseModel):
    campaign_id: str
    campaign_name: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_events: int
    events: List[CampaignTimelineEvent] = []

class CampaignDetailResponse(CampaignResponse):
    graph: Optional[CampaignGraph] = None
