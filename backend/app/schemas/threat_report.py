from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict
from datetime import datetime
from app.schemas.threat_decision import (
    ThreatClassification,
    ConfidenceLevel,
    NoveltyInfo,
    ImpactLevel,
    AccessScope,
    ThreatType,
    RecommendedAction,
    ProvenanceInfo,
    NoveltySignal,
    CampaignInfo,
    AnalysisCoverage
)

class HistoricalContextItem(BaseModel):
    type: str
    evidence: str

class AnalystThreatReportResponse(BaseModel):
    verdict: ThreatClassification
    risk_score: Optional[int] = None
    confidence: ConfidenceLevel
    
    novelty: NoveltyInfo
    
    impact: ImpactLevel
    access_scope: AccessScope
    threat_types: List[ThreatType]
    
    campaign: Optional[CampaignInfo] = None
    
    # "why" is a dictionary of grouped evidence by categories like "STATIC", "NETWORK", "STRUCTURAL", etc.
    why: Dict[str, List[str]]
    
    historical_context: List[HistoricalContextItem] = []
    
    recommended_action: RecommendedAction
    provenance: ProvenanceInfo
    
    analysis_coverage: AnalysisCoverage
    
    deterministic_summary: str

    model_config = ConfigDict(from_attributes=True)
