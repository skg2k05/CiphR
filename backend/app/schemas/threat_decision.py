from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime

class ThreatClassification(str, Enum):
    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"

class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class NoveltyStatus(str, Enum):
    KNOWN = "KNOWN"
    VARIANT = "VARIANT"
    POTENTIALLY_NOVEL = "POTENTIALLY_NOVEL"
    UNKNOWN = "UNKNOWN"

class ThreatType(str, Enum):
    BANKING_TROJAN = "BANKING_TROJAN"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    SMS_ABUSE = "SMS_ABUSE"
    ACCESSIBILITY_ABUSE = "ACCESSIBILITY_ABUSE"
    OVERLAY = "OVERLAY"
    SURVEILLANCE = "SURVEILLANCE"
    PERSISTENCE = "PERSISTENCE"
    C2 = "C2"
    UNKNOWN = "UNKNOWN"

class ImpactLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class AccessScope(str, Enum):
    FULL_DEVICE = "FULL_DEVICE"
    SENSITIVE_SUBSYSTEM = "SENSITIVE_SUBSYSTEM"
    USER_DATA = "USER_DATA"
    BACKGROUND_ONLY = "BACKGROUND_ONLY"
    NETWORK_ONLY = "NETWORK_ONLY"
    UNKNOWN = "UNKNOWN"

class CampaignStatus(str, Enum):
    MATCHED = "MATCHED"
    NEW = "NEW"
    UNKNOWN = "UNKNOWN"

class RecommendedAction(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    INVESTIGATE = "INVESTIGATE"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"

class EvidenceItemResponse(BaseModel):
    source: str
    finding: str
    severity: Optional[str] = None
    provenance: Optional[Dict[str, Any]] = None
    material_contribution: bool = False

    model_config = ConfigDict(from_attributes=True)

class NoveltySignal(BaseModel):
    type: str  # e.g., "SHA256", "TLSH_SIMILARITY", "CERTIFICATE", "CAMPAIGN", "DOMAIN"
    state: str # e.g., "UNSEEN", "KNOWN", "STRONG", "MATCHED"
    distance: Optional[int] = None
    related_sample_id: Optional[str] = None
    related_sample_count: Optional[int] = None
    campaign_id: Optional[str] = None

class NoveltyInfo(BaseModel):
    status: NoveltyStatus = NoveltyStatus.UNKNOWN
    signals: List[NoveltySignal] = []
    related_samples: List[str] = []
    explanation: str = "Insufficient evidence to determine novelty."

class CampaignInfo(BaseModel):
    status: CampaignStatus = CampaignStatus.UNKNOWN
    identifier: Optional[str] = None
    related_samples_count: int = 0
    related_sample_ids: List[str] = []
    intelligence: Optional[Dict[str, Any]] = None

class ProvenanceInfo(BaseModel):
    source_type: str = "upload"
    source_url: Optional[str] = None
    sha256: str
    analysis_timestamp: Optional[datetime] = None

class ThreatDecisionResponse(BaseModel):
    classification: ThreatClassification
    risk_score: Optional[int] = None
    risk_status: Optional[str] = None
    confidence: ConfidenceLevel
    novelty: NoveltyInfo
    threat_types: List[ThreatType]
    impact: ImpactLevel
    access_scope: AccessScope
    campaign: CampaignInfo
    evidence: List[EvidenceItemResponse]
    recommended_action: RecommendedAction
    provenance: ProvenanceInfo

    model_config = ConfigDict(from_attributes=True)
