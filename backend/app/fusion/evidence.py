from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid
from datetime import datetime, timezone


class EvidenceSource(str, Enum):
    STATIC = "STATIC"
    EMBER = "EMBER"
    TLSH = "TLSH"
    VT = "VT"
    NETWORK = "NETWORK"
    LLM = "LLM"
    CAMPAIGN = "CAMPAIGN"


class EvidenceAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceType(str, Enum):
    POSITIVE = "POSITIVE"  # Malicious/Suspicious
    NEGATIVE = "NEGATIVE"  # Benign/Clean
    NEUTRAL = "NEUTRAL"    # Contextual/Informational


class EvidenceItem(BaseModel):
    """
    Common representation of an independent evidence item.
    """
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: EvidenceSource
    availability: EvidenceAvailability = EvidenceAvailability.AVAILABLE
    evidence_type: EvidenceType = EvidenceType.NEUTRAL
    indicator: str
    value: Any = None
    semantics: str = ""
    
    # 0.0 to 1.0 (How strong is this specific finding inherently?)
    strength: float = 0.0
    
    # 0.0 to 1.0 (How reliable is the source/provenance?)
    reliability: float = 0.0
    
    # Metadata for provenance preservation (e.g. model version, feature version)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Used for grouping correlated evidence (e.g., sharing the same IP)
    correlation_ids: List[str] = Field(default_factory=list)
    
    # To track double-counting (e.g. LLM evidence derived from Static evidence ID)
    derived_from: List[str] = Field(default_factory=list)


class EvidenceLedger(BaseModel):
    """
    A collection of EvidenceItems for a given sample, preserving provenance and conflicts.
    """
    sample_id: str
    evidence: List[EvidenceItem] = Field(default_factory=list)

    def add_evidence(self, item: EvidenceItem):
        self.evidence.append(item)

    def get_by_source(self, source: EvidenceSource) -> List[EvidenceItem]:
        return [e for e in self.evidence if e.source == source]

    def get_available(self) -> List[EvidenceItem]:
        return [e for e in self.evidence if e.availability == EvidenceAvailability.AVAILABLE]

    def get_positive(self) -> List[EvidenceItem]:
        return [e for e in self.get_available() if e.evidence_type == EvidenceType.POSITIVE]
        
    def get_negative(self) -> List[EvidenceItem]:
        return [e for e in self.get_available() if e.evidence_type == EvidenceType.NEGATIVE]
