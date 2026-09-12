from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.fusion.evidence import (
    EvidenceLedger, 
    EvidenceItem, 
    EvidenceSource, 
    EvidenceType, 
    EvidenceAvailability
)


class FusionStatus(str, Enum):
    CORROBORATED = "CORROBORATED"
    CONFLICTED = "CONFLICTED"
    INSUFFICIENT = "INSUFFICIENT"
    UNRESOLVED = "UNRESOLVED"
    NEGATIVE_EVIDENCE_FOUND = "NEGATIVE_EVIDENCE_FOUND"


class FusionResult(BaseModel):
    """
    The result of reasoning over an EvidenceLedger.
    """
    status: FusionStatus = FusionStatus.INSUFFICIENT
    corroborated_clusters: List[Dict[str, Any]] = Field(default_factory=list)
    conflicts: List[Dict[str, Any]] = Field(default_factory=list)
    missing_critical_evidence: List[str] = Field(default_factory=list)
    explanation: str = ""


def _is_derived_from(item_a: EvidenceItem, item_b: EvidenceItem) -> bool:
    """Check if item_a is derived from item_b (double-counting prevention)."""
    return item_b.evidence_id in item_a.derived_from


def evaluate_ledger(ledger: EvidenceLedger) -> FusionResult:
    """
    Evaluates the evidence ledger to identify corroboration, conflicts, 
    and missing evidence without assigning arbitrary numerical weights or verdicts.
    """
    available_items = ledger.get_available()
    
    # Track missing providers
    expected_sources = {EvidenceSource.STATIC, EvidenceSource.EMBER, EvidenceSource.TLSH, EvidenceSource.VT}
    found_sources = {item.source for item in available_items}
    
    # 1. Missing Evidence Identification
    missing_sources = expected_sources - found_sources
    missing_critical = []
    
    for src in missing_sources:
        missing_critical.append(f"{src.value} evidence is missing or unavailable.")
    
    for item in ledger.evidence:
        if item.availability == EvidenceAvailability.FAILED:
            missing_critical.append(f"{item.source.value} provider failed: {item.semantics}")
            
    # 2. Extract and deduplicate positive/negative signals
    positive_items = [i for i in available_items if i.evidence_type == EvidenceType.POSITIVE]
    negative_items = [i for i in available_items if i.evidence_type == EvidenceType.NEGATIVE]
    
    # Prevent double-counting in positive items
    deduped_positives = []
    for item in positive_items:
        # Check if item derives from ANY other positive item.
        is_derived = any(_is_derived_from(item, other) for other in positive_items if other != item)
        if not is_derived:
            deduped_positives.append(item)
            
    # 3. Detect Corroboration
    corroborated_clusters = []
    
    # Structural corroboration: Multiple independent positive sources
    independent_positive_sources = {item.source for item in deduped_positives}
    if len(independent_positive_sources) > 1:
        cluster = {
            "type": "MALICIOUS_CORROBORATION",
            "sources": [s.value for s in independent_positive_sources],
            "evidence_ids": [item.evidence_id for item in deduped_positives]
        }
        corroborated_clusters.append(cluster)

    # 4. Detect Conflict
    conflicts = []
    
    # Any positive vs any negative is a conflict, regardless of numeric strength.
    # We preserve both sides of the conflict.
    if deduped_positives and negative_items:
        conflicts.append({
            "type": "POSITIVE_VS_NEGATIVE",
            "description": "Conflicting evidence detected. Both positive and negative indicators are present.",
            "positive_sources": [i.source.value for i in deduped_positives],
            "negative_sources": [i.source.value for i in negative_items]
        })
        
    # 5. Resolve Final Structural Status
    status = FusionStatus.INSUFFICIENT
    explanation = "Not enough independent evidence to draw a conclusion."
    
    if conflicts:
        status = FusionStatus.CONFLICTED
        explanation = "Conflicting evidence detected. Resolution requires manual review or higher-order logic."
    elif len(independent_positive_sources) > 1:
        status = FusionStatus.CORROBORATED
        explanation = f"Corroborated positive evidence from {len(independent_positive_sources)} independent sources."
    elif len(independent_positive_sources) == 1:
        status = FusionStatus.UNRESOLVED
        explanation = "Single positive source found; lacks structural corroboration."
    elif len(negative_items) > 0 and not positive_items:
        status = FusionStatus.NEGATIVE_EVIDENCE_FOUND
        explanation = "Negative indicators found with no positive evidence."
    
    return FusionResult(
        status=status,
        corroborated_clusters=corroborated_clusters,
        conflicts=conflicts,
        missing_critical_evidence=missing_critical,
        explanation=explanation
    )
