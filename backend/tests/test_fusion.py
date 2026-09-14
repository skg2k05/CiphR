import pytest
from app.fusion.evidence import (
    EvidenceLedger,
    EvidenceItem,
    EvidenceSource,
    EvidenceAvailability,
    EvidenceType
)
from app.fusion.engine import evaluate_ledger, FusionStatus


def test_scenario_a_ember_unavailable():
    """
    SCENARIO A: EMBER UNAVAILABLE
    Missing evidence is NOT negative evidence.
    """
    ledger = EvidenceLedger(sample_id="test_a")
    
    # EMBER missing/failed
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.EMBER,
        availability=EvidenceAvailability.UNAVAILABLE,
        indicator="EMBER Unavailable",
        semantics="EMBER model file missing or unreachable"
    ))
    
    # Static is neutral
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.STATIC,
        evidence_type=EvidenceType.NEUTRAL,
        indicator="No suspicious APIs",
        strength=0.1
    ))
    
    result = evaluate_ledger(ledger)
    
    assert "EMBER evidence is missing or unavailable." in result.missing_critical_evidence
    assert result.status == FusionStatus.INSUFFICIENT
    assert len(result.conflicts) == 0


def test_scenario_b_ember_static_corroboration():
    """
    SCENARIO B: EMBER + STATIC CORROBORATION
    Both positive, should produce corroborated cluster.
    """
    ledger = EvidenceLedger(sample_id="test_b")
    
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.EMBER,
        evidence_type=EvidenceType.POSITIVE,
        indicator="High model score",
        value=0.96,
        strength=0.9,
        reliability=0.9
    ))
    
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.STATIC,
        evidence_type=EvidenceType.POSITIVE,
        indicator="Suspicious dynamic loading",
        strength=0.7,
        reliability=0.8
    ))
    
    result = evaluate_ledger(ledger)
    
    assert result.status == FusionStatus.CORROBORATED
    assert len(result.corroborated_clusters) == 1
    cluster = result.corroborated_clusters[0]
    assert "EMBER" in cluster["sources"]
    assert "STATIC" in cluster["sources"]


def test_scenario_c_multi_source_corroboration():
    """
    SCENARIO C: MULTI-SOURCE CORROBORATION
    EMBER, TLSH, VT, STATIC all positive.
    """
    ledger = EvidenceLedger(sample_id="test_c")
    
    for src in [EvidenceSource.EMBER, EvidenceSource.STATIC, EvidenceSource.VT, EvidenceSource.TLSH]:
        ledger.add_evidence(EvidenceItem(
            source=src,
            evidence_type=EvidenceType.POSITIVE,
            indicator=f"Malicious finding from {src.value}",
            strength=0.85
        ))
        
    result = evaluate_ledger(ledger)
    
    assert result.status == FusionStatus.CORROBORATED
    assert len(result.corroborated_clusters) == 1
    assert len(result.corroborated_clusters[0]["sources"]) == 4


def test_scenario_d_conflict():
    """
    SCENARIO D: CONFLICT
    EMBER says malicious (high strength), VT says benign (high strength).
    """
    ledger = EvidenceLedger(sample_id="test_d")
    
    # High confidence malicious
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.EMBER,
        evidence_type=EvidenceType.POSITIVE,
        indicator="High model score",
        strength=0.95
    ))
    
    # High confidence benign
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.VT,
        evidence_type=EvidenceType.NEGATIVE,
        indicator="0/70 detections",
        strength=0.95
    ))
    
    result = evaluate_ledger(ledger)
    
    assert result.status == FusionStatus.CONFLICTED
    assert len(result.conflicts) == 1
    assert "EMBER" in result.conflicts[0]["positive_sources"]
    assert "VT" in result.conflicts[0]["negative_sources"]


def test_moderate_negative_conflict():
    """
    Ensures that a moderate negative evidence is not silently discarded
    just because the positive evidence is much stronger.
    """
    ledger = EvidenceLedger(sample_id="test_mod_conflict")
    
    # Strong positive
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.EMBER,
        evidence_type=EvidenceType.POSITIVE,
        indicator="Extremely high model score",
        strength=0.99
    ))
    
    # Moderate negative
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.STATIC,
        evidence_type=EvidenceType.NEGATIVE,
        indicator="Known good developer certificate",
        strength=0.60
    ))
    
    result = evaluate_ledger(ledger)
    
    assert result.status == FusionStatus.CONFLICTED
    assert len(result.conflicts) == 1
    assert "EMBER" in result.conflicts[0]["positive_sources"]
    assert "STATIC" in result.conflicts[0]["negative_sources"]


def test_scenario_e_ember_failure_other_evidence():
    """
    SCENARIO E: EMBER FAILURE + OTHER EVIDENCE
    EMBER fails gracefully, but Static and VT are sufficient to convict.
    """
    ledger = EvidenceLedger(sample_id="test_e")
    
    # EMBER fails
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.EMBER,
        availability=EvidenceAvailability.FAILED,
        indicator="EMBER failed",
        semantics="Out of memory during inference"
    ))
    
    # Static and VT positive
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.STATIC,
        evidence_type=EvidenceType.POSITIVE,
        indicator="Suspicious SMS permissions",
        strength=0.7
    ))
    ledger.add_evidence(EvidenceItem(
        source=EvidenceSource.VT,
        evidence_type=EvidenceType.POSITIVE,
        indicator="35/70 detections",
        strength=0.9
    ))
    
    result = evaluate_ledger(ledger)
    
    # Ensure failure is recorded but doesn't block evaluation
    failure_msg = next((msg for msg in result.missing_critical_evidence if "EMBER provider failed" in msg), None)
    assert failure_msg is not None
    
    # We still have independent positive evidence
    assert result.status == FusionStatus.CORROBORATED
    assert len(result.corroborated_clusters) == 1
    assert "STATIC" in result.corroborated_clusters[0]["sources"]
    assert "VT" in result.corroborated_clusters[0]["sources"]


def test_double_counting_prevention():
    """
    Ensures that derived evidence doesn't count as independent corroboration.
    e.g. LLM says malicious purely based on Static evidence.
    """
    ledger = EvidenceLedger(sample_id="test_double_count")
    
    static_item = EvidenceItem(
        source=EvidenceSource.STATIC,
        evidence_type=EvidenceType.POSITIVE,
        indicator="Hardcoded IP",
        strength=0.6
    )
    
    llm_item = EvidenceItem(
        source=EvidenceSource.LLM,
        evidence_type=EvidenceType.POSITIVE,
        indicator="LLM interprets Hardcoded IP as malicious",
        strength=0.6,
        derived_from=[static_item.evidence_id]
    )
    
    ledger.add_evidence(static_item)
    ledger.add_evidence(llm_item)
    
    result = evaluate_ledger(ledger)
    
    # Because LLM derived from Static, there's only 1 independent source
    assert result.status == FusionStatus.UNRESOLVED
    assert len(result.corroborated_clusters) == 0

