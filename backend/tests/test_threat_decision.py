import pytest
from datetime import datetime, timezone
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, MagicMock

from app.db.models import Sample, Analysis, Finding, Campaign
from app.services.threat_decision_service import build_threat_decision
from app.schemas.threat_decision import (
    ThreatClassification,
    ConfidenceLevel,
    NoveltyStatus,
    ImpactLevel,
    AccessScope,
    CampaignStatus,
    ThreatType,
    RecommendedAction
)

def _create_base_sample():
    sample = Sample(
        id=str(uuid.uuid4()),
        filename="test.apk",
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        status="COMPLETED",
        source="upload",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    return sample

def _create_mock_db(links_data=None, related_ids=None):
    if links_data is None: links_data = []
    if related_ids is None: related_ids = []
    
    db = AsyncMock(spec=AsyncSession)
    
    # First call is for links (returns objects with .signals)
    mock_links_result = MagicMock()
    mock_links = []
    for link in links_data:
        mock_row = MagicMock()
        mock_row.signals = link.get("signals", [])
        mock_links.append(mock_row)
    mock_links_result.all.return_value = mock_links
    
    # Second call is for related sample ids (returns tuples/rows with index 0)
    mock_related_result = MagicMock()
    mock_related = [[rid] for rid in related_ids]
    mock_related_result.all.return_value = mock_related
    
    db.execute.side_effect = [mock_links_result, mock_related_result]
    return db

@pytest.mark.asyncio
async def test_malicious_high_risk_sample():
    sample = _create_base_sample()
    db = _create_mock_db()
    
    sample.analysis = Analysis(
        sample_id=sample.id,
        status="COMPLETED",
        risk_score=95,
        tlsh="T123456",
        threat_narrative="EMBER detects this as highly malicious"
    )
    
    sample.findings = [
        Finding(
            id=str(uuid.uuid4()),
            sample_id=sample.id,
            title="Uses Accessibility Services",
            description="May abuse accessibility to perform clicks.",
            severity="CRITICAL",
            category="permissions"
        ),
        Finding(
            id=str(uuid.uuid4()),
            sample_id=sample.id,
            title="Connects to known C2",
            description="Contacted 1.2.3.4",
            severity="HIGH",
            category="network"
        )
    ]
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.classification == ThreatClassification.MALICIOUS
    assert decision.risk_score == 95
    assert decision.confidence == ConfidenceLevel.HIGH
    assert decision.impact == ImpactLevel.HIGH
    assert decision.access_scope == AccessScope.FULL_DEVICE
    assert ThreatType.ACCESSIBILITY_ABUSE in decision.threat_types
    assert decision.recommended_action == RecommendedAction.BLOCK
    assert len(decision.evidence) == 3

@pytest.mark.asyncio
async def test_benign_sample():
    sample = _create_base_sample()
    db = _create_mock_db()
    sample.analysis = Analysis(
        sample_id=sample.id,
        status="COMPLETED",
        risk_score=10,
        tlsh="T654321"
    )
    sample.findings = [
        Finding(
            id=str(uuid.uuid4()),
            sample_id=sample.id,
            title="Uses Internet",
            description="Normal internet access",
            severity="INFO",
            category="permissions"
        )
    ]
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.classification == ThreatClassification.BENIGN
    assert decision.confidence == ConfidenceLevel.LOW
    assert decision.impact == ImpactLevel.LOW
    assert decision.access_scope == AccessScope.NETWORK_ONLY
    assert decision.recommended_action == RecommendedAction.ALLOW

@pytest.mark.asyncio
async def test_campaign_matched_sample():
    sample = _create_base_sample()
    db = _create_mock_db()
    sample.analysis = Analysis(
        sample_id=sample.id,
        status="COMPLETED",
        risk_score=85,
        tlsh="T111111"
    )
    
    # Mock campaign
    mock_campaign = Campaign(
        id=str(uuid.uuid4()), 
        name="TestCampaign",
        intelligence_summary={"common_indicators": {"ips": ["1.1.1.1"]}}
    )
    sample.campaigns = [mock_campaign]
    
    # we need the second call to db.execute to return related_ids
    db = _create_mock_db(links_data=[], related_ids=["sample2", "sample3", "sample2"])
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.classification == ThreatClassification.MALICIOUS
    assert decision.campaign.status == CampaignStatus.MATCHED
    assert decision.campaign.related_samples_count == 2 # deduplicated
    assert decision.campaign.related_sample_ids == ["sample2", "sample3"]
    assert decision.campaign.intelligence == {"common_indicators": {"ips": ["1.1.1.1"]}}
    
    # Novelty should correctly map related_samples
    assert decision.novelty.status == NoveltyStatus.VARIANT
    assert decision.novelty.related_samples == ["sample2", "sample3"]
    assert decision.confidence == ConfidenceLevel.HIGH

@pytest.mark.asyncio
async def test_missing_evidence():
    sample = _create_base_sample()
    db = _create_mock_db()
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.classification == ThreatClassification.UNKNOWN
    assert decision.confidence == ConfidenceLevel.UNKNOWN
    assert decision.impact == ImpactLevel.UNKNOWN
    assert decision.access_scope == AccessScope.UNKNOWN
    assert decision.campaign.status == CampaignStatus.UNKNOWN
    assert len(decision.evidence) == 0

@pytest.mark.asyncio
async def test_impact_and_access_scope_mapping():
    sample = _create_base_sample()
    db = _create_mock_db()
    sample.analysis = Analysis(risk_score=50, status="COMPLETED")
    sample.findings = [
        Finding(
            id="1", sample_id=sample.id,
            title="Uses Camera", description="Takes pictures",
            severity="HIGH", category="permissions"
        ),
        Finding(
            id="2", sample_id=sample.id,
            title="Runs in background", description="Background service",
            severity="MEDIUM", category="service"
        )
    ]
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.classification == ThreatClassification.SUSPICIOUS
    assert decision.impact == ImpactLevel.MEDIUM
    assert decision.access_scope == AccessScope.SENSITIVE_SUBSYSTEM
    assert ThreatType.SURVEILLANCE in decision.threat_types
    assert decision.recommended_action == RecommendedAction.INVESTIGATE

@pytest.mark.asyncio
async def test_provenance_mapping():
    sample = _create_base_sample()
    db = _create_mock_db()
    sample.source = "url|https://example.com/malware.apk"
    sample.analysis = Analysis(started_at=datetime(2025, 1, 1, tzinfo=timezone.utc))
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.provenance.source_type == "url"
    assert decision.provenance.source_url == "https://example.com/malware.apk"
    assert decision.provenance.sha256 == sample.sha256
    assert decision.provenance.analysis_timestamp == sample.analysis.started_at
