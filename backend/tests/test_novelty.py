import pytest
from datetime import datetime, timedelta, timezone
import uuid
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Sample, Analysis, Finding
from app.services.threat_decision_service import build_threat_decision
from app.schemas.threat_decision import NoveltyStatus, ThreatClassification

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

def _create_mock_db(links_data=None):
    if links_data is None:
        links_data = []
        
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    
    # Mocking rows for sqlalchemy result
    mock_rows = []
    for link in links_data:
        mock_row = MagicMock()
        mock_row.signals = link.get("signals", [])
        mock_rows.append(mock_row)
        
    mock_result.all.return_value = mock_rows
    db.execute.return_value = mock_result
    return db

@pytest.mark.asyncio
async def test_novelty_exact_sha256_known():
    sample = _create_base_sample()
    
    db = _create_mock_db(links_data=[
        {
            "signals": [{"type": "exact_sha256", "evidence": "simulated_historical_match"}]
        }
    ])
    decision = await build_threat_decision(sample, db)
    
    assert decision.novelty.status == NoveltyStatus.KNOWN
    assert any(s.type == "SHA256" and s.state == "KNOWN" for s in decision.novelty.signals)
    assert "Exact SHA256 match" in decision.novelty.explanation

@pytest.mark.asyncio
async def test_novelty_tlsh_variant():
    sample = _create_base_sample()
    sample.analysis = Analysis(tlsh="T1234")
    
    db = _create_mock_db(links_data=[
        {
            "signals": [{"type": "tlsh_similarity", "evidence": "diff:25"}]
        }
    ])
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.novelty.status == NoveltyStatus.VARIANT
    assert any(s.type == "TLSH_SIMILARITY" and s.state == "STRONG" and s.distance == 25 for s in decision.novelty.signals)
    assert any(s.type == "SHA256" and s.state == "UNSEEN" for s in decision.novelty.signals)

@pytest.mark.asyncio
async def test_novelty_shared_cert():
    sample = _create_base_sample()
    
    db = _create_mock_db(links_data=[
        {
            "signals": [{"type": "same_certificate", "evidence": "mockcert"}]
        }
    ])
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.novelty.status == NoveltyStatus.VARIANT
    assert any(s.type == "CERTIFICATE" and s.state == "KNOWN" for s in decision.novelty.signals)

@pytest.mark.asyncio
async def test_novelty_shared_domain():
    sample = _create_base_sample()
    
    db = _create_mock_db(links_data=[
        {
            "signals": [{"type": "shared_domain", "evidence": "evil.com"}]
        }
    ])
    
    # Wait, shared_domain does NOT trigger VARIANT by itself, 
    # it only triggers DOMAIN signal which prevents POTENTIALLY_NOVEL.
    # Ah, let's check the logic: 
    # elif has_tlsh_similarity or has_cert_match or camp_status == CampaignStatus.MATCHED: VARIANT
    # So shared domain alone -> UNKNOWN. Let's verify this.
    decision = await build_threat_decision(sample, db)
    
    assert decision.novelty.status == NoveltyStatus.UNKNOWN
    assert any(s.type == "DOMAIN" and s.state == "KNOWN" for s in decision.novelty.signals)

@pytest.mark.asyncio
async def test_novelty_potentially_novel():
    sample = _create_base_sample()
    sample.analysis = Analysis(risk_score=90) # High risk
    
    sample.findings = [
        Finding(
            id=str(uuid.uuid4()),
            sample_id=sample.id,
            category="network",
            title="Connects to a new domain",
            severity="HIGH"
        ),
        Finding(
            id=str(uuid.uuid4()),
            sample_id=sample.id,
            category="permissions",
            title="Requests sensitive permissions",
            severity="HIGH"
        )
    ]
    
    db = _create_mock_db() # No historical relationships
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.classification == ThreatClassification.MALICIOUS
    assert decision.novelty.status == NoveltyStatus.POTENTIALLY_NOVEL
    assert any(s.type == "SHA256" and s.state == "UNSEEN" for s in decision.novelty.signals)

@pytest.mark.asyncio
async def test_novelty_insufficient_evidence():
    sample = _create_base_sample()
    sample.analysis = Analysis(risk_score=20) # Low risk
    db = _create_mock_db()
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.novelty.status == NoveltyStatus.UNKNOWN
    # SHA256 is UNSEEN, but no multiple newness signals, no strong correlation
    
@pytest.mark.asyncio
async def test_novelty_missing_not_negative():
    sample = _create_base_sample()
    # Explicitly lacking tlsh
    sample.analysis = Analysis(risk_score=50, tlsh=None)
    db = _create_mock_db()
    
    decision = await build_threat_decision(sample, db)
    
    # Check that missing TLSH translates to MISSING, not UNSEEN or something else
    tlsh_signal = next((s for s in decision.novelty.signals if s.type == "TLSH_SIMILARITY"), None)
    assert tlsh_signal is not None
    assert tlsh_signal.state == "MISSING"

@pytest.mark.asyncio
async def test_novelty_url_provenance():
    sample = _create_base_sample()
    sample.source = "url|https://evil-apk.com/download/malware.apk"
    db = _create_mock_db()
    
    decision = await build_threat_decision(sample, db)
    
    assert decision.provenance.source_type == "url"
    assert decision.provenance.source_url == "https://evil-apk.com/download/malware.apk"
