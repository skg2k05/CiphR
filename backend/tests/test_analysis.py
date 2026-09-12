import pytest
from app.services.apk_analysis_service import INDICATOR_RULES
from app.services.correlation_service import run_correlation
from app.db.models import Sample, Analysis, Campaign, sample_campaign_links
from sqlalchemy.future import select
from sqlalchemy import text
from tests.conftest import TestingSessionLocal

@pytest.fixture
async def db_session():
    async with TestingSessionLocal() as session:
        yield session

def test_indicator_rules():
    assert 'android.permission.BIND_DEVICE_ADMIN' in INDICATOR_RULES
    rule = INDICATOR_RULES['android.permission.BIND_DEVICE_ADMIN']
    assert rule['weight'] == 50
    assert rule['mitre_technique_id'] == 'T1624'

@pytest.mark.asyncio
async def test_run_correlation_shared_indicator(db_session):
    # Setup test data
    s1 = Sample(id="s1", filename="a.apk", sha256="123")
    s2 = Sample(id="s2", filename="b.apk", sha256="456")
    
    a1 = Analysis(
        sample=s1,
        status="COMPLETED",
        risk_score=50,
        risk_factors=[{"indicator": "android.permission.BIND_DEVICE_ADMIN", "weight": 50}],
        dex_data={
            "domains": [{"indicator": "evil.com"}],
            "hardcoded_ips": [{"indicator": "8.8.8.8"}],
            "suspicious_apis": [{"api": "java.lang.Runtime"}]
        }
    )
    a2 = Analysis(
        sample=s2,
        status="COMPLETED",
        risk_score=70,
        risk_factors=[{"indicator": "android.permission.BIND_DEVICE_ADMIN", "weight": 50}],
        dex_data={
            "domains": [{"indicator": "evil.com"}],
            "hardcoded_ips": [{"indicator": "8.8.8.8"}],
            "suspicious_apis": [{"api": "java.lang.Runtime"}]
        }
    )
    
    db_session.add_all([s1, s2, a1, a2])
    await db_session.commit()
    
    # Run correlation on s2
    await run_correlation("s2", db_session)
    
    # Assert
    # They should be linked via multi_signal because they share domain, ip, api, and indicator
    result = await db_session.execute(select(sample_campaign_links))
    links = result.all()
    
    assert len(links) == 2
    assert links[0].relationship == "multi_signal"
    # base confidence should be 0.8 (shared domain/ip), and bumped up due to multiple signals
    assert links[0].confidence > 0.8
    assert links[0].confidence <= 0.95
    assert len(links[0].signals) == 4 # shared domain, shared ip, shared api, shared indicator
    
    # Check Campaign Intelligence Recalculation
    campaigns_result = await db_session.execute(select(Campaign))
    campaign = campaigns_result.scalars().first()
    
    assert campaign.risk_score == 70
    assert campaign.severity in ["HIGH", "CRITICAL", "MEDIUM"] 
    # High risk is 70, so severity should be HIGH
    assert campaign.severity == "HIGH"
    
    summary = campaign.intelligence_summary
    assert summary["num_samples"] == 2
    assert summary["highest_risk"] == 70
    assert summary["average_risk"] == 60.0
    
    common = summary["common_indicators"]
    assert "evil.com" in common["domains"]
    assert "8.8.8.8" in common["ips"]
    assert "java.lang.Runtime" in common["apis"]
    
    # Cleanup for other tests
    await db_session.execute(text("DELETE FROM sample_campaign_links"))
    await db_session.execute(text("DELETE FROM findings"))
    await db_session.execute(text("DELETE FROM analyses"))
    await db_session.execute(text("DELETE FROM campaigns"))
    await db_session.execute(text("DELETE FROM samples"))
    await db_session.commit()
