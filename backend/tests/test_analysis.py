import pytest
from app.services.apk_analysis_service import INDICATOR_RULES
from app.services.correlation_service import run_correlation
from app.db.models import Sample, Analysis, Campaign, sample_campaign_links
from sqlalchemy.future import select
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
        risk_factors=[{"indicator": "android.permission.BIND_DEVICE_ADMIN", "weight": 50}]
    )
    a2 = Analysis(
        sample=s2,
        status="COMPLETED",
        risk_factors=[{"indicator": "android.permission.BIND_DEVICE_ADMIN", "weight": 50}]
    )
    
    db_session.add_all([s1, s2, a1, a2])
    await db_session.commit()
    
    # Run correlation on s2
    await run_correlation("s2", db_session)
    
    # Assert
    # They should be linked via shared_indicator
    result = await db_session.execute(select(sample_campaign_links))
    links = result.all()
    
    # There should be 2 links (s1 to campaign, s2 to campaign)
    assert len(links) == 2
    assert links[0].relationship == "shared_indicator"
    
    # Cleanup for other tests
    await db_session.delete(s1)
    await db_session.delete(s2)
    # The correlation service creates a campaign, we should delete it too
    campaigns_result = await db_session.execute(select(Campaign))
    for campaign in campaigns_result.scalars().all():
        await db_session.delete(campaign)
    await db_session.commit()
