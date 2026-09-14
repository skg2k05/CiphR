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
    assert rule['mitre_technique_id'] == 'T1626.001'

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

def test_extended_indicator_rules():
    """Verify new high-risk fraud indicators are registered with valid MITRE ATT&CK Mobile mappings."""
    assert 'android.permission.REQUEST_INSTALL_PACKAGES' in INDICATOR_RULES
    assert INDICATOR_RULES['android.permission.REQUEST_INSTALL_PACKAGES']['mitre_technique_id'] == 'T1476'

    assert 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE' in INDICATOR_RULES
    assert INDICATOR_RULES['android.permission.BIND_NOTIFICATION_LISTENER_SERVICE']['mitre_technique_id'] == 'T1517'

    assert 'android.permission.QUERY_ALL_PACKAGES' in INDICATOR_RULES
    assert INDICATOR_RULES['android.permission.QUERY_ALL_PACKAGES']['mitre_technique_id'] == 'T1418'


def test_real_apk_static_analysis():
    """Verify static analysis on a real APK extracts package, components, cert, and indicators."""
    from app.services.apk_analysis_service import analyze_apk_static
    result = analyze_apk_static("tests/fixtures/ApiDemos-debug.apk", None)

    assert result["status"] == "COMPLETED"
    assert result["package_name"] == "io.appium.android.apis"
    assert len(result["activities"]) > 0
    assert len(result["services"]) > 0
    assert len(result["receivers"]) > 0
    assert len(result["providers"]) > 0
    assert result["certificate_fingerprint"] is not None
    assert result["risk_score"] >= 0
    assert len(result["risk_factors"]) > 0


def test_malformed_apk_handling():
    """Verify analysis fails gracefully without crashing when an invalid file is parsed."""
    from app.services.apk_analysis_service import analyze_apk_static
    result = analyze_apk_static("tests/fixtures/dummy.apk", None)
    assert result["status"] == "FAILED"
    assert "error_message" in result

