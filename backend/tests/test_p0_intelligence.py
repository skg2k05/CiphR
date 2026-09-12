import pytest
from datetime import datetime
from sqlalchemy.future import select
from app.db.models import Sample, Analysis, Campaign, sample_campaign_links
from app.services.correlation_service import run_correlation
from tests.conftest import TestingSessionLocal

@pytest.fixture
async def db_session():
    async with TestingSessionLocal() as session:
        yield session

@pytest.mark.asyncio
async def test_p0_sample_and_campaign_intelligence(async_client, db_session):
    # Setup two correlated samples with same certificate
    cert_hash = "test_cert_fingerprint_1234567890abcdef"
    s1 = Sample(id="p0_s1", filename="sample1.apk", sha256="hash111", created_at=datetime(2026, 9, 12, 10, 0, 0))
    s2 = Sample(id="p0_s2", filename="sample2.apk", sha256="hash222", created_at=datetime(2026, 9, 12, 10, 5, 0))
    
    a1 = Analysis(
        sample=s1,
        status="COMPLETED",
        package_name="com.example.fraud1",
        app_name="Fraud App 1",
        certificate_fingerprint=cert_hash,
        permissions=["android.permission.INTERNET", "android.permission.SEND_SMS"],
        providers=["com.example.fraud1.Provider"],
        activities=["com.example.fraud1.MainActivity"],
        certificate_details={"issuer": "CN=Android Debug", "is_debug": True},
        risk_score=40,
        risk_factors=[{"indicator": "android.permission.SEND_SMS", "weight": 25}],
        completed_at=datetime(2026, 9, 12, 10, 1, 0)
    )
    a2 = Analysis(
        sample=s2,
        status="COMPLETED",
        package_name="com.example.fraud2",
        app_name="Fraud App 2",
        certificate_fingerprint=cert_hash,
        permissions=["android.permission.INTERNET", "android.permission.READ_SMS"],
        providers=[],
        activities=["com.example.fraud2.MainActivity"],
        certificate_details={"issuer": "CN=Android Debug", "is_debug": True},
        risk_score=35,
        risk_factors=[{"indicator": "android.permission.READ_SMS", "weight": 25}],
        completed_at=datetime(2026, 9, 12, 10, 6, 0)
    )
    
    db_session.add_all([s1, s2, a1, a2])
    await db_session.commit()
    
    # 1. Correlate s2 (s1 was existing)
    await run_correlation("p0_s2", db_session)
    
    # 2. Test Idempotency - running correlation again must not duplicate links
    await run_correlation("p0_s2", db_session)
    
    # 3. Test GET /samples/{sample_id}
    res_s1 = await async_client.get("/api/v1/samples/p0_s1")
    assert res_s1.status_code == 200
    data_s1 = res_s1.json()
    assert data_s1["analysis"]["permissions"] == ["android.permission.INTERNET", "android.permission.SEND_SMS"]
    assert data_s1["analysis"]["providers"] == ["com.example.fraud1.Provider"]
    assert data_s1["analysis"]["certificate_details"]["is_debug"] is True
    assert len(data_s1["campaigns"]) == 1
    assert data_s1["related_sample_count"] == 1
    assert data_s1["related_samples"][0]["sample_id"] == "p0_s2"
    assert data_s1["related_samples"][0]["relationship"] == "same_certificate"
    
    # 4. Test GET /samples/{sample_id}/related
    res_rel = await async_client.get("/api/v1/samples/p0_s1/related")
    assert res_rel.status_code == 200
    data_rel = res_rel.json()
    assert data_rel["total"] == 1
    assert data_rel["items"][0]["sample_id"] == "p0_s2"
    assert data_rel["items"][0]["filename"] == "sample2.apk"
    
    # Get campaign ID
    campaign_id = data_s1["campaigns"][0]["id"]
    
    # 5. Test GET /campaigns
    res_camps = await async_client.get("/api/v1/campaigns")
    assert res_camps.status_code == 200
    camps_data = res_camps.json()
    assert camps_data["total"] >= 1
    camp_item = next(c for c in camps_data["items"] if c["id"] == campaign_id)
    assert camp_item["sample_count"] == 2
    assert camp_item["first_seen"] is not None
    assert camp_item["last_seen"] is not None
    
    # 6. Test GET /campaigns/{campaign_id}/graph
    res_graph = await async_client.get(f"/api/v1/campaigns/{campaign_id}/graph")
    assert res_graph.status_code == 200
    graph_data = res_graph.json()
    
    node_types = {n["type"] for n in graph_data["nodes"]}
    assert "campaign" in node_types
    assert "sample" in node_types
    assert "certificate" in node_types
    
    # Verify Certificate node exists and contains metadata
    cert_nodes = [n for n in graph_data["nodes"] if n["type"] == "certificate"]
    assert len(cert_nodes) == 1
    assert cert_nodes[0]["metadata"]["fingerprint"] == cert_hash
    
    # Verify edges contain signed_by
    relationships = {e["relationship"] for e in graph_data["edges"]}
    assert "signed_by" in relationships
    assert "same_certificate" in relationships
    
    # 7. Test GET /campaigns/{campaign_id}/timeline
    res_timeline = await async_client.get(f"/api/v1/campaigns/{campaign_id}/timeline")
    assert res_timeline.status_code == 200
    timeline_data = res_timeline.json()
    assert timeline_data["campaign_id"] == campaign_id
    assert timeline_data["total_events"] >= 4
    
    event_types = [e["event_type"] for e in timeline_data["events"]]
    assert "campaign_detected" in event_types
    assert "sample_uploaded" in event_types
    assert "analysis_completed" in event_types
    assert "campaign_correlation" in event_types
    
    # Clean up test records
    await db_session.delete(s1)
    await db_session.delete(s2)
    camp_to_del = await db_session.execute(select(Campaign).filter(Campaign.id == campaign_id))
    camp_obj = camp_to_del.scalars().first()
    if camp_obj:
        await db_session.delete(camp_obj)
    await db_session.commit()
