"""
Integration test for the 10-APK controlled dataset end-to-end pipeline.

Verifies:
- All 10 samples are persisted
- Each receives a completed static analysis
- Risk scores are deterministic and cover varied threat levels (CRITICAL, HIGH/MEDIUM, LOW, SAFE)
- Related samples are identified via real correlation
- Campaigns are created correctly with expected sample counts (2 campaigns of 3 samples each)
- Independent samples have 0 campaign associations and 0 related samples
- Campaign graph contains expected nodes (campaign, sample, certificate) and edges
- Campaign timeline contains expected events (sample_uploaded, analysis_completed, campaign_correlation, campaign_detected)
"""

import io
import pytest
from pathlib import Path
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from fastapi import UploadFile

from tests.fixtures.dataset_builder import build_demo_dataset, FIXTURES_DIR
from tests.conftest import TestingSessionLocal
import app.services.pipeline_service as pipeline_module
from app.services.pipeline_service import process_sample_pipeline
from app.services.upload_service import process_upload
from app.db.models import Sample, Analysis, Campaign, sample_campaign_links

@pytest.fixture(autouse=True)
def patch_pipeline_session(monkeypatch):
    """Ensure background pipeline tasks operate against the in-memory test database."""
    monkeypatch.setattr(pipeline_module, "AsyncSessionLocal", TestingSessionLocal)

@pytest.mark.asyncio
async def test_multi_apk_end_to_end_pipeline(async_client):
    # 1. Build deterministic dataset fixtures
    apk_paths = build_demo_dataset()
    assert len(apk_paths) == 10, "Expected exactly 10 APK fixtures in the dataset"

    # 2. Upload each sample via the upload service into the test database
    sample_ids = []
    async with TestingSessionLocal() as db:
        for p in apk_paths:
            content = p.read_bytes()
            upload = UploadFile(filename=p.name, file=io.BytesIO(content))
            sample = await process_upload(
                upload,
                source="controlled_demo_dataset",
                submitted_by="analyst@ciphr.local",
                db=db
            )
            sample_ids.append(sample.id)

    assert len(sample_ids) == 10

    # 3. Process the pipeline for each sample
    for sid in sample_ids:
        await process_sample_pipeline(sid)

    # 4. Verify all 10 samples are persisted and completed
    async with TestingSessionLocal() as db:
        res = await db.execute(
            select(Sample)
            .options(selectinload(Sample.analysis), selectinload(Sample.campaigns))
        )
        samples = res.scalars().all()
        assert len(samples) == 10

        sample_map = {s.filename: s for s in samples}

        # Verify each sample has a completed analysis
        for name, s in sample_map.items():
            assert s.status == "COMPLETED", f"Sample {name} status is {s.status}"
            assert s.analysis is not None, f"Sample {name} has no analysis"
            assert s.analysis.status == "COMPLETED", f"Analysis for {name} is {s.analysis.status}"

        # 5. Verify deterministic risk scores & categories
        # Group 1: FinSteal (CRITICAL >= 80)
        for name in ["finsteal_v1.apk", "finsteal_v2.apk", "finsteal_v3.apk"]:
            score = sample_map[name].analysis.risk_score
            assert score >= 80, f"Expected FinSteal sample {name} to be CRITICAL (>=80), got {score}"

        # Group 2: AgentSMS (HIGH/MEDIUM >= 40)
        for name in ["agentsms_v1.apk", "agentsms_v2.apk", "agentsms_v3.apk"]:
            score = sample_map[name].analysis.risk_score
            assert 40 <= score < 80, f"Expected AgentSMS sample {name} to be MEDIUM/HIGH, got {score}"

        # Independent Lower-Risk Samples
        assert sample_map["benign_calculator.apk"].analysis.risk_score == 0  # SAFE
        assert sample_map["photo_viewer_pro.apk"].analysis.risk_score <= 15   # SAFE
        assert 20 <= sample_map["system_monitor_test.apk"].analysis.risk_score <= 35  # LOW
        assert 35 <= sample_map["stealth_dropper_lone.apk"].analysis.risk_score <= 45 # LOW/MEDIUM

        # 6. Verify Campaign Grouping
        camps_res = await db.execute(
            select(Campaign).options(selectinload(Campaign.samples))
        )
        campaigns = camps_res.scalars().all()
        assert len(campaigns) == 2, f"Expected exactly 2 campaigns, found {len(campaigns)}"

        # Check sample counts per campaign
        for c in campaigns:
            assert len(c.samples) == 3, f"Campaign {c.name} expected 3 samples, got {len(c.samples)}"

        # Verify independent samples have NO campaign links
        for name in ["benign_calculator.apk", "photo_viewer_pro.apk", "system_monitor_test.apk", "stealth_dropper_lone.apk"]:
            assert len(sample_map[name].campaigns) == 0, f"Independent sample {name} should have 0 campaigns"

    # 7. Test API endpoints for Related Samples
    # Check FinSteal sample has 2 related samples (both from FinSteal family)
    fin_sample = sample_map["finsteal_v1.apk"]
    resp_rel = await async_client.get(f"/api/v1/samples/{fin_sample.id}/related")
    assert resp_rel.status_code == 200
    rel_data = resp_rel.json()
    assert rel_data["total"] == 2
    rel_names = {item["filename"] for item in rel_data["items"]}
    assert rel_names == {"finsteal_v2.apk", "finsteal_v3.apk"}
    assert all(item["relationship"] == "same_certificate" for item in rel_data["items"])

    # Check Independent sample has 0 related samples
    calc_sample = sample_map["benign_calculator.apk"]
    resp_calc_rel = await async_client.get(f"/api/v1/samples/{calc_sample.id}/related")
    assert resp_calc_rel.status_code == 200
    assert resp_calc_rel.json()["total"] == 0

    # 8. Test Campaign Graph API
    campaign_id = fin_sample.campaigns[0].id
    resp_graph = await async_client.get(f"/api/v1/campaigns/{campaign_id}/graph")
    assert resp_graph.status_code == 200
    graph_data = resp_graph.json()

    # Graph should contain: 1 campaign node + 3 sample nodes + 1 certificate node = 5 nodes
    assert len(graph_data["nodes"]) == 5
    node_types = {n["type"] for n in graph_data["nodes"]}
    assert node_types == {"campaign", "sample", "certificate"}

    # Graph should contain: 3 sample->campaign edges + 3 sample->cert edges = 6 edges
    assert len(graph_data["edges"]) == 6
    relationships = {e["relationship"] for e in graph_data["edges"]}
    assert relationships == {"same_certificate", "signed_by"}

    # 9. Test Campaign Timeline API
    resp_timeline = await async_client.get(f"/api/v1/campaigns/{campaign_id}/timeline")
    assert resp_timeline.status_code == 200
    timeline_data = resp_timeline.json()
    assert timeline_data["total_events"] >= 7
    event_types = {e["event_type"] for e in timeline_data["events"]}
    assert "sample_uploaded" in event_types
    assert "campaign_correlation" in event_types
    assert "analysis_completed" in event_types
    assert "campaign_detected" in event_types
