#!/usr/bin/env python3
"""
CiphR — Multi-APK Controlled Dataset Audit Script.

Demonstrates end-to-end execution of:
10 APKs -> Static Analysis -> Risk Scores -> Correlation -> Campaigns -> Related Samples -> Graph -> Timeline.

Prints a human-readable summary:
- Total APKs:
- Risk distribution:
- Campaigns:
- Samples per campaign:
- Related sample relationships:
- Unrelated samples:
- Graph nodes:
- Graph edges:
"""

import sys
import io
import asyncio
from pathlib import Path
from collections import Counter, defaultdict

# Ensure backend root is in python path
BACKEND_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_ROOT))

from tests.fixtures.dataset_builder import build_demo_dataset
from app.db.database import AsyncSessionLocal, Base, engine
from app.db.models import Sample, Analysis, Campaign, sample_campaign_links
from app.services.pipeline_service import process_sample_pipeline
from app.services.upload_service import process_upload
from app.services.apk_analysis_service import calculate_risk_level
from app.api.routes.campaigns import get_campaign_graph
from fastapi import UploadFile
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

async def audit():
    print("==================================================================")
    print("  CIPHR — CONTROLLED MULTI-APK DEMO DATASET END-TO-END AUDIT")
    print("==================================================================\n")

    # 1. Initialize clean database schema for the audit
    print("[1/4] Initializing audit environment and synthesizing 10 safe APK fixtures...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    apk_paths = build_demo_dataset()
    print(f"      Synthesized {len(apk_paths)} deterministic APK test fixtures.")

    # 2. Upload APKs
    print("\n[2/4] Uploading APK fixtures to CiphR ingestion engine...")
    sample_ids = []
    async with AsyncSessionLocal() as db:
        for p in apk_paths:
            content = p.read_bytes()
            upload = UploadFile(filename=p.name, file=io.BytesIO(content))
            sample = await process_upload(
                upload,
                source="audit_multi_apk",
                submitted_by="secops-auditor@ciphr.local",
                db=db
            )
            sample_ids.append(sample.id)
            print(f"      Ingested: {p.name:<25} -> Sample ID: {sample.id[:8]}... (SHA256: {sample.sha256[:10]}...)")

    # 3. Process static analysis, risk evaluation, and threat correlation
    print("\n[3/4] Processing intelligence pipeline (Static Analysis + Threat Correlation)...")
    for sid in sample_ids:
        await process_sample_pipeline(sid)
    print("      All 10 samples completed static analysis and correlation.")

    # 4. Gather intelligence outputs
    print("\n[4/4] Extracting intelligence graph and campaign correlations...\n")
    async with AsyncSessionLocal() as db:
        # Query samples
        samples_res = await db.execute(
            select(Sample)
            .options(selectinload(Sample.analysis), selectinload(Sample.campaigns))
            .order_by(Sample.filename)
        )
        samples = samples_res.scalars().all()

        # Query campaigns
        camps_res = await db.execute(
            select(Campaign).options(selectinload(Campaign.samples))
        )
        campaigns = camps_res.scalars().all()

        # Risk distribution
        risk_dist = Counter()
        score_by_sample = {}
        for s in samples:
            score = s.analysis.risk_score if s.analysis else 0
            cat = calculate_risk_level(score)
            risk_dist[cat] += 1
            score_by_sample[s.filename] = (score, cat)

        # Related vs Unrelated
        campaign_samples = defaultdict(list)
        unrelated_samples = []
        for s in samples:
            if s.campaigns:
                for c in s.campaigns:
                    campaign_samples[c.name].append(s.filename)
            else:
                unrelated_samples.append(s.filename)

        # Query links
        links_res = await db.execute(select(sample_campaign_links))
        links = links_res.all()

        relationships_summary = defaultdict(int)
        for l in links:
            relationships_summary[f"{l.relationship} (confidence: {l.confidence:.1f})"] += 1

        # Aggregate graph stats across all campaigns
        total_graph_nodes = 0
        total_graph_edges = 0
        nodes_by_type = Counter()
        edges_by_rel = Counter()

        for c in campaigns:
            graph = await get_campaign_graph(c.id, db)
            total_graph_nodes += len(graph.nodes)
            total_graph_edges += len(graph.edges)
            for n in graph.nodes:
                nodes_by_type[n.type] += 1
            for e in graph.edges:
                edges_by_rel[e.relationship] += 1

        # Print Human-Readable Summary according to task spec
        print("------------------------------------------------------------------")
        print("                    HUMAN-READABLE SUMMARY")
        print("------------------------------------------------------------------")
        print(f"Total APKs: {len(samples)}")
        print("\nRisk distribution:")
        for cat in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
            if cat in risk_dist:
                count = risk_dist[cat]
                matching = [f"{fn} ({score_by_sample[fn][0]}/100)" for fn in score_by_sample if score_by_sample[fn][1] == cat]
                print(f"  - {cat:<8}: {count} sample(s) -> {', '.join(matching)}")

        print(f"\nCampaigns: {len(campaigns)}")
        for c in campaigns:
            print(f"  - {c.name} (Risk Score: {c.risk_score}/100, ID: {c.id})")

        print("\nSamples per campaign:")
        for c_name, s_list in campaign_samples.items():
            print(f"  - {c_name} ({len(s_list)} samples):")
            for fn in s_list:
                print(f"      * {fn:<25} [Score: {score_by_sample[fn][0]:2}/100 - {score_by_sample[fn][1]}]")

        print("\nRelated sample relationships:")
        if relationships_summary:
            for rel_info, count in relationships_summary.items():
                print(f"  - {rel_info}: {count} link instances across campaigns")
        else:
            print("  - None")

        print(f"\nUnrelated samples: {len(unrelated_samples)}")
        for fn in unrelated_samples:
            print(f"  - {fn:<25} [Score: {score_by_sample[fn][0]:2}/100 - {score_by_sample[fn][1]}] (Independent sample, 0 campaign links)")

        print(f"\nGraph nodes: {total_graph_nodes}")
        for ntype, count in nodes_by_type.items():
            print(f"  - {ntype.capitalize()}: {count}")

        print(f"\nGraph edges: {total_graph_edges}")
        for erel, count in edges_by_rel.items():
            print(f"  - {erel}: {count}")

        print("------------------------------------------------------------------\n")

if __name__ == "__main__":
    asyncio.run(audit())
