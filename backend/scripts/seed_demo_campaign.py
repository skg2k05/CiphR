import asyncio
import argparse
import sys
import os
import uuid
from datetime import datetime, timezone

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, selectinload
from sqlalchemy import select, delete

from app.db.models import Sample, Analysis, Finding, Campaign, sample_campaign_links
from app.core.config import settings
from app.services.correlation_service import run_correlation
from app.core.logging import logger

DEMO_SOURCE = "demo_fixture"
DEMO_SHA256_PREFIX = "DEMO-SHA256"
DEMO_CERT = "DEMO_CERT_9999_AABBCCDDEEFF"
DEMO_DOMAIN = "demo-c2.invalid"
DEMO_IP = "192.0.2.1" # TEST-NET-1 (RFC 5737)
DEMO_API = "Ljava/lang/Runtime;->exec"

async def cleanup_demo_data(session: AsyncSession):
    print("🧹 [CLEANUP] Removing existing demo fixtures...")
    
    # Find demo samples
    result = await session.execute(select(Sample).where(Sample.source == DEMO_SOURCE))
    samples = result.scalars().all()
    sample_ids = [s.id for s in samples]
    
    if not sample_ids:
        print("  No demo samples found.")
    else:
        print(f"  Found {len(sample_ids)} demo samples. Deleting...")
        # SQLAlchemy handles cascading deletes according to model constraints, but
        # since sample_campaign_links is many-to-many, we can just delete Samples
        # and wait for ON DELETE CASCADE at DB level or SQLAlchemy mapping
        # but let's delete explicitly if needed.
        for s in samples:
            await session.delete(s)
        
    # Find demo campaigns (Campaign name will be Campaign-<prefix>)
    camp_prefix = DEMO_CERT[:8]
    camp_result = await session.execute(select(Campaign).where(Campaign.name == f"Campaign-{camp_prefix}"))
    campaigns = camp_result.scalars().all()
    camp_ids = [c.id for c in campaigns]
    
    if not camp_ids:
        print("  No demo campaigns found.")
    else:
        print(f"  Found {len(camp_ids)} demo campaigns. Deleting...")
        for c in campaigns:
            await session.delete(c)
        
    await session.commit()
    print("✅ Cleanup complete.")

async def seed_demo_data(session: AsyncSession):
    print("🌱 [SEED] Generating controlled synthetic demo campaign...")
    
    # 1. First ensure clean state to be idempotent
    await cleanup_demo_data(session)
    
    # 2. Create 3 synthetic samples
    samples_data = [
        {
            "filename": "DEMO-Campaign-Sample-A.apk",
            "sha256": f"{DEMO_SHA256_PREFIX}-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "package_name": "com.ciphr.demo.alpha",
            "tlsh": None,
            "risk_score": 85,
            "findings": [
                {"title": "Demo Network Connection", "severity": "HIGH", "category": "network"}
            ]
        },
        {
            "filename": "DEMO-Campaign-Sample-B.apk",
            "sha256": f"{DEMO_SHA256_PREFIX}-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "package_name": "com.ciphr.demo.beta",
            "tlsh": None,
            "risk_score": 75,
            "findings": [
                {"title": "Demo Data Exfiltration", "severity": "HIGH", "category": "network"}
            ]
        },
        {
            "filename": "DEMO-Campaign-Sample-C.apk",
            "sha256": f"{DEMO_SHA256_PREFIX}-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "package_name": "com.ciphr.demo.gamma",
            "tlsh": None,
            "risk_score": 90,
            "findings": [
                {"title": "Demo Overlay Attack", "severity": "CRITICAL", "category": "permissions"}
            ]
        }
    ]
    
    sample_objs = []
    for data in samples_data:
        sample_id = str(uuid.uuid4())
        sample = Sample(
            id=sample_id,
            filename=data["filename"],
            sha256=data["sha256"],
            source=DEMO_SOURCE,
            status="COMPLETED"
        )
        
        analysis = Analysis(
            id=str(uuid.uuid4()),
            sample_id=sample_id,
            status="COMPLETED",
            package_name=data["package_name"],
            certificate_fingerprint=DEMO_CERT,
            tlsh=data["tlsh"],
            risk_score=data["risk_score"],
            dex_data={
                "domains": [{"indicator": DEMO_DOMAIN}],
                "hardcoded_ips": [{"indicator": DEMO_IP}],
                "urls": [{"indicator": f"http://{DEMO_DOMAIN}/api/v1/ping"}],
                "suspicious_apis": [{"api": DEMO_API}]
            }
        )
        
        for f_data in data["findings"]:
            finding = Finding(
                id=str(uuid.uuid4()),
                sample_id=sample_id,
                title=f_data["title"],
                severity=f_data["severity"],
                category=f_data["category"]
            )
            session.add(finding)
            
        session.add(sample)
        session.add(analysis)
        sample_objs.append(sample)
        
    await session.commit()
    print(f"✅ Created {len(sample_objs)} synthetic samples.")
    
    # 3. Invoke existing correlation service
    print("🔗 [CORRELATION] Invoking existing correlation engine...")
    for s in sample_objs:
        await run_correlation(s.id, session)
        
    # 4. Report Results
    print("\n📊 [RESULTS] Correlation Summary:")
    camp_prefix = DEMO_CERT[:8]
    camp_result = await session.execute(
        select(Campaign).where(Campaign.name == f"Campaign-{camp_prefix}").options(selectinload(Campaign.samples))
    )
    campaigns = camp_result.scalars().all()
    
    if not campaigns:
        print("  ⚠️ No demo campaigns were formed! The correlation engine did not link the samples.")
    
    for camp in campaigns:
        print(f"  Campaign: {camp.name} ({camp.id})")
        print(f"  Total Linked Samples: {len(camp.samples)}")
        print(f"  Intelligence Summary: {camp.intelligence_summary}")
        
        links_res = await session.execute(
            select(sample_campaign_links).where(sample_campaign_links.c.campaign_id == camp.id)
        )
        links = links_res.all()
        for link in links:
            print(f"    Sample ID {link.sample_id} linked via:")
            for sig in link.signals:
                print(f"      - {sig['type']}: {sig.get('evidence', '')}")

async def main():
    parser = argparse.ArgumentParser(description="Generate synthetic, controlled demo fixture for CiphR Campaign Intelligence.")
    parser.add_argument("--cleanup", action="store_true", help="Remove all synthetic demo fixture records.")
    args = parser.parse_args()

    print("==========================================================")
    print("🧪 CiphR DEMO/CONTROLLED FIXTURE GENERATOR")
    print("==========================================================")
    print("NOTICE: This script generates purely synthetic data for")
    print("demonstrating CiphR's UI and correlation capabilities.")
    print("These are NOT real malware samples, and they do NOT")
    print("represent real-world threat campaigns.")
    db_conn = settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL
    print(f"Target Database: {db_conn.split('?')[0]}")
    print("==========================================================\n")

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    
    async with async_session() as session:
        if args.cleanup:
            await cleanup_demo_data(session)
        else:
            await seed_demo_data(session)
            
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(main())
