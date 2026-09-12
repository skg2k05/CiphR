import asyncio
import json
import os
import time
from datetime import datetime, timezone
import uuid
import sys
from unittest.mock import patch, AsyncMock

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.future import select

from app.core.config import settings
from app.db.database import AsyncSessionLocal, engine, Base
from app.db.models import Sample, Analysis, Campaign
from app.services.pipeline_service import process_sample_pipeline

import warnings
warnings.filterwarnings("ignore")

async def setup_mock_db_with_fixtures():
    # Setup in-memory sqlite for test, or just use existing db.
    # Let's insert the fixtures into the actual DB to process them, or just use what is there.
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Sample).options(selectinload(Sample.analysis)))
        samples = res.scalars().all()
        if not samples:
            print("No samples in DB. Adding fixtures...")
            for f in ["ApiDemos-debug.apk", "ApiDemos-debug2.apk", "dummy.apk"]:
                p = os.path.abspath(os.path.join("tests", "fixtures", f))
                if os.path.exists(p):
                    sid = str(uuid.uuid4())
                    sample = Sample(id=sid, file_hash=f"hash_{f}", storage_path=p, status="UPLOADED", created_at=datetime.now(timezone.utc))
                    db.add(sample)
            await db.commit()
            
            res = await db.execute(select(Sample).options(selectinload(Sample.analysis)))
            samples = res.scalars().all()
            
    return samples

async def run_observation():
    samples = await setup_mock_db_with_fixtures()
    print(f"Found {len(samples)} samples to observe.")
    
    results = []
    
    # We will patch logger.info to capture the SHADOW_FUSION_COMPARISON payload
    for sample in samples:
        print(f"\nProcessing {sample.storage_path}...")
        
        # Reset analysis for legacy run
        async with AsyncSessionLocal() as db:
            s = await db.get(Sample, sample.id, options=[selectinload(Sample.analysis)])
            if s and s.analysis:
                await db.delete(s.analysis)
                await db.commit()
            
        settings.FUSION_SHADOW_ENABLED = False
        t0 = time.time()
        # To avoid actual OpenAI API calls and external correlations failing, 
        # we let pipeline run naturally (it uses mock generation if configured, or might fail gracefully).
        # We'll just catch exceptions if any so we can continue.
        try:
            await process_sample_pipeline(str(sample.id))
        except Exception as e:
            print(f"Legacy pipeline error: {e}")
            
        t1 = time.time()
        legacy_time = t1 - t0
        
        legacy_score = None
        legacy_status = None
        async with AsyncSessionLocal() as db:
            s = await db.get(Sample, sample.id, options=[selectinload(Sample.analysis)])
            if s and s.analysis:
                legacy_score = s.analysis.risk_score
                legacy_status = s.analysis.status
                await db.delete(s.analysis)
                await db.commit()

        settings.FUSION_SHADOW_ENABLED = True
        t0 = time.time()
        
        captured_shadow = None
        
        # We need to capture the JSON dumped to logger.info
        import logging
        original_info = logging.Logger.info
        def mock_info(self, msg, *args, **kwargs):
            nonlocal captured_shadow
            if isinstance(msg, str) and msg.startswith("SHADOW_FUSION_COMPARISON: "):
                try:
                    captured_shadow = json.loads(msg.replace("SHADOW_FUSION_COMPARISON: ", ""))
                except:
                    pass
            original_info(self, msg, *args, **kwargs)

        logging.Logger.info = mock_info
        try:
            await process_sample_pipeline(str(sample.id))
        except Exception as e:
            print(f"Shadow pipeline error: {e}")
        finally:
            logging.Logger.info = original_info
            
        t1 = time.time()
        shadow_time = t1 - t0
        
        async with AsyncSessionLocal() as db:
            s = await db.get(Sample, sample.id, options=[selectinload(Sample.analysis)])
            shadow_score = None
            shadow_status = None
            if s and s.analysis:
                shadow_score = s.analysis.risk_score
                shadow_status = s.analysis.status
        invariant_preserved = (legacy_score == shadow_score and legacy_status == shadow_status)
        
        res_entry = {
            "sample_id": str(sample.id),
            "filename": os.path.basename(str(sample.storage_path)) if sample.storage_path else "unknown",
            "legacy_time_s": legacy_time,
            "shadow_time_s": shadow_time,
            "overhead_s": shadow_time - legacy_time,
            "legacy_score": legacy_score,
            "shadow_score": shadow_score,
            "legacy_status": legacy_status,
            "shadow_status": shadow_status,
            "invariant_preserved": invariant_preserved,
            "shadow_telemetry": captured_shadow
        }
        results.append(res_entry)
        
        print(f"  Legacy time: {legacy_time:.3f}s")
        print(f"  Shadow time: {shadow_time:.3f}s")
        print(f"  Invariant preserved: {invariant_preserved}")
        if captured_shadow:
            print(f"  Fusion Status: {captured_shadow.get('shadow', {}).get('fusion_status')}")

    out_path = "benchmarks/phase6g_shadow_observation_results.json"
    os.makedirs("benchmarks", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")

if __name__ == "__main__":
    asyncio.run(run_observation())
