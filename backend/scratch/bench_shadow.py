import asyncio
import time
from app.core.config import settings
from app.services.pipeline_service import process_sample_pipeline
from app.db.database import AsyncSessionLocal
from app.db.models import Sample
from sqlalchemy.future import select

async def measure():
    sample_id = None
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Sample))
        sample = result.scalars().first()
        if sample:
            sample_id = str(sample.id)

    if not sample_id:
        print("No sample found to benchmark.")
        return

    # Benchmark without shadow
    settings.FUSION_SHADOW_ENABLED = False
    t0 = time.time()
    await process_sample_pipeline(sample_id)
    t1 = time.time()
    time_legacy = t1 - t0
    
    # Benchmark with shadow
    settings.FUSION_SHADOW_ENABLED = True
    t0 = time.time()
    await process_sample_pipeline(sample_id)
    t1 = time.time()
    time_shadow = t1 - t0

    print(f"Legacy Execution Time: {time_legacy:.4f}s")
    print(f"Legacy + Shadow Execution Time: {time_shadow:.4f}s")
    print(f"Overhead: {time_shadow - time_legacy:.4f}s ({(time_shadow - time_legacy) / time_legacy * 100:.2f}%)")


if __name__ == "__main__":
    asyncio.run(measure())
