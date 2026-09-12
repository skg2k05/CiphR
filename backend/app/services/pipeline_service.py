import asyncio
from datetime import datetime
from app.db.database import AsyncSessionLocal
from sqlalchemy.future import select

from app.db.models import Sample, Analysis, Finding
from app.services.apk_analysis_service import analyze_apk_static
from app.services.correlation_service import run_correlation
from app.services.llm_service import generate_narrative
from app.core.logging import logger

async def process_sample_pipeline(sample_id: str):
    """
    Background task to process the uploaded APK through the intelligence pipeline.
    """
    logger.info(f"Starting pipeline for sample: {sample_id}")
    
    async with AsyncSessionLocal() as db:
        try:
            # 1. Fetch sample
            result = await db.execute(select(Sample).filter(Sample.id == sample_id))
            sample = result.scalars().first()
            
            if not sample:
                logger.error(f"Sample {sample_id} not found for processing.")
                return
                
            sample.status = 'ANALYZING'
            
            # Create Initial Analysis record
            analysis = Analysis(
                sample_id=sample.id,
                status='RUNNING',
                started_at=datetime.utcnow()
            )
            db.add(analysis)
            await db.commit()
            
            # 2. Static Analysis (Androguard + Certificate + TLSH)
            # In a real environment, this might block the event loop, so run it in a threadpool
            loop = asyncio.get_running_loop()
            static_results = await loop.run_in_executor(None, analyze_apk_static, sample.storage_path, db)
            
            if static_results['status'] == 'FAILED':
                raise Exception(static_results.get('error_message', 'Static analysis failed'))
                
            # Update Analysis
            analysis.package_name = static_results.get('package_name')
            analysis.app_name = static_results.get('app_name')
            analysis.version_name = static_results.get('version_name')
            analysis.version_code = static_results.get('version_code')
            analysis.min_sdk = static_results.get('min_sdk')
            analysis.target_sdk = static_results.get('target_sdk')
            analysis.tlsh = static_results.get('tlsh')
            analysis.certificate_fingerprint = static_results.get('certificate_fingerprint')
            analysis.risk_score = static_results.get('risk_score')
            analysis.activities = static_results.get('activities', [])
            analysis.services = static_results.get('services', [])
            analysis.receivers = static_results.get('receivers', [])
            analysis.risk_factors = static_results.get('risk_factors', [])
            
            # Save Findings
            findings_data = static_results.get('findings_data', [])
            for f_data in findings_data:
                finding = Finding(sample_id=sample.id, **f_data)
                db.add(finding)
                
            await db.commit()
            
            # 3. Correlation Engine (Campaigns)
            analysis.status = 'CORRELATING'
            await db.commit()
            
            await run_correlation(sample.id, db)
            
            # 4. LLM Narrative Generation
            analysis.status = 'GENERATING_NARRATIVE'
            await db.commit()
            
            analysis_dict = {
                "package_name": analysis.package_name,
                "app_name": analysis.app_name,
                "risk_score": analysis.risk_score,
                "activities": analysis.activities,
                "services": analysis.services,
                "receivers": analysis.receivers,
                "risk_factors": analysis.risk_factors
            }
            
            narrative = await generate_narrative(analysis_dict, findings_data)
            analysis.threat_narrative = narrative
            
            # 5. Mark Completed
            analysis.status = 'COMPLETED'
            analysis.completed_at = datetime.utcnow()
            sample.status = 'COMPLETED'
            
            await db.commit()
            logger.info(f"Pipeline completed successfully for sample: {sample_id}")
            
        except Exception as e:
            logger.error(f"Pipeline failed for sample {sample_id}: {e}", exc_info=True)
            if sample:
                sample.status = 'FAILED'
            if analysis:
                analysis.status = 'FAILED'
                analysis.error_message = str(e)
                analysis.completed_at = datetime.utcnow()
            await db.commit()
