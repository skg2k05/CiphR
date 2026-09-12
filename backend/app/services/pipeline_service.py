import asyncio
import os
from datetime import datetime, timezone
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
    sample = None
    analysis = None
    
    async with AsyncSessionLocal() as db:
        try:
            # 1. Fetch sample
            result = await db.execute(select(Sample).filter(Sample.id == sample_id))
            sample = result.scalars().first()
            
            if not sample:
                logger.error(f"Sample {sample_id} not found for processing.")
                return
                
            sample.status = 'ANALYZING'  # type: ignore
            
            # Create Initial Analysis record
            analysis = Analysis(
                sample_id=sample.id,
                status='RUNNING',
                started_at=datetime.now(timezone.utc)
            )
            db.add(analysis)
            await db.commit()
            
            # 2. Static Analysis (Androguard + Certificate + TLSH)
            # In a real environment, this might block the event loop, so run it in a threadpool
            loop = asyncio.get_running_loop()
            static_results = await loop.run_in_executor(None, analyze_apk_static, str(sample.storage_path), db)
            
            if static_results['status'] == 'FAILED':
                raise Exception(static_results.get('error_message', 'Static analysis failed'))
                
            # Update Analysis
            if static_results.get('package_name') is not None:
                analysis.package_name = str(static_results.get('package_name'))  # type: ignore
                
            if static_results.get('app_name') is not None:
                analysis.app_name = str(static_results.get('app_name'))  # type: ignore
                
            if static_results.get('version_name') is not None:
                analysis.version_name = str(static_results.get('version_name'))  # type: ignore
                
            if static_results.get('version_code') is not None:
                analysis.version_code = str(static_results.get('version_code'))  # type: ignore
                
            if static_results.get('min_sdk') is not None:
                analysis.min_sdk = str(static_results.get('min_sdk'))  # type: ignore
                
            if static_results.get('target_sdk') is not None:
                analysis.target_sdk = str(static_results.get('target_sdk'))  # type: ignore
                
            if static_results.get('tlsh') is not None:
                analysis.tlsh = str(static_results.get('tlsh'))  # type: ignore
                
            if static_results.get('certificate_fingerprint') is not None:
                analysis.certificate_fingerprint = str(static_results.get('certificate_fingerprint'))  # type: ignore
                
            risk = static_results.get('risk_score')
            if risk is not None:
                analysis.risk_score = int(risk)  # type: ignore
                
            analysis.activities = static_results.get('activities', [])  # type: ignore
            analysis.services = static_results.get('services', [])  # type: ignore
            analysis.receivers = static_results.get('receivers', [])  # type: ignore
            analysis.risk_factors = static_results.get('risk_factors', [])  # type: ignore
            analysis.dex_data = static_results.get('dex_data')  # type: ignore
            
            # Save Findings
            findings_data = static_results.get('findings_data', [])
            for f_data in findings_data:
                finding = Finding(sample_id=sample.id, **f_data)
                db.add(finding)
                
            await db.commit()
            
            # 3. Correlation Engine (Campaigns)
            analysis.status = 'CORRELATING'  # type: ignore
            await db.commit()
            
            await run_correlation(str(sample.id), db)
            
            # 5. LLM Narrative Generation
            analysis.status = 'GENERATING_NARRATIVE'  # type: ignore
            await db.commit()
            
            # Fetch the campaign intelligence if a campaign was assigned
            campaign_summary = None
            if sample.campaigns:
                campaign_summary = sample.campaigns[0].intelligence_summary
                
            analysis_dict = {
                "package_name": analysis.package_name,
                "app_name": analysis.app_name,
                "risk_score": analysis.risk_score,
                "activities": analysis.activities,
                "services": analysis.services,
                "receivers": analysis.receivers,
                "risk_factors": analysis.risk_factors,
                "dex_data": analysis.dex_data,
                "campaign_summary": campaign_summary
            }
            
            narrative = await generate_narrative(analysis_dict, findings_data)
            analysis.threat_narrative = narrative  # type: ignore
            
            # 5. Mark Completed
            analysis.status = 'COMPLETED'  # type: ignore
            analysis.completed_at = datetime.now(timezone.utc)  # type: ignore
            sample.status = 'COMPLETED'  # type: ignore
            
            await db.commit()
            logger.info(f"Pipeline completed successfully for sample: {sample_id}")
            
        except Exception as e:
            logger.error(f"Pipeline failed for sample {sample_id}: {e}", exc_info=True)
            if sample:
                sample.status = 'FAILED'  # type: ignore
            if analysis:
                analysis.status = 'FAILED'  # type: ignore
                analysis.error_message = str(e)  # type: ignore
                analysis.completed_at = datetime.now(timezone.utc)  # type: ignore
            await db.commit()
