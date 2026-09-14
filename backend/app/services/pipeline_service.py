import asyncio
import os
from datetime import datetime, timezone
from app.db.database import AsyncSessionLocal
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.db.models import Sample, Analysis, Finding, sample_campaign_links
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
            analysis.providers = static_results.get('providers', [])  # type: ignore
            analysis.permissions = static_results.get('permissions', [])  # type: ignore
            analysis.certificate_details = static_results.get('certificate_details', {})  # type: ignore
            analysis.risk_factors = static_results.get('risk_factors', [])  # type: ignore
            analysis.dex_data = static_results.get('dex_data')  # type: ignore
            
            # Save Findings
            findings_data = static_results.get('findings_data', [])
            for f_data in findings_data:
                finding = Finding(
                    sample_id=sample.id,
                    title=f_data.get("title"),
                    description=f_data.get("description"),
                    severity=f_data.get("severity"),
                    category=f_data.get("category"),
                    evidence=f_data.get("evidence"),
                    mitre_technique_id=f_data.get("mitre_technique_id"),
                    confidence=f_data.get("confidence")
                )
                db.add(finding)
                
            await db.commit()
            
            # 3. Correlation Engine (Campaigns)
            analysis.status = 'CORRELATING'  # type: ignore
            await db.commit()
            
            await run_correlation(str(sample.id), db)
            
            # 5. LLM Narrative Generation
            analysis.status = 'GENERATING_NARRATIVE'  # type: ignore
            await db.commit()
            
            # Query campaign and correlation context for rich AI explanation
            camp_result = await db.execute(
                select(Sample).options(selectinload(Sample.campaigns)).filter(Sample.id == sample.id)
            )
            loaded_sample = camp_result.scalars().first()
            campaign_info = None
            campaign_summary = None
            related_count = 0
            correlation_reason = None
            
            if loaded_sample and loaded_sample.campaigns:
                target_camp = loaded_sample.campaigns[0]
                campaign_info = {"id": target_camp.id, "name": target_camp.name}
                campaign_summary = getattr(target_camp, 'intelligence_summary', None)
                
                link_count_res = await db.execute(
                    select(sample_campaign_links).filter(
                        sample_campaign_links.c.campaign_id == target_camp.id,
                        sample_campaign_links.c.sample_id != sample.id
                    )
                )
                related_count = len(link_count_res.all())
                
                my_link_res = await db.execute(
                    select(sample_campaign_links).filter(
                        sample_campaign_links.c.campaign_id == target_camp.id,
                        sample_campaign_links.c.sample_id == sample.id
                    )
                )
                my_link = my_link_res.first()
                if my_link:
                    correlation_reason = my_link.reason
            analysis_dict = {
                "package_name": analysis.package_name,
                "app_name": analysis.app_name,
                "risk_score": analysis.risk_score,
                "permissions": analysis.permissions,
                "providers": analysis.providers,
                "activities": analysis.activities,
                "services": analysis.services,
                "receivers": analysis.receivers,
                "certificate_details": analysis.certificate_details,
                "risk_factors": analysis.risk_factors,
                "dex_data": analysis.dex_data,
                "campaign": campaign_info,
                "campaign_summary": campaign_summary,
                "related_samples_count": related_count,
                "correlation_reason": correlation_reason
            }
            
            narrative = await generate_narrative(analysis_dict, findings_data)
            analysis.threat_narrative = narrative  # type: ignore
            
            # --- SHADOW MODE HOOK (Phase 6F) ---
            from app.core.config import settings
            if settings.FUSION_SHADOW_ENABLED:
                try:
                    from app.fusion.shadow import run_shadow_fusion
                    await run_shadow_fusion(
                        sample=sample,
                        analysis=analysis,
                        static_results=static_results,
                        findings_data=findings_data,
                        campaign_summary=campaign_summary or "",
                        narrative=narrative
                    )
                except Exception as shadow_err:
                    logger.error(f"Shadow fusion failed for {sample_id}, preserving legacy pipeline: {shadow_err}", exc_info=True)
            # -----------------------------------
            
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
                
            try:
                await db.commit()
            except Exception as commit_error:
                logger.error(f"Failed to commit FAILED status for sample {sample_id}: {commit_error}")
                await db.rollback()
