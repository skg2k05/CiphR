from fastapi import APIRouter, Depends, UploadFile, File, Form, BackgroundTasks, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional

from app.db.database import get_db
from app.db.models import Sample, Analysis, Finding, sample_campaign_links
from app.schemas.sample import SampleResponse, SampleDetailResponse, RelatedSampleItem, RelatedSamplesResponse
from app.schemas.analysis import AnalysisResponse
from app.schemas.finding import FindingResponse
from app.schemas.common import PaginatedResponse
from app.services.upload_service import process_upload
from app.services.pipeline_service import process_sample_pipeline
from app.core.utils import validate_uuid
from app.core.auth import get_api_key

router = APIRouter(prefix="/samples", tags=["Samples"], dependencies=[Depends(get_api_key)])

@router.post("/upload", response_model=SampleResponse)
async def upload_sample(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source: Optional[str] = Form(None),
    submitted_by: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db)
):
    """Uploads an APK for analysis and queues the pipeline."""
    sample = await process_upload(file, source or "", submitted_by or "", db)
    
    if str(sample.status) == 'QUEUED':
        background_tasks.add_task(process_sample_pipeline, str(sample.id))
        
    return sample

@router.get("", response_model=PaginatedResponse[SampleResponse])
async def list_samples(
    skip: int = 0,
    limit: int = 20,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(Sample).options(selectinload(Sample.analysis)).order_by(Sample.created_at.desc())
    if status:
        query = query.filter(Sample.status == status)
        
    result = await db.execute(query.offset(skip).limit(limit))
    samples = result.scalars().all()
    
    # Total count (simplistic for MVP)
    total_result = await db.execute(select(Sample))
    total = len(total_result.scalars().all())

    # Attach flat risk fields from analysis so SampleResponse can include them
    items = []
    for s in samples:
        s.risk_score = s.analysis.risk_score if s.analysis else None
        s.risk_level = s.analysis.risk_level if s.analysis else None
        items.append(s)
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=(skip // limit) + 1,
        size=limit
    )

@router.get("/{sample_id}", response_model=SampleDetailResponse)
async def get_sample(sample_id: str, db: AsyncSession = Depends(get_db)):
    validate_uuid(sample_id, "Sample")
    result = await db.execute(
        select(Sample)
        .options(
            selectinload(Sample.analysis), 
            selectinload(Sample.findings),
            selectinload(Sample.campaigns)
        )
        .filter(Sample.id == sample_id)
    )
    sample = result.scalars().first()
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    related_items = []
    if sample.campaigns:
        for camp in sample.campaigns:
            links_res = await db.execute(
                select(sample_campaign_links).filter(
                    sample_campaign_links.c.campaign_id == camp.id,
                    sample_campaign_links.c.sample_id != sample_id
                )
            )
            links = links_res.all()
            for link in links:
                rel_sample_res = await db.execute(select(Sample).filter(Sample.id == link.sample_id))
                rel_sample = rel_sample_res.scalars().first()
                if rel_sample:
                    related_items.append(RelatedSampleItem(
                        sample_id=rel_sample.id,
                        filename=rel_sample.filename,
                        sha256=rel_sample.sha256,
                        relationship=link.relationship,
                        confidence=link.confidence,
                        reason=link.reason,
                        campaign_id=camp.id,
                        campaign_name=camp.name
                    ))

    resp = SampleDetailResponse.model_validate(sample)
    resp.related_samples = related_items
    resp.related_sample_count = len(related_items)
    return resp

@router.get("/{sample_id}/related", response_model=RelatedSamplesResponse)
async def get_related_samples(sample_id: str, db: AsyncSession = Depends(get_db)):
    """Returns all correlated samples sharing campaigns with this sample."""
    result = await db.execute(
        select(Sample).options(selectinload(Sample.campaigns)).filter(Sample.id == sample_id)
    )
    sample = result.scalars().first()
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    related_items = []
    if sample.campaigns:
        for camp in sample.campaigns:
            links_res = await db.execute(
                select(sample_campaign_links).filter(
                    sample_campaign_links.c.campaign_id == camp.id,
                    sample_campaign_links.c.sample_id != sample_id
                )
            )
            links = links_res.all()
            for link in links:
                rel_sample_res = await db.execute(select(Sample).filter(Sample.id == link.sample_id))
                rel_sample = rel_sample_res.scalars().first()
                if rel_sample:
                    related_items.append(RelatedSampleItem(
                        sample_id=rel_sample.id,
                        filename=rel_sample.filename,
                        sha256=rel_sample.sha256,
                        relationship=link.relationship,
                        confidence=link.confidence,
                        reason=link.reason,
                        campaign_id=camp.id,
                        campaign_name=camp.name
                    ))

    return RelatedSamplesResponse(
        sample_id=sample_id,
        total=len(related_items),
        items=related_items
    )

@router.get("/{sample_id}/status")
async def get_sample_status(sample_id: str, db: AsyncSession = Depends(get_db)):
    validate_uuid(sample_id, "Sample")
    result = await db.execute(select(Sample).filter(Sample.id == sample_id))
    sample = result.scalars().first()
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
        
    analysis_result = await db.execute(select(Analysis).filter(Analysis.sample_id == sample_id))
    analysis = analysis_result.scalars().first()
    
    return {
        "sample_id": sample_id,
        "status": sample.status,
        "stages": {
            "validation": "completed",
            "pipeline": analysis.status if analysis else "pending",
            "error": analysis.error_message if analysis else None
        }
    }

@router.get("/{sample_id}/analysis", response_model=AnalysisResponse)
async def get_sample_analysis(sample_id: str, db: AsyncSession = Depends(get_db)):
    validate_uuid(sample_id, "Sample")
    result = await db.execute(select(Analysis).filter(Analysis.sample_id == sample_id))
    analysis = result.scalars().first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis

@router.get("/{sample_id}/findings", response_model=List[FindingResponse])
async def get_sample_findings(sample_id: str, db: AsyncSession = Depends(get_db)):
    validate_uuid(sample_id, "Sample")
    result = await db.execute(select(Finding).filter(Finding.sample_id == sample_id))
    findings = result.scalars().all()
    return findings
