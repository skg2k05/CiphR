from fastapi import APIRouter, Depends, UploadFile, File, Form, BackgroundTasks, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional

from app.db.database import get_db
from app.db.models import Sample, Analysis, Finding
from app.schemas.sample import SampleResponse, SampleDetailResponse
from app.schemas.analysis import AnalysisResponse
from app.schemas.finding import FindingResponse
from app.schemas.common import PaginatedResponse
from app.services.upload_service import process_upload
from app.services.pipeline_service import process_sample_pipeline

router = APIRouter(prefix="/samples", tags=["Samples"])

@router.post("/upload", response_model=SampleResponse)
async def upload_sample(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source: Optional[str] = Form(None),
    submitted_by: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db)
):
    """Uploads an APK for analysis and queues the pipeline."""
    sample = await process_upload(file, source, submitted_by, db)
    
    if sample.status == 'QUEUED':
        background_tasks.add_task(process_sample_pipeline, sample.id)
        
    return sample

@router.get("", response_model=PaginatedResponse[SampleResponse])
async def list_samples(
    skip: int = 0,
    limit: int = 20,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(Sample).order_by(Sample.created_at.desc())
    if status:
        query = query.filter(Sample.status == status)
        
    result = await db.execute(query.offset(skip).limit(limit))
    samples = result.scalars().all()
    
    # Total count (simplistic for MVP)
    total_result = await db.execute(select(Sample))
    total = len(total_result.scalars().all())
    
    return PaginatedResponse(
        items=samples,
        total=total,
        page=(skip // limit) + 1,
        size=limit
    )

@router.get("/{sample_id}", response_model=SampleDetailResponse)
async def get_sample(sample_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Sample)
        .options(selectinload(Sample.analysis), selectinload(Sample.findings))
        .filter(Sample.id == sample_id)
    )
    sample = result.scalars().first()
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    return sample

@router.get("/{sample_id}/status")
async def get_sample_status(sample_id: str, db: AsyncSession = Depends(get_db)):
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
    result = await db.execute(select(Analysis).filter(Analysis.sample_id == sample_id))
    analysis = result.scalars().first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis

@router.get("/{sample_id}/findings", response_model=List[FindingResponse])
async def get_sample_findings(sample_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).filter(Finding.sample_id == sample_id))
    findings = result.scalars().all()
    return findings
