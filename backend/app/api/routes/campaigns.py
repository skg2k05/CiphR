from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional

from app.db.database import get_db
from app.db.models import Campaign, Sample, sample_campaign_links
from app.schemas.campaign import CampaignResponse, CampaignDetailResponse, CampaignGraph, CampaignGraphNode, CampaignGraphEdge
from app.schemas.sample import SampleResponse
from app.schemas.common import PaginatedResponse

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])

@router.get("", response_model=PaginatedResponse[CampaignResponse])
async def list_campaigns(
    skip: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db)
):
    query = select(Campaign).order_by(Campaign.updated_at.desc())
    result = await db.execute(query.offset(skip).limit(limit))
    campaigns = result.scalars().all()
    
    total_result = await db.execute(select(Campaign))
    total = len(total_result.scalars().all())
    
    return PaginatedResponse(
        items=campaigns,
        total=total,
        page=(skip // limit) + 1,
        size=limit
    )

@router.get("/{campaign_id}", response_model=CampaignDetailResponse)
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Campaign).filter(Campaign.id == campaign_id))
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign

@router.get("/{campaign_id}/samples", response_model=List[SampleResponse])
async def get_campaign_samples(campaign_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Campaign)
        .options(selectinload(Campaign.samples))
        .filter(Campaign.id == campaign_id)
    )
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign.samples

@router.get("/{campaign_id}/graph", response_model=CampaignGraph)
async def get_campaign_graph(campaign_id: str, db: AsyncSession = Depends(get_db)):
    """Returns a graph representation of the campaign for the frontend."""
    # 1. Verify Campaign exists
    result = await db.execute(select(Campaign).filter(Campaign.id == campaign_id))
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # 2. Get all links for this campaign
    links_result = await db.execute(
        select(sample_campaign_links).filter(sample_campaign_links.c.campaign_id == campaign_id)
    )
    links = links_result.all()

    nodes = []
    edges = []
    
    # Add Campaign Node
    nodes.append(CampaignGraphNode(id=campaign_id, type="campaign", label=campaign.name))
    
    sample_ids = []
    for link in links:
        sample_id = link.sample_id
        sample_ids.append(sample_id)
        edges.append(CampaignGraphEdge(
            source=sample_id,
            target=campaign_id,
            relationship=link.relationship,
            confidence=link.confidence
        ))
        
    # Fetch sample details for nodes
    if sample_ids:
        samples_result = await db.execute(select(Sample).filter(Sample.id.in_(sample_ids)))
        samples = samples_result.scalars().all()
        for s in samples:
            nodes.append(CampaignGraphNode(id=s.id, type="sample", label=s.filename or s.sha256[:8]))

    return CampaignGraph(nodes=nodes, edges=edges)
