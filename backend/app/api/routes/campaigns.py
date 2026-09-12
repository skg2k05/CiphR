from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import datetime

from app.db.database import get_db
from app.db.models import Campaign, Sample, Analysis, sample_campaign_links
from app.schemas.campaign import (
    CampaignResponse, 
    CampaignDetailResponse, 
    CampaignGraph, 
    CampaignGraphNode, 
    CampaignGraphEdge,
    CampaignTimelineResponse,
    CampaignTimelineEvent
)
from app.schemas.sample import SampleResponse
from app.schemas.common import PaginatedResponse
from app.core.utils import validate_uuid
from app.core.auth import get_api_key

router = APIRouter(prefix="/campaigns", tags=["Campaigns"], dependencies=[Depends(get_api_key)])

async def _enrich_campaign_metadata(campaign: Campaign, db: AsyncSession) -> dict:
    """Calculates first_seen, last_seen, and sample_count for a campaign."""
    links_res = await db.execute(
        select(sample_campaign_links).filter(sample_campaign_links.c.campaign_id == campaign.id)
    )
    links = links_res.all()
    sample_count = len(links)
    
    first_seen = campaign.created_at
    last_seen = campaign.updated_at or campaign.created_at
    
    if links:
        sample_ids = [l.sample_id for l in links]
        samples_res = await db.execute(
            select(Sample).options(selectinload(Sample.analysis)).filter(Sample.id.in_(sample_ids))
        )
        samples = samples_res.scalars().all()
        dates = [s.created_at for s in samples if s.created_at]
        for s in samples:
            if s.analysis and s.analysis.completed_at:
                dates.append(s.analysis.completed_at)
        if dates:
            first_seen = min(dates)
            last_seen = max(dates)
            
    return {
        "sample_count": sample_count,
        "first_seen": first_seen,
        "last_seen": last_seen
    }

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
    
    items = []
    for c in campaigns:
        meta = await _enrich_campaign_metadata(c, db)
        resp = CampaignResponse.model_validate(c)
        resp.sample_count = meta["sample_count"]
        resp.first_seen = meta["first_seen"]
        resp.last_seen = meta["last_seen"]
        items.append(resp)
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=(skip // limit) + 1,
        size=limit
    )

@router.get("/{campaign_id}", response_model=CampaignDetailResponse)
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    validate_uuid(campaign_id, "Campaign")
    result = await db.execute(select(Campaign).filter(Campaign.id == campaign_id))
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
        
    meta = await _enrich_campaign_metadata(campaign, db)
    resp = CampaignDetailResponse.model_validate(campaign)
    resp.sample_count = meta["sample_count"]
    resp.first_seen = meta["first_seen"]
    resp.last_seen = meta["last_seen"]
    return resp

@router.get("/{campaign_id}/samples", response_model=List[SampleResponse])
async def get_campaign_samples(campaign_id: str, db: AsyncSession = Depends(get_db)):
    validate_uuid(campaign_id, "Campaign")
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
    """Returns a graph representation including Campaign, Samples, and Certificate nodes for vis-network."""
    validate_uuid(campaign_id, "Campaign")
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
    node_ids = set()
    
    # Add Campaign Node
    camp_node = CampaignGraphNode(
        id=campaign_id, 
        type="campaign", 
        label=str(campaign.name) if campaign.name is not None else "Unknown Campaign",
        metadata={"risk_score": campaign.risk_score, "status": campaign.status}
    )
    nodes.append(camp_node)
    node_ids.add(campaign_id)
    
    sample_ids = [link.sample_id for link in links]
    
    # Add Campaign -> Sample Edges
    for link in links:
        edges.append(CampaignGraphEdge(
            source=link.sample_id,
            target=campaign_id,
            relationship=link.relationship,
            confidence=link.confidence,
            signals=link.signals
        ))
        
    # Fetch sample details and analyses for nodes and certificates
    if sample_ids:
        samples_result = await db.execute(
            select(Sample).options(selectinload(Sample.analysis)).filter(Sample.id.in_(sample_ids))
        )
        samples = samples_result.scalars().all()
        for s in samples:
            if s.id not in node_ids:
                s_meta = {
                    "sha256": s.sha256,
                    "risk_score": s.analysis.risk_score if s.analysis else None,
                    "package_name": s.analysis.package_name if s.analysis else None
                }
                nodes.append(CampaignGraphNode(
                    id=s.id, 
                    type="sample", 
                    label=s.filename or s.sha256[:8],
                    metadata=s_meta
                ))
                node_ids.add(s.id)
                
            # Connect to Signing Certificate node if present
            if s.analysis and s.analysis.certificate_fingerprint:
                cert_fp = s.analysis.certificate_fingerprint
                cert_id = f"cert-{cert_fp[:16]}"
                if cert_id not in node_ids:
                    nodes.append(CampaignGraphNode(
                        id=cert_id,
                        type="certificate",
                        label=f"Cert: {cert_fp[:8]}...",
                        metadata={"fingerprint": cert_fp}
                    ))
                    node_ids.add(cert_id)
                    
                edges.append(CampaignGraphEdge(
                    source=s.id,
                    target=cert_id,
                    relationship="signed_by",
                    confidence=1.0
                ))

    return CampaignGraph(nodes=nodes, edges=edges)

@router.get("/{campaign_id}/timeline", response_model=CampaignTimelineResponse)
async def get_campaign_timeline(campaign_id: str, db: AsyncSession = Depends(get_db)):
    """Returns chronological timeline events derived from real persisted campaign and sample timestamps."""
    validate_uuid(campaign_id, "Campaign")
    result = await db.execute(select(Campaign).filter(Campaign.id == campaign_id))
    campaign = result.scalars().first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
        
    links_result = await db.execute(
        select(sample_campaign_links).filter(sample_campaign_links.c.campaign_id == campaign_id)
    )
    links = links_result.all()
    link_map = {l.sample_id: l for l in links}
    
    events: List[CampaignTimelineEvent] = []
    
    # 1. Campaign detection event
    events.append(CampaignTimelineEvent(
        timestamp=campaign.created_at,
        event_type="campaign_detected",
        title="Threat Campaign Detected",
        description=f"Campaign '{campaign.name}' registered with initial risk score {campaign.risk_score or 0}.",
        data={"campaign_id": campaign.id, "risk_score": campaign.risk_score}
    ))
    
    # 2. Sample events
    if links:
        sample_ids = [l.sample_id for l in links]
        samples_result = await db.execute(
            select(Sample).options(selectinload(Sample.analysis)).filter(Sample.id.in_(sample_ids))
        )
        samples = samples_result.scalars().all()
        
        for s in samples:
            # Upload event
            events.append(CampaignTimelineEvent(
                timestamp=s.created_at,
                event_type="sample_uploaded",
                title="Sample Uploaded",
                description=f"APK sample '{s.filename}' (SHA-256: {s.sha256[:10]}...) received.",
                sample_id=s.id,
                data={"filename": s.filename, "sha256": s.sha256}
            ))
            
            # Analysis completion event
            if s.analysis and s.analysis.completed_at:
                events.append(CampaignTimelineEvent(
                    timestamp=s.analysis.completed_at,
                    event_type="analysis_completed",
                    title="Static Analysis Completed",
                    description=f"Static analysis finished for '{s.filename}' with risk score {s.analysis.risk_score or 0}/100.",
                    sample_id=s.id,
                    data={"risk_score": s.analysis.risk_score, "package_name": s.analysis.package_name}
                ))
                
            # Correlation event
            link = link_map.get(s.id)
            if link:
                events.append(CampaignTimelineEvent(
                    timestamp=s.created_at,
                    event_type="campaign_correlation",
                    title="Sample Correlated to Campaign",
                    description=f"Sample '{s.filename}' linked via {link.relationship} ({link.reason or 'shared evidence'}).",
                    sample_id=s.id,
                    data={"relationship": link.relationship, "confidence": link.confidence}
                ))
                
    # Sort events chronologically
    events.sort(key=lambda e: e.timestamp)
    
    meta = await _enrich_campaign_metadata(campaign, db)
    return CampaignTimelineResponse(
        campaign_id=campaign.id,
        campaign_name=campaign.name,
        first_seen=meta["first_seen"],
        last_seen=meta["last_seen"],
        total_events=len(events),
        events=events
    )
