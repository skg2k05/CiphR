from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from app.db.models import Sample, Analysis, Campaign, sample_campaign_links
from app.services.tlsh_service import compare_tlsh
from app.core.logging import logger

async def _link_to_campaign(db: AsyncSession, sample_id: str, campaign_id: str, relationship: str, confidence: float, reason: str, linked_campaign_ids: set) -> bool:
    if campaign_id in linked_campaign_ids:
        return False
        
    existing_link = await db.execute(
        select(sample_campaign_links).filter(
            sample_campaign_links.c.sample_id == sample_id,
            sample_campaign_links.c.campaign_id == campaign_id
        )
    )
    if existing_link.first():
        linked_campaign_ids.add(campaign_id)
        return False

    stmt = sample_campaign_links.insert().values(
        sample_id=sample_id,
        campaign_id=campaign_id,
        relationship=relationship,
        confidence=confidence,
        reason=reason
    )
    await db.execute(stmt)
    linked_campaign_ids.add(campaign_id)
    return True

async def run_correlation(sample_id: str, db: AsyncSession):
    """
    Correlates a sample against existing analyses.
    Checks for:
    1. Exact Certificate Match
    2. High TLSH similarity
    3. Shared High-Risk Static Indicators
    """
    result = await db.execute(
        select(Sample)
        .options(selectinload(Sample.analysis), selectinload(Sample.campaigns))
        .filter(Sample.id == sample_id)
    )
    current_sample = result.scalars().first()
    
    if not current_sample or not current_sample.analysis:
        logger.warning(f"Correlation skipped: Sample {sample_id} or analysis not found.")
        return
        
    analysis = current_sample.analysis
    if analysis.status not in ['COMPLETED', 'CORRELATING']:
        return

    cert = analysis.certificate_fingerprint
    tlsh_hash = analysis.tlsh
    risk_factors = analysis.risk_factors or []
    
    # Extract indicators that are considered high-risk (weight >= 20)
    high_risk_indicators = set([rf["indicator"] for rf in risk_factors if rf.get("weight", 0) >= 20])
    
    # We want to find other analyses that match
    matched_campaigns = set(c for c in current_sample.campaigns)
    linked_campaign_ids = set(c.id for c in matched_campaigns)
    correlations_made = False
    
    # Fetch all other completed/correlating analyses to compare against
    all_analyses_result = await db.execute(
        select(Analysis)
        .options(selectinload(Analysis.sample).selectinload(Sample.campaigns))
        .filter(Analysis.sample_id != sample_id)
    )
    all_analyses = all_analyses_result.scalars().all()
    
    for match in all_analyses:
        # Track if any strong signal matched between current_sample and match
        matched_signals = []
        
        # 1. Certificate Match
        if cert and match.certificate_fingerprint == cert:
            matched_signals.append({
                "relationship": "same_certificate",
                "confidence": 1.0,
                "reason": "Samples share identical signing certificate fingerprint."
            })
            
        # 2. TLSH Match
        if tlsh_hash and tlsh_hash != "ERROR_GENERATING_TLSH" and not tlsh_hash.startswith("MOCK"):
            if match.tlsh and match.tlsh != "ERROR_GENERATING_TLSH" and not match.tlsh.startswith("MOCK"):
                diff = compare_tlsh(tlsh_hash, match.tlsh)
                if diff < 50:
                    matched_signals.append({
                        "relationship": "tlsh_similarity",
                        "confidence": 0.9,
                        "reason": f"High TLSH similarity (diff: {diff})"
                    })
                    
        # 3. Shared High-Risk Indicator Match
        match_factors = match.risk_factors or []
        match_indicators = set([rf["indicator"] for rf in match_factors])
        shared_indicators = high_risk_indicators.intersection(match_indicators)
        
        if shared_indicators:
            matched_signals.append({
                "relationship": "shared_indicator",
                "confidence": 0.7,
                "reason": f"Samples share high-risk static indicators: {', '.join(shared_indicators)}"
            })
            
        # Process correlations if any signal matched
        if matched_signals:
            best_signal = matched_signals[0] # Pick the strongest signal (cert > tlsh > indicator)
            
            # Determine which campaign to link to
            target_campaign = None
            if match.sample.campaigns:
                target_campaign = match.sample.campaigns[0]
            else:
                # Create or reuse a campaign for this cluster
                prefix = cert[:8] if cert else (sample_id[:8])
                camp_name = f"Campaign-{prefix}"
                camp_res = await db.execute(select(Campaign).filter(Campaign.name == camp_name))
                target_campaign = camp_res.scalars().first()
                if not target_campaign:
                    target_campaign = Campaign(
                        name=camp_name,
                        description="Automatically correlated threat campaign.",
                        risk_score=max(analysis.risk_score or 0, match.risk_score or 0)
                    )
                    db.add(target_campaign)
                    await db.flush()
                
                # Insert link for the match defensively
                existing_match_link = await db.execute(
                    select(sample_campaign_links).filter(
                        sample_campaign_links.c.sample_id == match.sample_id,
                        sample_campaign_links.c.campaign_id == target_campaign.id
                    )
                )
                if not existing_match_link.first():
                    stmt_match = sample_campaign_links.insert().values(
                        sample_id=match.sample_id,
                        campaign_id=target_campaign.id,
                        relationship=best_signal["relationship"],
                        confidence=best_signal["confidence"],
                        reason=best_signal["reason"]
                    )
                    await db.execute(stmt_match)
            
            # Link current sample to target_campaign
            linked = await _link_to_campaign(
                db, 
                sample_id, 
                target_campaign.id, 
                best_signal["relationship"], 
                best_signal["confidence"], 
                best_signal["reason"],
                linked_campaign_ids
            )
            
            if linked:
                matched_campaigns.add(target_campaign)
                correlations_made = True

    if correlations_made:
        await db.commit()
        logger.info(f"Correlation completed for sample {sample_id}. Links created.")
    else:
        logger.info(f"No correlations found for sample {sample_id}.")
