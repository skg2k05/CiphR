from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from app.db.models import Sample, Analysis, Campaign, sample_campaign_links
from app.services.tlsh_service import compare_tlsh
from app.core.logging import logger
import json

async def _link_to_campaign(db: AsyncSession, sample_id: str, campaign_id: str, relationship: str, confidence: float, reason: str, signals: list, linked_campaign_ids: set) -> bool:
    if campaign_id in linked_campaign_ids:
        return False
        
    stmt = sample_campaign_links.insert().values(
        sample_id=sample_id,
        campaign_id=campaign_id,
        relationship=relationship,
        confidence=confidence,
        reason=reason,
        signals=signals
    )
    await db.execute(stmt)
    linked_campaign_ids.add(campaign_id)
    return True

async def recalculate_campaign_intelligence(db: AsyncSession, campaign_id: str):
    """
    Recalculates deterministic campaign intelligence summary and severity
    based on all samples within the campaign.
    """
    # Fetch campaign with all samples and their analyses
    result = await db.execute(
        select(Campaign)
        .options(selectinload(Campaign.samples).selectinload(Sample.analysis))
        .filter(Campaign.id == campaign_id)
    )
    campaign = result.scalars().first()
    
    if not campaign or not campaign.samples:
        return
        
    analyses = [s.analysis for s in campaign.samples if s.analysis]
    
    num_samples = len(campaign.samples)
    if num_samples == 0:
        return
        
    risk_scores = [a.risk_score for a in analyses if a.risk_score is not None]
    highest_risk = max(risk_scores) if risk_scores else 0
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    
    # Calculate common/unique indicators
    all_ips = {}
    all_urls = {}
    all_domains = {}
    all_apis = {}
    
    for a in analyses:
        if a.dex_data:
            for ip in a.dex_data.get("hardcoded_ips", []):
                all_ips[ip["indicator"]] = all_ips.get(ip["indicator"], 0) + 1
            for url in a.dex_data.get("urls", []):
                all_urls[url["indicator"]] = all_urls.get(url["indicator"], 0) + 1
            for domain in a.dex_data.get("domains", []):
                all_domains[domain["indicator"]] = all_domains.get(domain["indicator"], 0) + 1
            for api in a.dex_data.get("suspicious_apis", []):
                all_apis[api["api"]] = all_apis.get(api["api"], 0) + 1
                
    def get_common(ind_dict):
        # Common = present in > 50% of samples (or all if < 3)
        threshold = max(1, num_samples // 2)
        return [k for k, v in ind_dict.items() if v >= threshold]
        
    intelligence_summary = {
        "num_samples": num_samples,
        "highest_risk": highest_risk,
        "average_risk": round(avg_risk, 2),
        "common_indicators": {
            "ips": get_common(all_ips),
            "urls": get_common(all_urls),
            "domains": get_common(all_domains),
            "apis": get_common(all_apis)
        }
    }
    
    campaign.intelligence_summary = intelligence_summary  # type: ignore
    campaign.risk_score = highest_risk  # type: ignore
    
    # Calculate Severity
    severity = "LOW"
    if highest_risk >= 80 or num_samples >= 5:
        severity = "CRITICAL"
    elif highest_risk >= 60 or num_samples >= 3:
        severity = "HIGH"
    elif highest_risk >= 40 or num_samples >= 2:
        severity = "MEDIUM"
        
    campaign.severity = severity  # type: ignore
    await db.commit()

async def run_correlation(sample_id: str, db: AsyncSession):
    """
    Correlates a sample against existing analyses using multi-signal evidence.
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

    cert = str(analysis.certificate_fingerprint) if analysis.certificate_fingerprint else None
    tlsh_hash = str(analysis.tlsh) if analysis.tlsh else None
    risk_factors = analysis.risk_factors or []
    high_risk_indicators = set([rf["indicator"] for rf in risk_factors if rf.get("weight", 0) >= 20])
    
    dex_ips = set(ip["indicator"] for ip in (dict(analysis.dex_data).get("hardcoded_ips", []) if isinstance(analysis.dex_data, dict) else []))
    dex_domains = set(d["indicator"] for d in (dict(analysis.dex_data).get("domains", []) if isinstance(analysis.dex_data, dict) else []))
    dex_urls = set(u["indicator"] for u in (dict(analysis.dex_data).get("urls", []) if isinstance(analysis.dex_data, dict) else []))
    dex_apis = set(a["api"] for a in (dict(analysis.dex_data).get("suspicious_apis", []) if isinstance(analysis.dex_data, dict) else []))
    
    matched_campaigns = set(c for c in current_sample.campaigns)
    linked_campaign_ids = set(c.id for c in matched_campaigns)
    correlations_made = False
    
    all_analyses_result = await db.execute(
        select(Analysis)
        .options(selectinload(Analysis.sample).selectinload(Sample.campaigns))
        .filter(Analysis.sample_id != sample_id)
    )
    all_analyses = all_analyses_result.scalars().all()
    
    updated_campaign_ids = set()
    
    for match in all_analyses:
        matched_signals = []
        base_confidence = 0.0
        
        # 1. Certificate Match
        if cert is not None and str(match.certificate_fingerprint) == cert:
            matched_signals.append({"type": "same_certificate", "confidence": 1.0, "evidence": cert})
            base_confidence = max(base_confidence, 1.0)
            
        # 2. TLSH Match
        match_tlsh_str = str(match.tlsh) if match.tlsh is not None else ""
        if tlsh_hash is not None and not tlsh_hash.startswith("ERROR") and match_tlsh_str and not match_tlsh_str.startswith("ERROR"):
            diff = compare_tlsh(tlsh_hash, match_tlsh_str)
            if diff < 50:
                matched_signals.append({"type": "tlsh_similarity", "confidence": 0.9, "evidence": f"diff:{diff}"})
                base_confidence = max(base_confidence, 0.9)
                
        # 3. DEX/Infrastructure Matches
        match_ips = set(ip["indicator"] for ip in (dict(match.dex_data).get("hardcoded_ips", []) if isinstance(match.dex_data, dict) else []))
        match_domains = set(d["indicator"] for d in (dict(match.dex_data).get("domains", []) if isinstance(match.dex_data, dict) else []))
        match_apis = set(a["api"] for a in (dict(match.dex_data).get("suspicious_apis", []) if isinstance(match.dex_data, dict) else []))
        
        shared_ips = dex_ips.intersection(match_ips)
        shared_domains = dex_domains.intersection(match_domains)
        shared_apis = dex_apis.intersection(match_apis)
        
        if shared_ips:
            matched_signals.append({"type": "shared_ip", "confidence": 0.8, "evidence": list(shared_ips)[0]})
            base_confidence = max(base_confidence, 0.8)
        if shared_domains:
            matched_signals.append({"type": "shared_domain", "confidence": 0.8, "evidence": list(shared_domains)[0]})
            base_confidence = max(base_confidence, 0.8)
        if shared_apis:
            matched_signals.append({"type": "shared_api", "confidence": 0.7, "evidence": list(shared_apis)[0]})
            base_confidence = max(base_confidence, 0.7)
            
        # 4. Shared High-Risk Indicator Match
        match_factors = match.risk_factors or []
        match_indicators = set([rf["indicator"] for rf in match_factors])
        shared_indicators = high_risk_indicators.intersection(match_indicators)
        
        if shared_indicators:
            matched_signals.append({"type": "shared_indicator", "confidence": 0.7, "evidence": list(shared_indicators)[0]})
            base_confidence = max(base_confidence, 0.7)
            
        if matched_signals:
            # Bounded confidence calculation: base + (num_additional_signals * 0.05), capped at 0.95 (if base < 1.0)
            final_confidence = base_confidence
            if final_confidence < 1.0 and len(matched_signals) > 1:
                final_confidence = min(0.95, final_confidence + (len(matched_signals) - 1) * 0.05)
                
            relationship_name = matched_signals[0]["type"]
            if len(matched_signals) > 1:
                if matched_signals[0]["type"] == "same_certificate":
                    relationship_name = "same_certificate" # Cert trumps all
                else:
                    relationship_name = "multi_signal"
                    
            target_campaign = None
            if match.sample.campaigns:
                target_campaign = match.sample.campaigns[0]
            else:
                prefix = cert[:8] if cert else (sample_id[:8])
                target_campaign = Campaign(
                    name=f"Campaign-{prefix}",
                    description="Automatically correlated threat campaign.",
                    risk_score=max(analysis.risk_score or 0, match.risk_score or 0)
                )
                db.add(target_campaign)
                await db.flush()
                
                stmt_match = sample_campaign_links.insert().values(
                    sample_id=match.sample_id,
                    campaign_id=target_campaign.id,
                    relationship=relationship_name,
                    confidence=final_confidence,
                    reason=f"{len(matched_signals)} shared threat signals observed.",
                    signals=matched_signals
                )
                await db.execute(stmt_match)
                updated_campaign_ids.add(target_campaign.id)
            
            linked = await _link_to_campaign(
                db, 
                sample_id, 
                str(target_campaign.id), 
                relationship_name,
                final_confidence, 
                f"{len(matched_signals)} shared threat signals observed.",
                matched_signals,
                linked_campaign_ids
            )
            
            if linked:
                matched_campaigns.add(target_campaign)
                updated_campaign_ids.add(target_campaign.id)
                correlations_made = True

    if correlations_made:
        await db.commit()
        for cid in updated_campaign_ids:
            await recalculate_campaign_intelligence(db, cid)
        logger.info(f"Correlation completed for sample {sample_id}. Links created and intelligence recalculated.")
    else:
        logger.info(f"No correlations found for sample {sample_id}.")
