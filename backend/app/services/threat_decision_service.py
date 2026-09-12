from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import Sample, Analysis, Finding, sample_campaign_links
from app.schemas.threat_decision import (
    ThreatDecisionResponse,
    ThreatClassification,
    ConfidenceLevel,
    NoveltyStatus,
    NoveltyInfo,
    NoveltySignal,
    ThreatType,
    ImpactLevel,
    AccessScope,
    CampaignStatus,
    CampaignInfo,
    EvidenceItemResponse,
    RecommendedAction,
    ProvenanceInfo,
    AnalysisCoverage
)
import json

def _determine_analysis_coverage(analysis: Optional[Analysis], has_correlation: bool) -> AnalysisCoverage:
    coverage = AnalysisCoverage.MANIFEST_ONLY
    
    if analysis and isinstance(analysis.dex_data, dict):
        dex_data = analysis.dex_data
        if "error" not in dex_data:
            dex_files_analyzed = dex_data.get("dex_files_analyzed", 0)
            if dex_files_analyzed > 0:
                coverage = AnalysisCoverage.STATIC_DEX
                
                # Check for meaningful indicators
                keys_to_check = ["suspicious_apis", "hardcoded_ips", "urls", "domains", "encoded_strings", "decoded_indicators"]
                if any(isinstance(dex_data.get(k), list) and len(dex_data.get(k)) > 0 for k in keys_to_check):
                    coverage = AnalysisCoverage.STATIC_DEX_ENRICHED
                    
    if has_correlation:
        coverage = AnalysisCoverage.CORRELATED
        
    return coverage

async def build_threat_decision(sample: Sample, db: AsyncSession) -> ThreatDecisionResponse:
    analysis: Optional[Analysis] = sample.analysis
    findings: List[Finding] = sample.findings if hasattr(sample, 'findings') else []
    
    # --- Classification & Risk ---
    classification = ThreatClassification.UNKNOWN
    risk_score = None
    risk_status = None
    
    if analysis:
        risk_score = analysis.risk_score
        risk_status = analysis.status
        if risk_score is not None:
            if risk_score >= 80:
                classification = ThreatClassification.MALICIOUS
            elif risk_score >= 40:
                classification = ThreatClassification.SUSPICIOUS
            else:
                classification = ThreatClassification.BENIGN

    # --- Campaign ---
    camp_status = CampaignStatus.UNKNOWN
    camp_identifier = None
    if getattr(sample, "campaigns", None) and len(sample.campaigns) > 0:
        camp_status = CampaignStatus.MATCHED
        camp_identifier = str(sample.campaigns[0].id)
    
    # --- Fetch Correlations (sample_campaign_links) ---
    links_result = await db.execute(
        select(sample_campaign_links).where(sample_campaign_links.c.sample_id == sample.id)
    )
    links = links_result.all()
    
    related_sample_ids = []
    campaign_intelligence = None
    
    if camp_status == CampaignStatus.MATCHED and camp_identifier:
        rel_links_result = await db.execute(
            select(sample_campaign_links.c.sample_id)
            .where(sample_campaign_links.c.campaign_id == camp_identifier)
            .where(sample_campaign_links.c.sample_id != sample.id)
        )
        # Deduplicate while preserving order
        related_sample_ids = list(dict.fromkeys([row[0] for row in rel_links_result.all()]))
        
        camp_obj = sample.campaigns[0]
        campaign_intelligence = getattr(camp_obj, 'intelligence_summary', None)
    
    # --- Novelty Signals ---
    novelty_signals = []
    
    # 1. SHA256 Signal
    # CiphR deduplicates local uploads. Unless a threat intel feed or correlation 
    # explicitly provides an 'exact_sha256' match, the hash is considered UNSEEN.
    has_exact_sha256 = False
    
    # We will append the SHA256 signal later after checking links.
        
    # 2. Campaign Signal
    if camp_status == CampaignStatus.MATCHED:
        novelty_signals.append(NoveltySignal(type="CAMPAIGN", state="MATCHED", campaign_id=camp_identifier))
        
    # 3. Analyze Link Signals (TLSH, Cert, Domain, etc)
    has_tlsh_similarity = False
    has_cert_match = False
    has_domain_match = False
    
    for link in links:
        # link is a Row mapping to sample_campaign_links columns
        # columns: sample_id, campaign_id, relationship, confidence, reason, signals
        raw_signals = getattr(link, "signals", []) or []
        for sig in raw_signals:
            stype = sig.get("type")
            sevidence = str(sig.get("evidence", ""))
            
            if stype == "exact_sha256":
                has_exact_sha256 = True
                
            elif stype == "tlsh_similarity":
                has_tlsh_similarity = True
                distance = None
                if sevidence.startswith("diff:"):
                    try:
                        distance = int(sevidence.split(":")[1])
                    except:
                        pass
                novelty_signals.append(NoveltySignal(type="TLSH_SIMILARITY", state="STRONG", distance=distance))
                
            elif stype == "same_certificate":
                has_cert_match = True
                novelty_signals.append(NoveltySignal(type="CERTIFICATE", state="KNOWN"))
                
            elif stype == "shared_domain":
                has_domain_match = True
                novelty_signals.append(NoveltySignal(type="DOMAIN", state="KNOWN"))

    if has_exact_sha256:
        novelty_signals.append(NoveltySignal(type="SHA256", state="KNOWN"))
    else:
        novelty_signals.append(NoveltySignal(type="SHA256", state="UNSEEN"))

    # 4. Track explicitly missing providers as UNKNOWN/MISSING, not negative
    has_tlsh_provider = False
    if analysis and analysis.tlsh and not str(analysis.tlsh).startswith("ERROR"):
        has_tlsh_provider = True

    # Check multiple independent newness signals
    # Newness implies UNSEEN SHA256 + new infrastructure + distinct behavioral finding.
    # We infer "new domain" if the sample has a domain finding, but no shared_domain correlation.
    has_network_findings = any("network" in (f.category or "").lower() or "domain" in (f.category or "").lower() for f in findings)
    
    # Require multiple distinct categories of findings to consider it functionally "novel" behavior
    # rather than just a single new domain. This avoids substituting risk score for novelty.
    distinct_finding_categories = set((f.category or "").lower() for f in findings if (f.category or "").lower() not in ("network", "domain", ""))
    
    multiple_newness = False
    if has_network_findings and not has_domain_match and len(distinct_finding_categories) >= 1:
        multiple_newness = True

    # --- Novelty Logic Hierarchy ---
    novelty_status = NoveltyStatus.UNKNOWN
    explanation = "Insufficient evidence to determine novelty."
    
    # Check if SHA256 is KNOWN
    sha256_known = any(s.type == "SHA256" and s.state == "KNOWN" for s in novelty_signals)
    
    if sha256_known:
        novelty_status = NoveltyStatus.KNOWN
        explanation = "Exact SHA256 match found in historical intelligence."
    elif has_tlsh_similarity or has_cert_match or camp_status == CampaignStatus.MATCHED:
        novelty_status = NoveltyStatus.VARIANT
        explanation = "Unseen hash but strong structural similarity or shared indicators to previously observed samples."
    elif multiple_newness:
        novelty_status = NoveltyStatus.POTENTIALLY_NOVEL
        explanation = "Unseen hash with multiple independent newness signals and no strong historical relationships."
    else:
        # Insufficient evidence
        novelty_status = NoveltyStatus.UNKNOWN
        explanation = "Insufficient relationship evidence to classify novelty."
        
    # Append missing providers
    if not has_tlsh_provider:
        novelty_signals.append(NoveltySignal(type="TLSH_SIMILARITY", state="MISSING"))
        
    novelty_info = NoveltyInfo(
        status=novelty_status,
        signals=novelty_signals,
        related_samples=related_sample_ids,
        explanation=explanation
    )

    # --- Threat Types & Access Scope ---
    threat_types = set()
    access_scope = AccessScope.UNKNOWN
    impact_level = ImpactLevel.UNKNOWN
    
    has_critical_findings = False
    has_high_findings = False
    
    for f in findings:
        title = f.title.lower() if getattr(f, 'title', None) else ""
        desc = f.description.lower() if getattr(f, 'description', None) else ""
        cat = f.category.lower() if getattr(f, 'category', None) else ""
        sev = f.severity.upper() if getattr(f, 'severity', None) else "INFO"
        
        if sev == "CRITICAL":
            has_critical_findings = True
            impact_level = ImpactLevel.HIGH
        elif sev == "HIGH":
            has_high_findings = True
            if impact_level == ImpactLevel.UNKNOWN:
                impact_level = ImpactLevel.MEDIUM
                
        if "bank" in title or "bank" in desc:
            threat_types.add(ThreatType.BANKING_TROJAN)
        if "credential" in title or "credential" in desc:
            threat_types.add(ThreatType.CREDENTIAL_THEFT)
        if "sms" in title or "sms" in desc:
            threat_types.add(ThreatType.SMS_ABUSE)
        if "accessibility" in title or "accessibility" in desc:
            threat_types.add(ThreatType.ACCESSIBILITY_ABUSE)
            access_scope = AccessScope.FULL_DEVICE
        if "overlay" in title or "overlay" in desc:
            threat_types.add(ThreatType.OVERLAY)
        if "camera" in title or "audio" in title or "location" in title:
            threat_types.add(ThreatType.SURVEILLANCE)
            if access_scope != AccessScope.FULL_DEVICE:
                access_scope = AccessScope.SENSITIVE_SUBSYSTEM
        if "background" in title or "receiver" in title:
            if access_scope in (AccessScope.UNKNOWN, AccessScope.NETWORK_ONLY):
                access_scope = AccessScope.BACKGROUND_ONLY
        if "network" in cat or "url" in cat or "ip" in cat or "internet" in title or "internet" in desc:
            if access_scope == AccessScope.UNKNOWN:
                access_scope = AccessScope.NETWORK_ONLY
                
    if not threat_types and classification == ThreatClassification.MALICIOUS:
        threat_types.add(ThreatType.UNKNOWN)
        
    if impact_level == ImpactLevel.UNKNOWN:
        if classification == ThreatClassification.MALICIOUS:
            impact_level = ImpactLevel.HIGH
        elif classification == ThreatClassification.BENIGN:
            impact_level = ImpactLevel.LOW
            
    # --- Confidence ---
    confidence = ConfidenceLevel.UNKNOWN
    if classification != ThreatClassification.UNKNOWN:
        if camp_status == CampaignStatus.MATCHED:
            confidence = ConfidenceLevel.HIGH
        elif has_critical_findings:
            confidence = ConfidenceLevel.HIGH
        elif has_high_findings:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW

    # --- Recommended Action ---
    recommended_action = RecommendedAction.UNKNOWN
    if classification == ThreatClassification.MALICIOUS:
        recommended_action = RecommendedAction.BLOCK
    elif classification == ThreatClassification.SUSPICIOUS:
        recommended_action = RecommendedAction.INVESTIGATE
    elif classification == ThreatClassification.BENIGN:
        recommended_action = RecommendedAction.ALLOW

    # --- Evidence ---
    evidence_items = []
    if analysis:
        # Add EMBER as evidence
        if getattr(analysis, 'threat_narrative', None):
            evidence_items.append(EvidenceItemResponse(
                source="EMBER_ML",
                finding="EMBER Classification",
                severity="HIGH" if risk_score and risk_score >= 80 else "INFO",
                material_contribution=True
            ))
            
    for f in findings:
        evidence_items.append(EvidenceItemResponse(
            source=f.category or "STATIC",
            finding=f.title,
            severity=f.severity,
            material_contribution=(f.severity in ("CRITICAL", "HIGH"))
        ))
        
    # --- Provenance ---
    provenance = ProvenanceInfo(
        source_type=sample.source_type,
        source_url=sample.source_url,
        sha256=sample.sha256,
        analysis_timestamp=analysis.started_at if analysis else None
    )

    # --- Analysis Coverage ---
    has_link_signals = any(bool(getattr(link, "signals", []) or []) for link in links)
    has_correlation = (camp_status == CampaignStatus.MATCHED) or has_link_signals
    analysis_coverage = _determine_analysis_coverage(analysis, has_correlation)

    return ThreatDecisionResponse(
        classification=classification,
        risk_score=risk_score,
        risk_status=risk_status,
        confidence=confidence,
        novelty=novelty_info,
        threat_types=list(threat_types),
        impact=impact_level,
        access_scope=access_scope,
        campaign=CampaignInfo(
            status=camp_status,
            identifier=camp_identifier,
            related_samples_count=len(related_sample_ids),
            related_sample_ids=related_sample_ids,
            intelligence=campaign_intelligence
        ),
        evidence=evidence_items,
        recommended_action=recommended_action,
        provenance=provenance,
        analysis_coverage=analysis_coverage
    )
