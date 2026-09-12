from typing import List, Dict
from app.schemas.threat_decision import ThreatDecisionResponse, NoveltyStatus, ThreatClassification, RecommendedAction
from app.schemas.threat_report import AnalystThreatReportResponse, HistoricalContextItem

def build_analyst_report(decision: ThreatDecisionResponse) -> AnalystThreatReportResponse:
    # 1. Group Evidence for "why"
    why_groups: Dict[str, List[str]] = {}
    for evidence in decision.evidence:
        # source is something like "EMBER_ML", "STATIC", "permissions", "network", "api"
        source = evidence.source.upper()
        
        # Categorize
        if source == "EMBER_ML":
            category = "ML"
        elif source in ("NETWORK", "DOMAIN", "IP"):
            category = "NETWORK"
        elif source in ("STATIC", "PERMISSIONS", "API", "SERVICE", "MANIFEST"):
            category = "STATIC"
        else:
            category = "STATIC" # Default fallback
            
        if category not in why_groups:
            why_groups[category] = []
            
        # Format the finding text
        sev_str = f" [{evidence.severity}]" if evidence.severity else ""
        finding_text = f"{evidence.finding}{sev_str}"
        if finding_text not in why_groups[category]:
            why_groups[category].append(finding_text)
            
    # Also add Structural/Campaign/Novelty signals to "why"
    for sig in decision.novelty.signals:
        if sig.state not in ("UNSEEN", "MISSING"):
            category = "STRUCTURAL"
            if sig.type == "CERTIFICATE":
                category = "CERTIFICATE"
            elif sig.type == "CAMPAIGN":
                category = "CAMPAIGN"
            
            if category not in why_groups:
                why_groups[category] = []
                
            sig_text = f"{sig.type}: {sig.state}"
            if sig.distance is not None:
                sig_text += f" (Distance: {sig.distance})"
            if sig.campaign_id:
                sig_text += f" (Campaign: {sig.campaign_id})"
                
            why_groups[category].append(sig_text)

    # 2. Historical Context
    historical_context = []
    for sig in decision.novelty.signals:
        if sig.state not in ("UNSEEN", "MISSING"):
            text = sig.state
            if sig.distance is not None:
                text += f" (Distance {sig.distance})"
            historical_context.append(HistoricalContextItem(type=sig.type, evidence=text))

    # 3. Deterministic Summary Generation
    summary_parts = []
    
    # Sentence 1: Risk & Confidence
    cls_str = decision.classification.value.capitalize()
    conf_str = decision.confidence.value.lower()
    summary_parts.append(f"{cls_str} APK with {conf_str} confidence.")
    
    # Sentence 2: Novelty
    hash_status = "unseen" if any(s.type == "SHA256" and s.state == "UNSEEN" for s in decision.novelty.signals) else "known"
    nov_status = decision.novelty.status
    if nov_status == NoveltyStatus.KNOWN:
        summary_parts.append("The file hash is known in historical intelligence.")
    elif nov_status == NoveltyStatus.VARIANT:
        summary_parts.append(f"The file hash is {hash_status}, but structural correlation indicates a variant of previously observed samples.")
    elif nov_status == NoveltyStatus.POTENTIALLY_NOVEL:
        summary_parts.append(f"The file hash is {hash_status}, and infrastructure indicators suggest a potentially novel threat.")
    else:
        summary_parts.append(f"The file hash is {hash_status}, and historical correlation is insufficient to determine novelty.")
        
    # Sentence 3: Threat Types
    if decision.threat_types and decision.threat_types[0].value != "UNKNOWN":
        types_str = ", ".join([t.value.lower().replace("_", " ") for t in decision.threat_types])
        summary_parts.append(f"The sample is associated with {types_str} behavior.")
        
    # Sentence 4: Recommended Action
    rec_str = decision.recommended_action.value
    summary_parts.append(f"Recommended action: {rec_str}.")
    
    deterministic_summary = " ".join(summary_parts)

    return AnalystThreatReportResponse(
        verdict=decision.classification,
        risk_score=decision.risk_score,
        confidence=decision.confidence,
        novelty=decision.novelty,
        impact=decision.impact,
        access_scope=decision.access_scope,
        threat_types=decision.threat_types,
        campaign=decision.campaign,
        why=why_groups,
        historical_context=historical_context,
        recommended_action=decision.recommended_action,
        provenance=decision.provenance,
        deterministic_summary=deterministic_summary
    )
