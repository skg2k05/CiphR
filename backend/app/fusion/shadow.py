import json
import logging
from typing import Any, Dict, List
from datetime import datetime, timezone

from app.db.models import Sample, Analysis
from app.fusion.evidence import (
    EvidenceLedger,
    EvidenceItem,
    EvidenceSource,
    EvidenceAvailability,
    EvidenceType,
)
from app.fusion.engine import evaluate_ledger
from app.ember.classifier import classify_apk

logger = logging.getLogger("ciphr.fusion.shadow")


def _map_static_findings(ledger: EvidenceLedger, findings_data: List[Dict[str, Any]]) -> List[str]:
    """Map static findings to EvidenceItems and return their IDs for provenance."""
    static_evidence_ids = []
    
    for f in findings_data:
        # Map severity to evidence type
        severity = f.get("severity", "INFO")
        ev_type = EvidenceType.NEUTRAL
        strength = 0.5
        
        if severity == "CRITICAL":
            ev_type = EvidenceType.POSITIVE
            strength = 0.9
        elif severity == "HIGH":
            ev_type = EvidenceType.POSITIVE
            strength = 0.8
        elif severity == "MEDIUM":
            ev_type = EvidenceType.POSITIVE
            strength = 0.6
        elif severity == "LOW":
            ev_type = EvidenceType.NEUTRAL
            strength = 0.3
            
        # Treat explicitly clean indicators (e.g. good certificates) as NEGATIVE if severity is INFO
        # This is a simplification; a real implementation would have explicit 'clean' indicators.
        if severity == "INFO" and "benign" in f.get("description", "").lower():
            ev_type = EvidenceType.NEGATIVE
            strength = 0.6
            
        item = EvidenceItem(
            source=EvidenceSource.STATIC,
            evidence_type=ev_type,
            indicator=f.get("title", "Static Finding"),
            semantics=f.get("description", ""),
            strength=strength,
            reliability=0.9, # Static analysis is generally highly reliable (what you see is what you get)
            provenance={"category": f.get("category", "")}
        )
        ledger.add_evidence(item)
        static_evidence_ids.append(item.evidence_id)
        
    return static_evidence_ids


def _map_tlsh(ledger: EvidenceLedger, tlsh_value: str):
    if tlsh_value:
        ledger.add_evidence(EvidenceItem(
            source=EvidenceSource.TLSH,
            evidence_type=EvidenceType.NEUTRAL,
            indicator="TLSH Hash Computed",
            value=tlsh_value,
            semantics="Provides locality sensitive hash for clustering",
            strength=0.1,
            reliability=1.0
        ))
    else:
        ledger.add_evidence(EvidenceItem(
            source=EvidenceSource.TLSH,
            availability=EvidenceAvailability.UNAVAILABLE,
            indicator="TLSH Missing",
            semantics="No TLSH hash provided in static results."
        ))


def _map_campaign(ledger: EvidenceLedger, campaign_summary: str, parent_ids: List[str]):
    if campaign_summary:
        ledger.add_evidence(EvidenceItem(
            source=EvidenceSource.CAMPAIGN,
            evidence_type=EvidenceType.POSITIVE, # Treat known campaigns as malicious context
            indicator="Associated with known Threat Campaign",
            semantics=str(campaign_summary) if not isinstance(campaign_summary, str) else campaign_summary,
            strength=0.8,
            reliability=0.8,
            derived_from=parent_ids # Prevent double counting: Campaign association is derived from static indicators (like IPs)
        ))
    else:
        ledger.add_evidence(EvidenceItem(
            source=EvidenceSource.CAMPAIGN,
            availability=EvidenceAvailability.UNAVAILABLE,
            indicator="No Campaign",
            semantics="No campaign intelligence available."
        ))


def _map_llm(ledger: EvidenceLedger, narrative: str, parent_ids: List[str]):
    if narrative:
        ledger.add_evidence(EvidenceItem(
            source=EvidenceSource.LLM,
            evidence_type=EvidenceType.NEUTRAL, # LLM is interpretive context
            indicator="LLM Threat Narrative",
            semantics=narrative,
            strength=0.5,
            reliability=0.5, # Low reliability for LLM
            derived_from=parent_ids # LLM is derived from all static findings
        ))
    else:
        ledger.add_evidence(EvidenceItem(
            source=EvidenceSource.LLM,
            availability=EvidenceAvailability.UNAVAILABLE,
            indicator="No Narrative",
            semantics="LLM narrative generation was skipped or failed."
        ))

_ember_executor = None

async def build_ledger(
    sample: Sample, 
    static_results: Dict[str, Any], 
    findings_data: List[Dict[str, Any]], 
    campaign_summary: str, 
    narrative: str
) -> EvidenceLedger:
    ledger = EvidenceLedger(sample_id=str(sample.id))
    
    # 1. Static Analysis
    static_ids = _map_static_findings(ledger, findings_data)
    
    # 2. TLSH
    _map_tlsh(ledger, static_results.get("tlsh") or "")
    
    # 3. Campaign (Derived from static indicators)
    _map_campaign(ledger, campaign_summary, parent_ids=static_ids)
    
    # 4. LLM (Derived from static indicators)
    _map_llm(ledger, narrative, parent_ids=static_ids)
    
    # 5. EMBER (CPU-bound, run via adapter)
    try:
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        
        # Dedicated bounded executor for EMBER feature extraction and inference
        # This prevents shadow EMBER execution from starving the default asyncio threadpool
        # if multiple concurrent APKs are processed, which is critical since feature extraction takes 1-3 seconds.
        global _ember_executor
        if _ember_executor is None:
            _ember_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ember_shadow")
            
        loop = asyncio.get_running_loop()
        ember_res = await loop.run_in_executor(_ember_executor, classify_apk, str(sample.storage_path))
        
        if ember_res.inference_success:
            # Simple heuristic mapping for shadow mode. 
            # In a real system, the threshold might be empirically defined.
            # Here we map scores > 0.8 as positive, < 0.2 as negative, else neutral.
            score = ember_res.score
            ev_type = EvidenceType.NEUTRAL
            strength = 0.5
            
            if score is not None:
                if score >= 0.8:
                    ev_type = EvidenceType.POSITIVE
                    strength = score
                elif score <= 0.2:
                    ev_type = EvidenceType.NEGATIVE
                    strength = 1.0 - score
                
            ledger.add_evidence(EvidenceItem(
                source=EvidenceSource.EMBER,
                evidence_type=ev_type,
                indicator=f"EMBER {ember_res.model_version}",
                value=score,
                semantics=ember_res.score_semantics,
                strength=strength,
                reliability=0.8,
                provenance={
                    "model_name": ember_res.model_name,
                    "model_version": ember_res.model_version,
                    "feature_version": ember_res.feature_version
                }
            ))
        else:
            ledger.add_evidence(EvidenceItem(
                source=EvidenceSource.EMBER,
                availability=EvidenceAvailability.FAILED,
                indicator="EMBER Failed",
                semantics=str(ember_res.error)
            ))
            
    except Exception as e:
        logger.warning(f"Failed to run EMBER during shadow mode: {e}")
        ledger.add_evidence(EvidenceItem(
            source=EvidenceSource.EMBER,
            availability=EvidenceAvailability.FAILED,
            indicator="EMBER Execution Error",
            semantics=str(e)
        ))
        
    return ledger


async def run_shadow_fusion(
    sample: Sample, 
    analysis: Analysis, 
    static_results: Dict[str, Any], 
    findings_data: List[Dict[str, Any]], 
    campaign_summary: str, 
    narrative: str
):
    """
    Executes the FusionEngine in Shadow Mode.
    Constructs the ledger, evaluates it, and emits a structured comparison log.
    Does NOT modify the database or authoritative legacy risk score.
    """
    try:
        t0 = datetime.now(timezone.utc)
        
        # 1. Build Ledger
        ledger = await build_ledger(sample, static_results, findings_data, campaign_summary, narrative)
        
        # 2. Evaluate
        fusion_result = evaluate_ledger(ledger)
        
        t1 = datetime.now(timezone.utc)
        elapsed_ms = (t1 - t0).total_seconds() * 1000
        
        # 3. Construct comparison payload
        comparison = {
            "timestamp": t1.isoformat(),
            "sample_id": str(sample.id),
            "execution_time_ms": elapsed_ms,
            "legacy": {
                "risk_score": analysis.risk_score,
                "status": analysis.status
            },
            "shadow": {
                "fusion_status": fusion_result.status.value,
                "evidence_count": len(ledger.evidence),
                "positive_count": len(ledger.get_positive()),
                "negative_count": len(ledger.get_negative()),
                "conflict_count": len(fusion_result.conflicts),
                "corroboration_count": len(fusion_result.corroborated_clusters),
                "missing_providers": fusion_result.missing_critical_evidence
            }
        }
        
        logger.info(f"SHADOW_FUSION_COMPARISON: {json.dumps(comparison)}")
        
    except Exception as e:
        logger.error(f"Shadow Fusion encountered an unhandled exception for {sample.id}: {e}", exc_info=True)
