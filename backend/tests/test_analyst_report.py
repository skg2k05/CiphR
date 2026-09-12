import pytest
from app.services.analyst_report_service import build_analyst_report
from app.schemas.threat_decision import (
    ThreatDecisionResponse,
    ThreatClassification,
    ConfidenceLevel,
    NoveltyStatus,
    NoveltyInfo,
    NoveltySignal,
    ImpactLevel,
    AccessScope,
    ThreatType,
    CampaignStatus,
    CampaignInfo,
    EvidenceItemResponse,
    RecommendedAction,
    ProvenanceInfo,
    AnalysisCoverage
)

def _create_base_decision() -> ThreatDecisionResponse:
    return ThreatDecisionResponse(
        classification=ThreatClassification.UNKNOWN,
        confidence=ConfidenceLevel.UNKNOWN,
        novelty=NoveltyInfo(status=NoveltyStatus.UNKNOWN, signals=[], related_samples=[], explanation=""),
        impact=ImpactLevel.UNKNOWN,
        access_scope=AccessScope.UNKNOWN,
        threat_types=[],
        campaign=CampaignInfo(status=CampaignStatus.UNKNOWN, related_samples_count=0),
        evidence=[],
        recommended_action=RecommendedAction.UNKNOWN,
        provenance=ProvenanceInfo(source_type="upload", sha256="123"),
        analysis_coverage=AnalysisCoverage.MANIFEST_ONLY
    )

def test_malicious_report():
    decision = _create_base_decision()
    decision.classification = ThreatClassification.MALICIOUS
    decision.confidence = ConfidenceLevel.HIGH
    decision.novelty.status = NoveltyStatus.VARIANT
    decision.novelty.signals = [
        NoveltySignal(type="SHA256", state="UNSEEN"),
        NoveltySignal(type="TLSH_SIMILARITY", state="STRONG", distance=20)
    ]
    decision.threat_types = [ThreatType.CREDENTIAL_THEFT, ThreatType.OVERLAY]
    decision.recommended_action = RecommendedAction.QUARANTINE
    decision.campaign = CampaignInfo(status=CampaignStatus.MATCHED, identifier="campaign_123", related_samples_count=5)
    decision.analysis_coverage = AnalysisCoverage.CORRELATED
    
    report = build_analyst_report(decision)
    
    assert report.verdict == ThreatClassification.MALICIOUS
    assert report.analysis_coverage == AnalysisCoverage.CORRELATED
    assert "Malicious APK with high confidence" in report.deterministic_summary
    assert "variant of previously observed samples" in report.deterministic_summary
    assert "credential theft, overlay behavior" in report.deterministic_summary
    assert "Recommended action: QUARANTINE" in report.deterministic_summary
    
    assert len(report.historical_context) == 1
    assert report.historical_context[0].type == "TLSH_SIMILARITY"
    assert "STRONG (Distance 20)" in report.historical_context[0].evidence
    
    assert report.campaign is not None
    assert report.campaign.status == CampaignStatus.MATCHED
    assert report.campaign.related_samples_count == 5

def test_benign_report():
    decision = _create_base_decision()
    decision.classification = ThreatClassification.BENIGN
    decision.confidence = ConfidenceLevel.HIGH
    decision.novelty.status = NoveltyStatus.UNKNOWN
    decision.recommended_action = RecommendedAction.ALLOW
    
    report = build_analyst_report(decision)
    
    assert report.verdict == ThreatClassification.BENIGN
    assert "Benign APK with high confidence" in report.deterministic_summary
    assert "insufficient to determine novelty" in report.deterministic_summary
    assert "Recommended action: ALLOW" in report.deterministic_summary

def test_evidence_grouping():
    decision = _create_base_decision()
    decision.evidence = [
        EvidenceItemResponse(source="EMBER_ML", finding="High confidence malicious", severity="HIGH"),
        EvidenceItemResponse(source="network", finding="Connects to bad IP", severity="HIGH"),
        EvidenceItemResponse(source="permissions", finding="Requests CAMERA", severity="MEDIUM")
    ]
    decision.novelty.signals = [
        NoveltySignal(type="CERTIFICATE", state="KNOWN"),
        NoveltySignal(type="SHA256", state="UNSEEN")
    ]
    
    report = build_analyst_report(decision)
    
    assert "ML" in report.why
    assert any("High confidence malicious" in e for e in report.why["ML"])
    
    assert "NETWORK" in report.why
    assert any("Connects to bad IP" in e for e in report.why["NETWORK"])
    
    assert "STATIC" in report.why
    assert any("Requests CAMERA" in e for e in report.why["STATIC"])
    
    assert "CERTIFICATE" in report.why
    assert any("CERTIFICATE: KNOWN" in e for e in report.why["CERTIFICATE"])

def test_url_provenance():
    decision = _create_base_decision()
    decision.provenance = ProvenanceInfo(
        source_type="url",
        source_url="http://evil.com/malware.apk",
        sha256="abc"
    )
    
    report = build_analyst_report(decision)
    
    assert report.provenance.source_type == "url"
    assert report.provenance.source_url == "http://evil.com/malware.apk"

def test_potentially_novel_report():
    decision = _create_base_decision()
    decision.classification = ThreatClassification.SUSPICIOUS
    decision.confidence = ConfidenceLevel.MEDIUM
    decision.novelty.status = NoveltyStatus.POTENTIALLY_NOVEL
    decision.novelty.signals = [NoveltySignal(type="SHA256", state="UNSEEN")]
    
    report = build_analyst_report(decision)
    
    assert "potentially novel threat" in report.deterministic_summary
