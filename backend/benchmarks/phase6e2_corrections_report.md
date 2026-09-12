# Phase 6E.2 — Evidence Fusion Design Corrections

## 1. Audit Finding Being Corrected
The Phase 6E.1 audit identified two primary architectural flaws:
1. `FusionEngine` accidentally acted as a prescriptive verdict engine by returning `RESOLVED_MALICIOUS`.
2. The conflict handler silently suppressed moderate negative evidence (`strength < 0.8`) when faced with strong positive evidence.

## 2. Original Problem
The original implementation used arbitrary numerical thresholds (e.g., `strength >= 0.9 and reliability >= 0.9`) to jump to a final malware conclusion. This violated the core mandate of Phase 6E, which required the `FusionEngine` to serve merely as a structural reasoning layer (identifying corroboration, conflict, missing data, and provenance) without making final verdicts.

## 3. Correction Implemented
- Redesigned `FusionStatus` to only describe the state of the evidence.
- Removed all hardcoded `strength` thresholds from `evaluate_ledger`.
- Refactored conflict detection to trigger whenever any `POSITIVE` and `NEGATIVE` evidence items co-occur, regardless of strength, preserving both sides.

## 4. New FusionStatus Semantics
- `CORROBORATED`: Multiple independent positive sources exist.
- `CONFLICTED`: Both positive and negative indicators are present.
- `INSUFFICIENT`: No positive or negative indicators are available (or expected providers failed).
- `UNRESOLVED`: Only a single positive indicator exists; lacks structural corroboration.
- `NEGATIVE_EVIDENCE_FOUND`: Negative indicators exist with no positive indicators.

## 5. Corroboration Semantics
Corroboration is strictly structural. If multiple independent sources produce positive findings, they are grouped into a `MALICIOUS_CORROBORATION` cluster. No numerical score is generated.

## 6. Conflict Semantics
Conflicts now preserve both sides completely. A weak negative finding (e.g., a known good certificate) will successfully conflict with a strong positive finding (e.g., EMBER score of 0.99). This forces downstream components (or human analysts) to explicitly resolve the discrepancy rather than having it silently erased by an arbitrary threshold.

## 7. Why Arbitrary Thresholds Were Removed
Arbitrary thresholds (`> 0.9`) encode hidden assumptions about what constitutes a definitive conviction. By removing them, the `FusionEngine` correctly defers the final verdict logic to higher-level decision nodes (or Phase 6F integration) while retaining its role as an objective evidence structurer.

## 8. Evidence Strength vs Decision Confidence
`strength` remains an attribute of `EvidenceItem` for future explanation, ordering, or manual review, but it no longer influences the deterministic structural outputs (Corroboration/Conflict) of the engine.

## 9. Provenance / Double-Counting
The `derived_from` lineage is maintained. Derived evidence (like an LLM hypothesis based on a static string) does not count as an independent corroborating source.

## 10. Missing Evidence
Missing or failed evidence explicitly remains missing (`UNAVAILABLE` or `FAILED`). It is never coerced into a negative indicator.

## 11. EMBER Semantics
EMBER semantics are unchanged. The raw score remains an unaltered LightGBM output. The engine does not calibrate or threshold it.

## 12. Test Results
- `pytest tests/test_fusion.py -v`: 7/7 passing (added `test_moderate_negative_conflict`).
- `pytest tests/test_ember.py -v`: 9/9 passing.
- `pytest tests/ -q`: 42/42 passing.

## 13. Regression Results
All regression tests passed. The core logic handles missing, failed, and valid EMBER inference identical to Phase 6D.

## 14. Files Changed
- `app/fusion/engine.py`
- `tests/test_fusion.py`
- `benchmarks/phase6e_fusion_report.md` (Updated)

## 15. Files Not Changed
- `app/fusion/evidence.py`
- `app/services/pipeline_service.py`
- `app/api/*`
- `app/db/*`

## 16. Security Verification
- No raw malicious APKs were downloaded.
- No malware was executed.

## 17. Production Boundary Verification
The production API, risk scoring pipeline, database schema, and existing analysis engines remain entirely untouched. 

## 18. Remaining Limitations
The `FusionEngine` remains an offline abstraction. It requires integration with the live pipeline (Phase 6F) to operate on real incoming traffic.

## 19. Readiness for Phase 6F
**READY.**

The FusionEngine does not produce a final malware verdict.
No arbitrary numerical fusion thresholds or weights are used.
