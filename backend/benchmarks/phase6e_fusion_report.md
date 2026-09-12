# Phase 6E — Evidence Fusion Architecture Report

## 1. Executive Summary

Phase 6E established a new Evidence Fusion Architecture designed to safely represent, correlate, corroborate, and reason over heterogeneous evidence within CiphR. The objective was to transition away from the assumption that a single model (or single static analyzer) produces an absolute verdict, towards a multi-source "Evidence Ledger" model. 

Crucially, this phase was executed entirely as an offline architectural abstraction. **No raw malicious APKs were downloaded, and the production risk-scoring boundary (API, Risk Engine, DB schema) remains 100% untouched.**

## 2. Current Architecture Assessment

The existing CiphR risk architecture relies on a linear, single-pass pipeline (`pipeline_service.py`):
`Static Analysis -> Risk Score -> Correlation Engine -> LLM Narrative`.

While effective for static rules, it fails to safely accommodate ML models like EMBER. If EMBER fails, or if it contradicts Static Analysis, the current architecture has no semantic capability to resolve the conflict without applying arbitrary mathematical weights (e.g., `final_score = static * 0.4 + ember * 0.6`).

## 3. Evidence Sources

The new abstraction (`app/fusion/evidence.py`) formalizes the following distinct evidence sources:
- **STATIC:** Indicators from Androguard, DEX parsing, Certificates.
- **EMBER:** Output from the EMBER2024 LightGBM model.
- **TLSH:** Similarity metrics from the Trend Micro Locality Sensitive Hash.
- **VT:** Threat Intelligence from VirusTotal.
- **NETWORK:** C2, DNS, and IP intelligence.
- **LLM:** Generative AI interpretation/hypotheses.
- **CAMPAIGN:** Association with known threat clusters.

## 4. Evidence Representation

A common internal representation (`EvidenceItem`) was established:
- `evidence_id`: UUID
- `source`: `EvidenceSource` Enum
- `availability`: `AVAILABLE`, `UNAVAILABLE`, `FAILED`, `NOT_APPLICABLE`
- `evidence_type`: `POSITIVE` (Malicious), `NEGATIVE` (Benign), `NEUTRAL`
- `indicator`: A string describing the finding.
- `value`: The raw output (e.g. `0.95`).
- `semantics`: Human-readable context.
- `strength` & `reliability`: Bounded `[0.0, 1.0]` floats.
- `provenance`: Dictionary tracking versions (e.g., model version).
- `derived_from`: List of parent UUIDs to prevent double-counting.

Multiple `EvidenceItem` objects are aggregated into an `EvidenceLedger` for a specific sample.

## 5. Evidence Strength vs Source Reliability vs Decision Confidence

These three concepts were explicitly disambiguated in the architecture:
- **Strength:** The inherent weight of the finding itself (e.g., finding the `spymax` package name has high strength).
- **Source Reliability:** The trust in the provider (e.g., an LLM hypothesis has low reliability, whereas a cryptographic signature match has 1.0 reliability).
- **Decision Confidence (Fusion Result):** The final confidence of the `FusionResult`, derived from the corroboration of multiple high-strength, high-reliability independent sources.

## 6. Missing Evidence Semantics

The architecture explicitly tracks missing evidence.
- `UNAVAILABLE`: The evidence source was not configured or skipped.
- `FAILED`: The evidence source threw an exception.
**Missing evidence is NOT negative evidence.** If EMBER fails, the system logs the failure and evaluates the remaining evidence without assuming the sample is benign.

## 7. Corroboration Model

Corroboration is defined as multiple *independent* sources providing `POSITIVE` (or `NEGATIVE`) evidence. The `engine.py` logic creates a `corroborated_clusters` list. Rather than adding scores (e.g., `0.9 + 0.8 = 1.7`), the engine structurally validates that `N > 1` independent sources agree. The engine returns `CORROBORATED` (updated in Phase 6E.2) rather than making a final malware verdict itself.

## 8. Conflict Model

Conflicts occur when `POSITIVE` evidence contradicts `NEGATIVE` evidence, regardless of strength (updated in Phase 6E.2 to ensure strong positive evidence does not silently erase moderate negative evidence). The engine traps this state and returns `FusionStatus.CONFLICTED`, preserving the exact conflicting sources for manual or automated resolution, rather than averaging the scores to a meaningless neutral value.

## 9. Double-Counting Risks

To prevent double-counting (e.g., LLM interpreting a Static finding, and both contributing to the malicious score), the `EvidenceItem` includes a `derived_from` field. The `engine.py` explicitly deduplicates positive evidence by verifying that corroborating evidence is not derived from another item in the ledger.

## 10. EMBER Integration Semantics

EMBER evidence must preserve:
- `provenance` (Model version and Feature Extractor version).
- The raw `score` is not a probability; it is a model activation output.
- The `semantics` string enforces that it is a model confidence score, not a calibrated percentage.

## 11. LLM Evidence Semantics

LLM output is treated strictly as **interpretation** and **hypothesis**, not ground truth. It carries low `reliability` and will frequently use the `derived_from` field to point back to the raw Static or EMBER findings it was asked to analyze.

## 12. TLSH Evidence Semantics

TLSH evidence is treated as similarity, not ground truth. High similarity to a known malicious cluster provides strong contextual evidence, but its `evidence_type` depends entirely on the reputation of the reference sample.

## 13. Threat Intelligence Semantics

VT/External intel is captured as `VT` source evidence. It is highly reliable but not infallible (vendors frequently false-positive).

## 14. Campaign Intelligence Semantics

Campaign association provides contextual `NEUTRAL` or `POSITIVE` evidence, but must trace its `derived_from` lineage back to the shared indicators (IPs, certificates) that caused the correlation, to prevent compounding double-counting.

## 15. Proposed Fusion Architecture

The offline `FusionEngine` takes an `EvidenceLedger` and outputs a `FusionResult`. It analyzes missing providers, extracts and deduplicates independent signals, detects Corroboration and Conflicts, and assigns a final structural `FusionStatus` (`CORROBORATED`, `CONFLICTED`, `INSUFFICIENT`, `UNRESOLVED`, `NEGATIVE_EVIDENCE_FOUND`).

## 16. Offline Synthetic Scenarios

The architecture was validated via 5 synthetic scenarios in `tests/test_fusion.py`:
- **Scenario A:** EMBER Unavailable -> Correctly resolved as `INSUFFICIENT` without assuming benignity.
- **Scenario B:** EMBER + Static -> Correctly identified as `RESOLVED_MALICIOUS` corroboration.
- **Scenario C:** Multi-Source Corroboration -> Clustered successfully.
- **Scenario D:** Conflict -> Correctly identified as `CONFLICTED`.
- **Scenario E:** EMBER Failure + Other Evidence -> Degraded gracefully to remaining evidence.

## 17. Test Results
The fusion architecture unit tests passed 100%.

## 18. Regression Results
The full CiphR test suite (`pytest tests/`) passed successfully (with the single pre-existing `test_concurrent_duplicate_upload` flake). The production API, database, and pipeline remain unaffected.

## 19. Security/Isolation Verification

- **Zero malicious APKs were downloaded or installed.**
- **No emulators or dynamic analysis tools were executed.**
- **No arbitrary websites were accessed.**

## 20. Files Changed (Created)
- `app/fusion/__init__.py`
- `app/fusion/evidence.py`
- `app/fusion/engine.py`
- `tests/test_fusion.py`
- `benchmarks/phase6e_fusion_report.md`
- `walkthrough.md`
- `implementation_plan.md`
- `task.md`

## 21. Files NOT Changed
- `app/services/pipeline_service.py`
- `app/api/routes/*`
- `app/db/models.py`
- `app/schemas/*`
- `app/ember/*`

## 22. Git Status
All modifications are untracked additions inside `app/fusion`, `tests/test_fusion.py`, and `benchmarks/`. No production code was modified. No commits or pushes have been made.

## 23. Known Limitations

- **Offline Only:** The fusion engine is currently an isolated offline abstraction. It is not hooked up to the REST API or the PostgreSQL database.
- **Raw Malware Missing:** As decided in Phase 6D.3, we still lack a secure sandbox and a raw malicious APK corpus to validate the complete end-to-end `thrember` extractor on real-world malware.

## 24. Recommended Phase 6F

Phase 6F should focus on safely integrating the `FusionEngine` into `app/services/pipeline_service.py` behind a feature flag, allowing the legacy Risk Score and the new `EvidenceLedger` to run in parallel on production incoming samples. This will allow monitoring of the new architecture's behavior on live benign traffic without disrupting existing service contracts.
