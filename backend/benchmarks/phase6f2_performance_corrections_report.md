# Phase 6F.2 — Shadow Performance & Operational Corrections

## 1. Phase 6F.1 Findings
The Phase 6F.1 read-only audit classified the shadow integration as **PASS WITH CORRECTIONS**. The primary findings were:
1. The documentation significantly underestimated the computational overhead of the EMBER shadow execution, erroneously claiming 10-15 ms.
2. The `classify_apk` execution, which takes 1-3 seconds per APK for feature extraction, was running on the default `asyncio` ThreadPoolExecutor, posing a concurrency starvation risk for other backend tasks during sustained production load.

## 2. Documentation Corrections
`benchmarks/phase6f_shadow_integration_report.md` has been updated to remove the 10-15 ms total claim. The performance section now explicitly distinguishes between LightGBM inference time (< 15 ms) and feature extraction time (1-3 seconds), establishing the true baseline overhead of the shadow execution.

## 3. EMBER Performance Breakdown
- **LightGBM Model Inference:** $< 15$ ms
- **Feature Extraction:** $\approx 1-3$ seconds
- **Model Initialization:** Model initialization is correctly cached as a singleton in `app/ember/classifier.py`, meaning the disk I/O cost of loading the LightGBM model is only paid once on first invocation.

## 4. classify_apk() Timing
The total time to execute `classify_apk()` in the current environment is heavily dominated by static parsing of the APK file to extract raw EMBER features. This time varies by sample size and host environment but consistently takes at least one second per file.

## 5. Shadow Overhead
Because shadow fusion runs synchronously relative to the background analysis pipeline, enabling `FUSION_SHADOW_ENABLED` directly adds $\approx 1-3$ seconds to the total legacy processing time per sample.

## 6. Threadpool Analysis
The default `loop.run_in_executor(None, ...)` relies on a global, unbounded (or loosely bounded depending on Python version) threadpool meant for brief blocking operations. Executing multi-second CPU-bound feature extraction on this pool under heavy concurrent API load could starve standard background I/O operations (like database commits).

## 7. Concurrency Design
To mitigate the starvation risk, `app/fusion/shadow.py` was updated to initialize and utilize a dedicated bounded executor:
`ThreadPoolExecutor(max_workers=2, thread_name_prefix="ember_shadow")`
This restricts concurrent shadow EMBER executions to a safe limit. If more concurrent APKs are processed, they will queue safely without destabilizing the broader application or exhausting server threads.

## 8. Model Initialization Analysis
No changes were required for model initialization. The `app/ember/classifier.py` implementation relies on a lazy-loaded `_model_instance`, ensuring the model is loaded safely and exactly once.

## 9. Changes Implemented
- Updated `app/fusion/shadow.py` to route `classify_apk` through a dedicated, bounded `ThreadPoolExecutor`.
- Corrected the performance claims in `benchmarks/phase6f_shadow_integration_report.md`.

## 10. Test Results
All regression and integration tests were re-executed:
- `pytest tests/test_shadow_integration.py -v`: 3/3 PASS
- `pytest tests/test_fusion.py -v`: 7/7 PASS
- `pytest tests/test_ember.py -v`: 9/9 PASS
- `pytest tests/ -q`: 45/45 PASS

## 11. Performance Results
- The integration remains safe.
- The threadpool boundary successfully limits concurrent shadow executions.
- Baseline pipeline timing is unaffected when shadow is disabled.

## 12. Legacy Result Invariant
Re-verified. Shadow mode execution, even with the new bounded executor, is tightly wrapped in a `try...except` block, ensuring legacy `process_sample_pipeline` results remain perfectly authoritative and structurally unchanged.

## 13. Failure Isolation
Re-verified. Any failure in the bounded executor propagates safely as an `EvidenceAvailability.FAILED` state within the `EvidenceLedger` or falls back to the outer catch-all logger without crashing the legacy pipeline.

## 14. Security Verification
- No raw malicious APKs downloaded.
- No malware executed.
- No new external repositories accessed.

## 15. Production Boundary Verification
- The production authoritative API, Database schema, Risk Engine, and Frontend remain absolutely untouched. 

## 16. Known Limitations
- The bounded executor sets `max_workers=2`. While safe, this creates a potential throughput bottleneck specifically for shadow analysis. If a massive burst of APKs is uploaded, shadow fusion will queue up, extending total pipeline time for those queued files. This is acceptable for observation but should be tuned if Fusion becomes authoritative.

## 17. Recommendation for Phase 6G
Phase 6F.2 corrects all Phase 6F.1 findings. The system is structurally safe and operationally bounded. Phase 6G should now focus on observability (e.g., frontend visual analytics to inspect the Shadow Evidence Ledger for analysts) rather than further backend architectural redesigns.

---
**Final Classification:** PASS

All required corrections have been implemented. The shadow execution risk is safely bounded and properly documented.
