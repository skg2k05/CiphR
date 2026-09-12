# Phase 6D.1 -- EMBER2024 Android Discriminative Validation Report

## A. Status

**BLOCKED -- INSUFFICIENT GROUND TRUTH**

The validation harness executed successfully. The EMBER2024 adapter produces consistent, deterministic inference on all available APK samples. However, **no confirmed malicious APK samples exist in the local corpus**, making it impossible to compute discriminative metrics (ROC-AUC, PR-AUC, score separation, or ranking analysis).

The validation did produce useful benign-baseline and feature-activation analysis.

---

## B. Corpus

### Composition

```
Total samples:  4
Benign:         2
Malicious:      0
Synthetic:      2
Unique SHA256:  4
Real-world APK: 2
Synthetic:      2
```

### Full Inventory

| Filename | SHA256 | Label | Size | Real APK | Valid ZIP | Provenance |
|----------|--------|-------|------|----------|----------|------------|
| ApiDemos-debug.apk | `354b5660...` | benign | 4,809,449 | Yes | Yes | Android SDK sample (io.appium.android.apis) |
| ApiDemos-debug2.apk | `4a571ee9...` | benign | 4,809,462 | Yes | Yes | Android SDK sample variant |
| dummy.apk | `c6b8f2e6...` | synthetic | 177 | No | Yes | Synthetic test fixture (minimal ZIP) |
| dummy2.apk | `d6f17581...` | synthetic | 6 | No | No | Synthetic test fixture (not valid APK) |

### Quality Checks

- All files exist: **YES**
- All files are regular files: **YES**
- All files are non-empty: **YES**
- No duplicate SHA256 values: **YES**
- All labels are explicit: **YES**
- No train/test contamination: N/A (no EMBER2024 training data available locally)

---

## C. Methodology

1. Ran the existing Phase 6D `classify_apk()` adapter (from `app/ember/classifier.py`) against every sample in the corpus.
2. No second EMBER implementation was created.
3. Feature activation was analyzed by extracting the 2568-dimensional vector and examining which of the 12 feature sub-groups produced non-zero values for APK files.
4. CiphR static analysis was run offline using `androguard` and the existing `INDICATOR_RULES` from `apk_analysis_service.py`, without database writes.
5. Determinism was verified with 3 runs on 3 representative samples.
6. Performance was measured per-sample with separate model-load, feature-extraction, and inference timings.

---

## D. Feature Pipeline

| Property | Value |
|----------|-------|
| Extractor | `thrember.features.PEFeatureExtractor` |
| Feature version | `thrember-PEFeatureExtractor-v3` |
| Expected dimension | 2568 |
| Actual dimension (all samples) | **2568** |
| Model file | `EMBER2024_APK.model` |
| Model num_features | 2568 |
| Model num_trees | 500 |

### Critical Provenance Correction

The Phase 6D report stated EMBER was "PE-centric" and treated APKs as "opaque binary blobs." **This was partially incorrect.**

From the [EMBER2024 README](https://github.com/FutureComputing4AI/EMBER2024):

> *"We show that effective classifiers for APK, ELF, and PDF files can be trained using just features from general file info, byte statistics, and string statistics."*

The `EMBER2024_APK.model` is an **APK-specific LightGBM classifier** trained on **208,000 APK training samples + 48,000 APK test samples** from VirusTotal. The feature extractor uses a **subset** of the full 2568-dim feature space that is meaningful for non-PE files.

---

## E. Score Semantics

> **EMBER score is model evidence, not a calibrated probability of maliciousness.**

The raw LightGBM output is a model confidence value for binary classification (benign=0, malicious=1). It has NOT been calibrated. A score of 0.3984 does NOT mean "39.84% probability of malware."

---

## F. Score Distribution

### Benign APKs (n=2)

| Metric | Value |
|--------|-------|
| Count | 2 |
| Min | 0.398387 |
| Max | 0.398387 |
| Mean | 0.398387 |
| Median | 0.398387 |
| StDev | 0.0 |

### Malicious APKs (n=0)

**No confirmed malicious samples available.**

### Synthetic (n=2, not used for classification)

| Metric | Value |
|--------|-------|
| Count | 2 |
| Min | 0.010087 |
| Max | 0.023504 |
| Mean | 0.016795 |
| Median | 0.016795 |
| StDev | 0.009488 |

Note: The two benign APKs (ApiDemos variants) produce identical scores (0.3984) because they are nearly identical files (same package, same content, 13-byte size difference). This means we effectively have a **single distinct benign data point**, not two independent observations.

---

## G. ROC-AUC / PR-AUC

**BLOCKED.**

> Threshold-dependent classification metrics were not used because no validated APK-specific operating threshold has been established.

ROC-AUC and PR-AUC require both positive (malicious) and negative (benign) labeled samples. With zero malicious samples, these metrics cannot be computed.

---

## H. Ranking Analysis

### Ranked by EMBER Score (descending)

| Rank | Filename | Label | Score |
|------|----------|-------|-------|
| 1 | ApiDemos-debug.apk | benign | 0.398387 |
| 2 | ApiDemos-debug2.apk | benign | 0.398387 |

```
Highest benign score: 0.398387
Lowest malicious score: N/A (no malicious samples)
Overlap region: Cannot be determined
```

Without malicious samples, ranking analysis is meaningless for discriminative purposes.

---

## I. Family Analysis

**N/A.** No malicious samples exist, so no malware family analysis can be performed.

---

## J. Complementarity Analysis

### CiphR vs EMBER Comparison (benign samples only)

| Filename | EMBER Score | CiphR Risk Score | CiphR DEX Risk | CiphR Total Risk | Permissions | Risky Perms |
|----------|-------------|-----------------|----------------|-----------------|-------------|-------------|
| ApiDemos-debug.apk | 0.398387 | 95 | 10 | 100 | 12 | 6 |
| ApiDemos-debug2.apk | 0.398387 | 95 | 10 | 100 | 12 | 6 |

### Observations

1. **CiphR flags these benign APKs as extremely high risk** (score=100/100) due to 6 risky permissions including `SEND_SMS`, `RECEIVE_SMS`, `READ_CONTACTS`, `CAMERA`, `RECORD_AUDIO`, `WRITE_CONTACTS`. The ApiDemos app legitimately uses these for demonstration purposes.

2. **EMBER scores these same APKs at 0.398** -- below 0.5 but not close to 0. This suggests EMBER is more cautious about labeling them as malware.

3. **Evidence of complementarity**: CiphR and EMBER operate on fundamentally different signal domains:
   - CiphR: Android-specific manifest permissions, DEX bytecode patterns, certificates
   - EMBER: File-level byte statistics, byte entropy histograms, string statistics
   
   These are **independent feature spaces** with zero overlap in what they measure.

4. **Correlation cannot be meaningfully calculated** with only 2 data points (which produce identical values for both metrics).

### CiphR Risky Permissions Detected

```
android.permission.READ_CONTACTS        (weight=15)
android.permission.RECEIVE_SMS           (weight=20)
android.permission.CAMERA                (weight=15)
android.permission.WRITE_CONTACTS        (weight=5)
android.permission.SEND_SMS              (weight=20)
android.permission.RECORD_AUDIO          (weight=20)
```

---

## K. Performance

| Filename | Size | Model Load | Feature Extraction | Inference | Total |
|----------|------|------------|-------------------|-----------|-------|
| ApiDemos-debug.apk | 4.8 MB | 0.0165s | 2.9195s | 0.0005s | 2.9365s |
| ApiDemos-debug2.apk | 4.8 MB | 0.0176s | 2.8696s | 0.0005s | 2.8877s |
| dummy.apk | 177 B | 0.0190s | 0.1318s | 0.0004s | 0.1513s |
| dummy2.apk | 6 B | 0.0199s | 0.1267s | 0.0005s | 0.1471s |

### Observations

- **Feature extraction dominates** (~99% of total time for real APKs)
- Model load: ~16ms (negligible after first load)
- LightGBM inference: <1ms (effectively instant)
- Size-dependent: ~2.9s for 4.8MB files, ~0.13s for tiny files
- Feature extraction baseline cost: ~0.13s minimum regardless of file size
- Performance is acceptable for an evidence source in a batch analysis pipeline

---

## L. Feature Activation Analysis

This section reveals **which feature sub-groups actually contribute** to the EMBER score for APK files.

### Feature Activation by Group (ApiDemos-debug.apk)

| Feature Group | Dim | Non-Zero | Activation | Interpretation |
|--------------|-----|----------|------------|----------------|
| **general** | 7 | 6 | 85.7% | File size, virtual size, has_debug, has_signature, etc. |
| **histogram** | 256 | 256 | **100.0%** | Byte value distribution -- fully activated |
| **byteentropy** | 256 | 256 | **100.0%** | Byte-entropy histogram -- fully activated |
| **strings** | 177 | 126 | **71.2%** | String statistics -- significantly activated |
| header | 74 | 0 | 0.0% | PE header fields -- not applicable to APK |
| section | 224 | 0 | 0.0% | PE section info -- not applicable to APK |
| imports | 1282 | 0 | 0.0% | PE import table -- not applicable to APK |
| exports | 129 | 0 | 0.0% | PE export table -- not applicable to APK |
| datadirectories | 34 | 0 | 0.0% | PE data directories -- not applicable to APK |
| richheader | 33 | 0 | 0.0% | PE rich header -- not applicable to APK |
| authenticode | 8 | 0 | 0.0% | PE authenticode -- not applicable to APK |
| pefilewarnings | 88 | 0 | 0.0% | PE parse warnings -- not applicable to APK |

### Summary

- **4 feature groups are active**: general (7 dim), histogram (256), byteentropy (256), strings (177) = **696 features** out of 2568 (27.1%)
- **8 feature groups are zero**: All PE-specific groups produce zero vectors for APK files = **1872 features** (72.9%) permanently zero

This is consistent with the EMBER2024 paper's claim that APK classifiers use "features from general file info, byte statistics, and string statistics." The model was **trained knowing** these PE-specific features would be zero for APK inputs.

### Effective Feature Utilization

The model relies on exactly **696 active dimensions** (27.1% of total) for APK classification. The remaining 72.9% are structurally zero and do not contribute to the decision boundary. This is by design, not a defect.

---

## M. Determinism

| Sample | Run 1 | Run 2 | Run 3 | Deterministic |
|--------|-------|-------|-------|---------------|
| ApiDemos-debug.apk | 0.3983871671279465 | 0.3983871671279465 | 0.3983871671279465 | **YES** |
| ApiDemos-debug2.apk | 0.3983871671279465 | 0.3983871671279465 | 0.3983871671279465 | **YES** |
| dummy.apk | 0.023504409767698818 | 0.023504409767698818 | 0.023504409767698818 | **YES** |

All 9 runs (3 samples x 3 runs) produced bit-identical results. Determinism is confirmed and consistent with Phase 6D.

---

## N. Sample-Level Investigation

### Highest-Scoring Benign APK

| Field | Value |
|-------|-------|
| Filename | ApiDemos-debug.apk |
| SHA256 | `354b56605e8f201ce5fdd5b796524d8fabae726ee57de2d76dcf878c4d7826f1` |
| Label | benign |
| EMBER Score | 0.398387 |
| Feature Dimension | 2568 |
| Provenance | Android SDK sample application (io.appium.android.apis) |
| CiphR Risk Score | 95 (capped at 100 with DEX) |
| CiphR Risky Permissions | 6 (SEND_SMS, RECEIVE_SMS, READ_CONTACTS, CAMERA, RECORD_AUDIO, WRITE_CONTACTS) |

**Interpretation**: The ApiDemos app scores 0.398 (below 0.5) on EMBER but 100/100 on CiphR's permission heuristics. This is a known false-positive scenario for permission-based analysis: demo apps legitimately request many permissions. EMBER's byte-level features may capture that this binary's structure looks more like a typical developer tool than typical malware. However, without malicious samples for comparison, this interpretation is speculative.

### Lowest-Scoring Malicious APK

**N/A.** No malicious samples exist in the corpus.

---

## O. Limitations

1. **CRITICAL: No malicious ground truth.** Zero confirmed malicious APKs are available. This makes all discriminative metrics impossible to compute and prevents answering the core scientific question.

2. **Extremely small corpus.** Only 2 real-world APK samples, both from the same source (Android SDK ApiDemos). This is statistically meaningless for generalization.

3. **No diversity.** Both benign samples are variants of the same app, producing identical EMBER scores. There is effectively 1 unique benign data point.

4. **Feature space utilization.** Only 27.1% of the 2568-dimensional feature vector is active for APKs. However, this is by design -- the EMBER2024 APK model was explicitly trained with this subset active.

5. **Provenance correction.** The EMBER2024_APK.model is NOT a generic PE model applied to APKs. It is an APK-specific model trained on 208K+ APK samples from VirusTotal. The Phase 6D documentation's "PE/APK domain mismatch" limitation was overstated.

6. **Lack of calibration.** The raw EMBER score has not been calibrated. Score magnitudes cannot be interpreted as probabilities.

7. **CiphR comparison limited.** With only 2 identical-scored data points, correlation analysis is impossible. The complementarity observation is qualitative only.

8. **Pre-existing test flake.** `test_concurrent_duplicate_upload` fails intermittently due to a SQLAlchemy race condition. This is pre-existing and unrelated to EMBER.

---

## P. Testing

### All EMBER Tests: PASSED

```
tests/test_ember.py::test_valid_apk_inference         PASSED
tests/test_ember.py::test_deterministic_inference      PASSED
tests/test_ember.py::test_missing_apk                  PASSED
tests/test_ember.py::test_invalid_apk                  PASSED
tests/test_ember.py::test_missing_model                PASSED
tests/test_ember.py::test_feature_dimension_mismatch   PASSED
tests/test_ember.py::test_result_contract_success      PASSED
tests/test_ember.py::test_result_contract_failure      PASSED
tests/test_ember.py::test_result_immutable             PASSED
```

### Full Suite: 34 passed, 1 pre-existing flake

```
34 passed, 1 failed (pre-existing: test_concurrent_duplicate_upload)
```

No existing tests were weakened. No new tests were needed (validation is a research script, not a code change).

---

## Q. Change Control

### Files Created

| File | Purpose |
|------|---------|
| `benchmarks/phase6d1_validation.py` | Validation harness script (read-only research) |
| `benchmarks/phase6d1_results.json` | Machine-readable validation results |
| `benchmarks/phase6d1_validation_report.md` | This report |

### Files Modified

**None.** No source code was modified.

### Files NOT Touched

- All `app/` source files (API, models, services, ember adapter)
- All `tests/` files
- Phase 6B, 6C, and 6D evidence files
- Database, frontend, campaign code
- Requirements or configuration

---

## R. Conclusion

> **Does EMBER2024 provide sufficiently useful independent evidence on Android APKs to justify consideration in CiphR evidence fusion?**

### Answer: `BLOCKED -- obtain better labeled corpus first`

**Rationale:**

1. **The adapter works.** EMBER2024 reliably produces deterministic, stable inference on APK files with 696 active features (by design).

2. **The model is legitimate.** The `EMBER2024_APK.model` is an APK-specific classifier trained on 208K+ real APK samples from VirusTotal. The feature subset (general info, byte histogram, byte entropy, strings) is explicitly designed for non-PE file classification.

3. **Discriminative power is unknown.** Without confirmed malicious APKs, we cannot determine whether EMBER scores separate malware from benign apps. A single benign data point (score=0.398) tells us nothing about the malicious score distribution.

4. **Complementarity is plausible but unproven.** EMBER operates on a completely different feature space (byte-level statistics) than CiphR's existing signals (Android permissions, DEX bytecode, certificates). If EMBER provides good separation on APKs, it would be a genuinely independent evidence source. But we cannot verify this without labeled data.

5. **What's needed to unblock:**
   - 10-50 confirmed malicious APK samples with credible ground truth (e.g., VirusTotal detections, malware family labels)
   - 10-50 additional benign APK samples from diverse sources (not just ApiDemos)
   - Rerun this validation harness with the expanded corpus
   - If ROC-AUC > 0.7 and the score distributions show meaningful separation, EMBER earns its place in evidence fusion

**Phase 6D.1 is COMPLETE. Do NOT proceed to Phase 6E until the corpus limitation is resolved.**
