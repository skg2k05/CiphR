# CiphR Phase 6D.2 — EMBER2024 APK Ground-Truth Validation Acquisition Report

## A. Status

**PARTIALLY UNBLOCKED**

Official labeled EMBER2024 feature vectors for APKs were successfully acquired. This allows for extremely high-confidence model-level validation (N=96,000). However, the dataset does **not** provide raw APK binaries, meaning end-to-end CiphR APK pipeline validation remains unavailable.

---

## B. Official Dataset

* **Dataset:** EMBER2024 (joyce8/EMBER2024 on HuggingFace)
* **Version:** v1 (Published 2024/2025)
* **APK Portion:** `APK_test.zip` split
* **Sample Counts:** 96,000 total (48,000 benign, 48,000 malicious)
* **Labels:** Binary `label` (0=benign, 1=malicious), plus multi-class `family` labels for malware.
* **Feature Format:** JSONL (newline-delimited JSON containing precomputed feature vectors and metadata)
* **Raw APK Availability:** **NONE.** The dataset explicitly only provides precomputed features to avoid distributing malware binaries.

---

## C. Model Compatibility

* **Model:** `EMBER2024_APK.model`
* **Model Feature Dimension:** 2568
* **Dataset Feature Dimension:** 2568 (via `thrember-PEFeatureExtractor-v3`)
* **Feature Version:** Compatible. The features extracted from the JSONL records exactly match the dimensions and semantics expected by the model.
* **Compatibility Result:** **SUCCESS.** The precomputed features can be directly fed into the CiphR LightGBM model.

---

## D. Model-Level Benchmark

This is a **MODEL-LEVEL validation** using official precomputed APK features. It validates the LightGBM weights, but does not validate the `androguard`/`thrember` raw-APK parsing pipeline.

* **Sample Count:** 96,000 labeled test samples
* **ROC-AUC:** 0.986137
* **PR-AUC:** 0.987086

### Score Distribution
* **Benign (N=48,000):** Mean = 0.0819, Median = 0.0129, P95 = 0.4793
* **Malicious (N=48,000):** Mean = 0.8966, Median = 0.9860, P5 = 0.3571

### Operating Points
* TPR at 0.1% FPR: 0.5610 (threshold=0.9793)
* TPR at 1.0% FPR: 0.8149 (threshold=0.8565)
* TPR at 5.0% FPR: 0.9318 (threshold=0.4794)

The model performs exceptionally well at distinguishing precomputed benign features from malicious ones.

---

## E. Raw APK Validation Availability

**UNAVAILABLE.** 
The official dataset provides SHA1, SHA256, and MD5 hashes, but deliberately excludes the raw `.apk` binaries.

---

## F. Raw APK → CiphR Validation

**UNAVAILABLE.**
Because no raw APKs were provided, it is impossible to validate that `classify_apk(path_to_apk)` produces the same robust feature extraction as the precomputed vectors.

---

## G. Ground Truth Quality

The labels originate from the official EMBER2024 research. According to the dataset methodology (and the `ClarAVy` tool), these are backed by VirusTotal telemetry. The labels are highly credible, and the dataset includes 524 distinct malware families (e.g., `spymax`, `wapron`, `boogr`).

---

## H. Security Review

* **Zero APKs downloaded.**
* **Zero APKs executed.**
* **Zero dynamic analysis performed.**

The investigation was purely an offline static data-processing task on JSON records.

---

## I. Reproducibility

1. **Acquisition:** Downloaded `APK_test.zip` using `huggingface_hub` into the `scratch/ember2024_benchmark/apk_test_data/` directory.
2. **Extraction:** Extracted 12 `.jsonl` files (approx 40MB each).
3. **Validation:** Executed `benchmarks/phase6d2_dataset_investigation.py` which parsed the JSONL records, mapped them using `PEFeatureExtractor.process_raw_features`, and executed `Booster.predict()`.

All steps are documented in `benchmarks/phase6d2_dataset_manifest.json` and `benchmarks/phase6d2_results.json`.

---

## J. Phase 6D.1 Decision

### PARTIALLY UNBLOCKED

We now possess 96,000 highly credible labeled feature vectors that prove the `EMBER2024_APK.model` is highly discriminative on Android malware (ROC-AUC > 0.98). 

However, Phase 6D.1 specifically requires validating the **end-to-end CiphR pipeline** (Raw APK -> CiphR/thrember extraction -> Model). This remains blocked because EMBER2024 does not supply raw binaries.

---

## Final Report Summary

```text
Phase 6D.2 Status: PARTIALLY UNBLOCKED
Dataset: EMBER2024 (joyce8/EMBER2024)
Dataset Version: v1
APK Samples Available: 96,000 (precomputed features)
Benign: 48,000
Malicious: 48,000
Raw APKs Available: FALSE
Feature Vectors Available: TRUE
Model Compatibility: TRUE
Model-Level Validation: ROC-AUC=0.986, PR-AUC=0.987
Raw APK Validation: BLOCKED
Ground Truth Quality: HIGH (VirusTotal/ClarAVy)
Security Status: SAFE (No binaries downloaded/executed)
Existing CiphR Tests: 35/35 PASSED
Files Created: phase6d2_dataset_investigation.py, phase6d2_dataset_manifest.json, phase6d2_dataset_report.md, phase6d2_results.json
Files Modified: 0
Recommended Next Step: Decide whether to proceed to Phase 6E (integration) relying on the model-level validation, or source raw APKs from an alternative repository (like AndroZoo) to complete end-to-end pipeline validation.
```
