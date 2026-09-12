# EMBER2024 Integration — CiphR

## 1. What EMBER2024 Contributes

EMBER2024 provides a **LightGBM-based binary classifier** trained on a large
corpus of PE/binary samples (the EMBER 2024 dataset by Sophos AI / Elastic).
When applied to APK files, it treats the APK as a raw binary blob and extracts
structural features (byte histograms, entropy, PE headers, imports/exports,
sections, strings, etc.).

Within CiphR, EMBER serves as an **independent evidence signal** alongside
existing analysis (Androguard static analysis, TLSH correlation, DEX/Smali
analysis, LLM narrative generation).

## 2. What the Score Means

The EMBER score is the **raw output of a LightGBM binary classifier** trained
to distinguish benign (label 0) from malicious (label 1) samples.

- Higher scores indicate the model considers the sample more similar to
  malicious training samples.
- Lower scores indicate the model considers the sample more similar to
  benign training samples.

## 3. What the Score Does NOT Mean

> **EMBER score is model evidence, not a calibrated probability of maliciousness.**

- The score is **NOT** a probability. A score of 0.7 does NOT mean "70% chance
  of being malware."
- The score should **NOT** be compared directly to a threshold (e.g., >0.5 =
  malware) without proper calibration research.
- The score does **NOT** replace the CiphR risk score, which is computed from
  permission analysis, DEX intelligence, campaign correlation, and other signals.
- The score does **NOT** account for Android-specific behavioural indicators
  (the EMBER model was trained on PE-format binary features).

## 4. Required Model Files

| File | Description | Size |
|------|-------------|------|
| `EMBER2024_APK.model` | Pretrained LightGBM Booster | ~3.6 MB |

Default location: configured via `EMBER_MODEL_PATH` in settings/environment.
Fallback: `backend/scratch/ember2024_benchmark/EMBER2024_APK.model`.

## 5. Required Feature Extractor

The `thrember` package (version 0.1.0) provides the `PEFeatureExtractor` class.
It is installed as an editable package from:

```
backend/scratch/ember2024_benchmark/EMBER2024/
```

Dependencies: `lightgbm`, `pefile`, `signify`, `numpy`, `scikit-learn`.

## 6. Expected Feature Dimension

**2568** — this is the sum of all sub-feature dimensions in the
`PEFeatureExtractor`:

| Feature Group | Dimension |
|---------------|-----------|
| GeneralFileInfo | 7 |
| ByteHistogram | 256 |
| ByteEntropyHistogram | 256 |
| StringExtractor | 104 |
| HeaderFileInfo | 72 |
| SectionInfo | 255 |
| ImportsInfo | 1280 |
| ExportsInfo | 128 |
| DataDirectories | 30 |
| RichHeader | 30 |
| AuthenticodeSignature | 16 |
| PEFormatWarnings | 134 |
| **Total** | **2568** |

The adapter validates this at runtime and fails cleanly if mismatched.

## 7. How to Run Inference

```python
from app.ember import classify_apk

result = classify_apk("/path/to/sample.apk")

if result.inference_success:
    print(f"Score: {result.score}")
    print(f"Dimension: {result.feature_dimension}")
else:
    print(f"Error: {result.error}")
```

## 8. How to Run the Benchmark

```bash
cd backend
python benchmarks/phase6d_benchmark.py
```

This runs:
- Inference on all available fixture APKs
- Determinism test (3 identical runs)
- Failure isolation tests
- Performance measurement

Results are printed to stdout and saved to `benchmarks/phase6d_results.json`.

## 9. Known Limitations

1. **PE-centric model**: EMBER was designed for PE (Windows executable) analysis.
   When applied to APK files, it treats them as opaque binary blobs. Android-
   specific features (manifest permissions, DEX bytecode, etc.) are NOT captured
   by EMBER — those are covered by CiphR's Androguard-based analysis.

2. **No calibration**: The raw score has not been calibrated to represent a true
   probability. Score distributions may vary significantly across APK families.

3. **Training data bias**: The model was trained on the EMBER 2024 dataset which
   is primarily PE-focused. Its discriminative power on APK files has not been
   independently validated at scale.

4. **No APK-specific features**: DEX code, manifest, certificates, and Android
   component structure are invisible to EMBER.

5. **Feature extraction overhead**: The `PEFeatureExtractor` was designed for PE
   files and may produce degenerate (all-zero) sub-features for APK-specific
   sections, reducing effective discriminative power.

## 10. Why EMBER Is an Independent Evidence Signal

EMBER is deliberately kept as an **isolated, additional signal** rather than
being directly integrated into the CiphR risk score because:

1. **No calibration evidence**: Without proper calibration research, incorporating
   the raw EMBER score into the risk engine could produce misleading results.

2. **Domain mismatch**: The model was trained on PE files, not APKs. Its
   effectiveness on APKs requires further validation.

3. **Architectural separation**: CiphR's existing risk engine (permission-based
   heuristics + DEX analysis + TLSH + campaign correlation + LLM narrative) is
   well-understood and deterministic. Mixing in an uncalibrated ML signal without
   proper evidence fusion would reduce transparency.

4. **Future evidence fusion**: A proper evidence-fusion layer (Phase 6E) should
   be designed to combine EMBER output with other signals using principled
   weighting, calibration, and evaluation.

The current architecture:

```
APK
 ↓
Existing CiphR analysis (Androguard, DEX, TLSH, Campaigns, LLM)
 ↓
EMBER2024 inference (independent)
 ↓
Both available as separate evidence
 ↓
Future: evidence-fusion layer (Phase 6E)
```
