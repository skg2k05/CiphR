#!/usr/bin/env python
"""
Phase 6D.2 -- EMBER2024 APK Dataset Investigation & Model-Level Validation.

This script:
1. Downloads the official EMBER2024 APK test features from HuggingFace
2. Investigates the dataset structure, labels, and metadata
3. Runs model-level validation using the official precomputed features
4. Reports ROC-AUC, PR-AUC, score distributions, and ranking analysis

Run from the backend directory:
    python benchmarks/phase6d2_dataset_investigation.py

IMPORTANT:
- This uses PRECOMPUTED feature vectors, NOT raw APK binaries.
- This validates the MODEL, not the CiphR raw-APK feature extraction pipeline.
- These are separate experiments and must not be conflated.
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import sys
import time
import zipfile
from pathlib import Path

import numpy as np

# Ensure backend root is on sys.path
BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRATCH_DIR = BACKEND_ROOT / "scratch" / "ember2024_benchmark"
MODEL_PATH = SCRATCH_DIR / "EMBER2024_APK.model"
DATASET_DIR = SCRATCH_DIR / "apk_test_data"
RESULTS_FILE = Path(__file__).parent / "phase6d2_results.json"
MANIFEST_FILE = Path(__file__).parent / "phase6d2_dataset_manifest.json"


def separator(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


# ---------------------------------------------------------------------------
# 1. Download APK test features
# ---------------------------------------------------------------------------

def download_apk_test_data() -> Path:
    separator("1. Download APK Test Features from HuggingFace")

    DATASET_DIR.mkdir(parents=True, exist_ok=True)

    # Check if already extracted
    jsonl_files = list(DATASET_DIR.glob("*.jsonl"))
    if jsonl_files:
        print(f"  Already have {len(jsonl_files)} .jsonl files in {DATASET_DIR}")
        return DATASET_DIR

    print("  Downloading APK_test.zip from joyce8/EMBER2024...")
    from huggingface_hub import hf_hub_download
    zip_path = hf_hub_download(
        repo_id="joyce8/EMBER2024",
        filename="APK_test.zip",
        repo_type="dataset",
        local_dir=str(DATASET_DIR),
    )
    zip_path = Path(zip_path)
    print(f"  Downloaded: {zip_path} ({zip_path.stat().st_size:,} bytes)")

    print("  Extracting...")
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(str(DATASET_DIR))
    print("  Extraction complete.")

    # List extracted files
    jsonl_files = list(DATASET_DIR.rglob("*.jsonl"))
    print(f"  Found {len(jsonl_files)} .jsonl files:")
    for f in sorted(jsonl_files):
        print(f"    {f.name} ({f.stat().st_size:,} bytes)")

    return DATASET_DIR


# ---------------------------------------------------------------------------
# 2. Investigate dataset structure
# ---------------------------------------------------------------------------

def investigate_dataset(data_dir: Path) -> dict:
    separator("2. Investigate Dataset Structure")

    jsonl_files = sorted(data_dir.rglob("*.jsonl"))
    if not jsonl_files:
        print("  ERROR: No .jsonl files found!")
        return {"error": "No data files found"}

    print(f"  Found {len(jsonl_files)} .jsonl files:")
    total_samples = 0
    file_info = []

    for f in jsonl_files:
        line_count = sum(1 for _ in f.open("r"))
        size = f.stat().st_size
        file_info.append({
            "filename": f.name,
            "path": str(f),
            "lines": line_count,
            "size_bytes": size,
        })
        total_samples += line_count
        print(f"    {f.name}: {line_count:,} samples, {size:,} bytes")

    print(f"\n  Total samples: {total_samples:,}")

    # Inspect first record to understand schema
    first_file = jsonl_files[0]
    with first_file.open("r") as fin:
        first_line = fin.readline()
    first_record = json.loads(first_line)

    print(f"\n  Schema (keys in first record):")
    for key in sorted(first_record.keys()):
        val = first_record[key]
        val_type = type(val).__name__
        if isinstance(val, str):
            preview = val[:60]
        elif isinstance(val, (int, float)):
            preview = str(val)
        elif isinstance(val, dict):
            preview = f"dict with {len(val)} keys: {list(val.keys())[:5]}"
        elif isinstance(val, list):
            preview = f"list of {len(val)} items"
        else:
            preview = str(val)[:60]
        print(f"    {key}: ({val_type}) {preview}")

    # Count labels
    print("\n  Counting labels...")
    label_counts = {}
    file_type_counts = {}
    family_counts = {}
    sha256_set = set()

    for f in jsonl_files:
        with f.open("r") as fin:
            for line in fin:
                rec = json.loads(line)
                label = rec.get("label")
                file_type = rec.get("file_type")
                family = rec.get("family")
                sha = rec.get("sha256")

                label_counts[label] = label_counts.get(label, 0) + 1
                file_type_counts[file_type] = file_type_counts.get(file_type, 0) + 1
                if family:
                    family_counts[family] = family_counts.get(family, 0) + 1
                if sha:
                    sha256_set.add(sha)

    print(f"\n  Label distribution:")
    for label, count in sorted(label_counts.items(), key=lambda x: str(x[0])):
        label_name = {0: "benign", 1: "malicious", None: "unlabeled"}.get(label, str(label))
        print(f"    {label_name} ({label}): {count:,}")

    print(f"\n  File type distribution:")
    for ft, count in sorted(file_type_counts.items(), key=lambda x: -x[1]):
        print(f"    {ft}: {count:,}")

    print(f"\n  Unique SHA256: {len(sha256_set):,}")
    print(f"  Unique families: {len(family_counts)}")
    if family_counts:
        top_families = sorted(family_counts.items(), key=lambda x: -x[1])[:10]
        print(f"  Top 10 families:")
        for fam, count in top_families:
            print(f"    {fam}: {count}")

    return {
        "files": file_info,
        "total_samples": total_samples,
        "label_distribution": {str(k): v for k, v in label_counts.items()},
        "file_type_distribution": file_type_counts,
        "unique_sha256": len(sha256_set),
        "unique_families": len(family_counts),
        "top_families": {fam: count for fam, count in sorted(family_counts.items(), key=lambda x: -x[1])[:20]},
        "schema_keys": sorted(first_record.keys()),
    }


# ---------------------------------------------------------------------------
# 3. Vectorize and run model-level validation
# ---------------------------------------------------------------------------

def run_model_validation(data_dir: Path) -> dict:
    separator("3. Model-Level Validation (precomputed features)")

    from thrember.features import PEFeatureExtractor

    extractor = PEFeatureExtractor()
    expected_dim = extractor.dim
    print(f"  Feature extractor dim: {expected_dim}")

    import lightgbm as lgb
    booster = lgb.Booster(model_file=str(MODEL_PATH))
    model_features = booster.num_feature()
    print(f"  Model num_features: {model_features}")

    if expected_dim != model_features:
        print(f"  ERROR: Dimension mismatch! extractor={expected_dim}, model={model_features}")
        return {"error": "dimension_mismatch", "extractor_dim": expected_dim, "model_dim": model_features}

    # Vectorize samples
    jsonl_files = sorted(data_dir.rglob("*.jsonl"))

    print(f"\n  Vectorizing samples from {len(jsonl_files)} files...")

    all_features = []
    all_labels = []
    all_sha256 = []
    all_families = []
    vectorize_errors = 0
    t0 = time.perf_counter()

    for f in jsonl_files:
        with f.open("r") as fin:
            for line_num, line in enumerate(fin):
                try:
                    raw = json.loads(line)
                    features = extractor.process_raw_features(raw)
                    label = raw.get("label")

                    if label is None:
                        continue  # Skip unlabeled

                    all_features.append(features)
                    all_labels.append(int(label))
                    all_sha256.append(raw.get("sha256", ""))
                    all_families.append(raw.get("family"))
                except Exception as e:
                    vectorize_errors += 1
                    if vectorize_errors <= 3:
                        print(f"    Vectorize error at line {line_num}: {e}")

                if (line_num + 1) % 10000 == 0:
                    print(f"    Processed {line_num + 1:,} records...")

    vectorize_time = time.perf_counter() - t0
    print(f"  Vectorized {len(all_features):,} labeled samples in {vectorize_time:.1f}s")
    print(f"  Vectorize errors: {vectorize_errors}")

    if not all_features:
        return {"error": "no_features_vectorized"}

    X = np.array(all_features, dtype=np.float32)
    y = np.array(all_labels, dtype=np.int32)

    print(f"  X shape: {X.shape}")
    print(f"  y shape: {y.shape}")
    print(f"  Benign (0): {(y == 0).sum():,}")
    print(f"  Malicious (1): {(y == 1).sum():,}")

    # Run inference
    print(f"\n  Running inference...")
    t0 = time.perf_counter()
    scores = booster.predict(X)
    inference_time = time.perf_counter() - t0
    print(f"  Inference done in {inference_time:.3f}s for {len(scores):,} samples")
    print(f"  ({inference_time / len(scores) * 1000:.4f} ms/sample)")

    # Score distributions
    benign_scores = scores[y == 0]
    malicious_scores = scores[y == 1]

    def stats(arr):
        return {
            "count": len(arr),
            "min": round(float(arr.min()), 6),
            "max": round(float(arr.max()), 6),
            "mean": round(float(arr.mean()), 6),
            "median": round(float(np.median(arr)), 6),
            "std": round(float(arr.std()), 6),
            "p5": round(float(np.percentile(arr, 5)), 6),
            "p25": round(float(np.percentile(arr, 25)), 6),
            "p75": round(float(np.percentile(arr, 75)), 6),
            "p95": round(float(np.percentile(arr, 95)), 6),
        }

    benign_stats = stats(benign_scores)
    malicious_stats = stats(malicious_scores)

    print(f"\n  BENIGN score distribution (n={benign_stats['count']:,}):")
    for k, v in benign_stats.items():
        print(f"    {k}: {v}")

    print(f"\n  MALICIOUS score distribution (n={malicious_stats['count']:,}):")
    for k, v in malicious_stats.items():
        print(f"    {k}: {v}")

    # ROC-AUC and PR-AUC
    from sklearn.metrics import roc_auc_score, precision_recall_curve, auc, roc_curve

    roc_auc = roc_auc_score(y, scores)
    precision, recall, _ = precision_recall_curve(y, scores)
    pr_auc = auc(recall, precision)

    print(f"\n  ROC-AUC: {roc_auc:.6f}")
    print(f"  PR-AUC:  {pr_auc:.6f}")

    # TPR at specific FPR thresholds
    fpr, tpr, thresholds = roc_curve(y, scores)
    for target_fpr in [0.001, 0.005, 0.01, 0.05]:
        idx = np.argmin(np.abs(fpr - target_fpr))
        print(f"  TPR at {target_fpr*100:.1f}% FPR: {tpr[idx]:.4f} (threshold={thresholds[idx]:.4f})")

    # Ranking analysis
    print(f"\n  Ranking analysis:")
    print(f"    Highest benign score:    {benign_stats['max']}")
    print(f"    Lowest malicious score:  {malicious_stats['min']}")

    overlap_low = max(benign_stats["min"], malicious_stats["min"])
    overlap_high = min(benign_stats["max"], malicious_stats["max"])
    if overlap_low <= overlap_high:
        print(f"    Overlap region:          [{overlap_low:.6f}, {overlap_high:.6f}]")
    else:
        print(f"    Perfect separation:      YES (no overlap)")

    # Family analysis
    family_analysis = {}
    if any(f is not None for f in all_families):
        print(f"\n  Family analysis (malicious only):")
        family_scores = {}
        for i, (label, family) in enumerate(zip(all_labels, all_families)):
            if label == 1 and family is not None:
                if family not in family_scores:
                    family_scores[family] = []
                family_scores[family].append(float(scores[i]))

        top_families = sorted(family_scores.items(), key=lambda x: -len(x[1]))[:15]
        for fam, fam_scores in top_families:
            fam_arr = np.array(fam_scores)
            family_analysis[fam] = {
                "count": len(fam_scores),
                "mean": round(float(fam_arr.mean()), 6),
                "median": round(float(np.median(fam_arr)), 6),
                "min": round(float(fam_arr.min()), 6),
                "max": round(float(fam_arr.max()), 6),
            }
            print(f"    {fam}: n={len(fam_scores)}, mean={fam_arr.mean():.4f}, "
                  f"median={np.median(fam_arr):.4f}, range=[{fam_arr.min():.4f}, {fam_arr.max():.4f}]")

    return {
        "model_features": model_features,
        "extractor_dim": expected_dim,
        "compatible": True,
        "total_labeled": len(all_features),
        "benign_count": int((y == 0).sum()),
        "malicious_count": int((y == 1).sum()),
        "vectorize_errors": vectorize_errors,
        "vectorize_time_s": round(vectorize_time, 2),
        "inference_time_s": round(inference_time, 4),
        "ms_per_sample": round(inference_time / len(scores) * 1000, 4),
        "roc_auc": round(roc_auc, 6),
        "pr_auc": round(pr_auc, 6),
        "benign_scores": benign_stats,
        "malicious_scores": malicious_stats,
        "family_analysis": family_analysis,
        "ranking": {
            "highest_benign": benign_stats["max"],
            "lowest_malicious": malicious_stats["min"],
            "overlap_region": [overlap_low, overlap_high] if overlap_low <= overlap_high else None,
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("  PHASE 6D.2 -- EMBER2024 APK Dataset Investigation")
    print("=" * 70)
    print(f"  Model:     {MODEL_PATH}")
    print(f"  Model exists: {MODEL_PATH.is_file()}")
    print()

    all_results = {}

    # 1. Download
    data_dir = download_apk_test_data()
    all_results["download"] = {"data_dir": str(data_dir), "success": True}

    # 2. Investigate
    investigation = investigate_dataset(data_dir)
    all_results["investigation"] = investigation

    # 3. Model validation
    validation = run_model_validation(data_dir)
    all_results["model_validation"] = validation

    # Save results
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_FILE, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    # Save manifest
    manifest = {
        "dataset_name": "EMBER2024",
        "dataset_version": "v1",
        "source": "HuggingFace: joyce8/EMBER2024",
        "download_method": "huggingface_hub.hf_hub_download(repo_id='joyce8/EMBER2024', filename='APK_test.zip', repo_type='dataset')",
        "feature_version": "thrember-PEFeatureExtractor-v3",
        "feature_dimension": 2568,
        "model_file": "EMBER2024_APK.model",
        "license": "Apache-2.0",
        "subset_used": "APK_test",
        "data_type": "precomputed_feature_vectors_jsonl",
        "raw_apk_binaries": False,
        "notes": "This dataset contains precomputed raw feature JSONL, NOT raw APK binaries. Model-level validation only.",
        "total_labeled_samples": investigation.get("total_samples"),
        "label_distribution": investigation.get("label_distribution"),
    }
    with open(MANIFEST_FILE, "w") as f:
        json.dump(manifest, f, indent=2)

    separator("Results saved")
    print(f"  Results:  {RESULTS_FILE}")
    print(f"  Manifest: {MANIFEST_FILE}")
    print()


if __name__ == "__main__":
    main()
