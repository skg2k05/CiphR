#!/usr/bin/env python
"""
Phase 6D.1 -- EMBER2024 Android Discriminative Validation.

Run from the backend directory:
    python benchmarks/phase6d1_validation.py

This script validates whether EMBER2024's APK-specific LightGBM model
provides meaningful discriminative evidence when applied to Android APKs.

It does NOT modify any production code, API, or database.
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import sys
import time
import zipfile
from collections import OrderedDict
from pathlib import Path

# Ensure backend root is on sys.path
BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.ember.classifier import classify_apk, reset_model, _extract_features
from app.ember.result import EMBER_EXPECTED_DIMENSION

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
FIXTURES_DIR = BACKEND_ROOT / "tests" / "fixtures"
UPLOADS_DIR = BACKEND_ROOT / "uploads"
MODEL_PATH = BACKEND_ROOT / "scratch" / "ember2024_benchmark" / "EMBER2024_APK.model"
RESULTS_FILE = Path(__file__).parent / "phase6d1_results.json"


# ---------------------------------------------------------------------------
# Corpus definition
# ---------------------------------------------------------------------------

# Manually curated labels for every available APK sample.
# label: "benign", "malicious", or "synthetic" (no valid ground truth)
# provenance: documented source
CORPUS = [
    {
        "path": str(FIXTURES_DIR / "ApiDemos-debug.apk"),
        "label": "benign",
        "provenance": "Android SDK sample application (com.example.android.apis)",
        "is_real_apk": True,
        "family": None,
    },
    {
        "path": str(FIXTURES_DIR / "ApiDemos-debug2.apk"),
        "label": "benign",
        "provenance": "Android SDK sample application variant",
        "is_real_apk": True,
        "family": None,
    },
    {
        "path": str(FIXTURES_DIR / "dummy.apk"),
        "label": "synthetic",
        "provenance": "Synthetic test fixture (177 bytes, minimal ZIP)",
        "is_real_apk": False,
        "family": None,
    },
    {
        "path": str(FIXTURES_DIR / "dummy2.apk"),
        "label": "synthetic",
        "provenance": "Synthetic test fixture (6 bytes, not a valid APK)",
        "is_real_apk": False,
        "family": None,
    },
]


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def file_size(path: str) -> int:
    return os.path.getsize(path)


def is_valid_zip(path: str) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as z:
            return z.testzip() is None
    except Exception:
        return False


def separator(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


# ---------------------------------------------------------------------------
# 1. Corpus quality checks
# ---------------------------------------------------------------------------

def validate_corpus() -> list[dict]:
    separator("1. Corpus Quality Checks")
    validated = []
    sha_set = set()

    for entry in CORPUS:
        p = str(entry["path"])
        rec = {
            "filename": os.path.basename(p),
            "path": p,
            "label": entry["label"],
            "provenance": entry["provenance"],
            "is_real_apk": entry["is_real_apk"],
            "family": entry["family"],
            "exists": os.path.isfile(p),
            "is_regular_file": os.path.isfile(p) and not os.path.isdir(p),
            "size_bytes": file_size(p) if os.path.isfile(p) else 0,
            "non_empty": file_size(p) > 0 if os.path.isfile(p) else False,
            "sha256": sha256_of(p) if os.path.isfile(p) else None,
            "valid_zip": is_valid_zip(p) if os.path.isfile(p) else False,
        }

        if rec["sha256"]:
            rec["duplicate_sha256"] = rec["sha256"] in sha_set
            sha_set.add(rec["sha256"])
        else:
            rec["duplicate_sha256"] = False

        validated.append(rec)
        status = "OK" if rec["exists"] and rec["non_empty"] else "WARN"
        print(f"  [{status}] {rec['filename']}")
        print(f"       Label: {rec['label']}  Size: {rec['size_bytes']}  ZIP: {rec['valid_zip']}  Dup: {rec['duplicate_sha256']}")

    # Summary
    total = len(validated)
    benign = sum(1 for v in validated if v["label"] == "benign")
    malicious = sum(1 for v in validated if v["label"] == "malicious")
    synthetic = sum(1 for v in validated if v["label"] == "synthetic")
    unique_sha = len(sha_set)
    real_apk = sum(1 for v in validated if v["is_real_apk"])

    print(f"\n  Corpus composition:")
    print(f"    Total samples:  {total}")
    print(f"    Benign:         {benign}")
    print(f"    Malicious:      {malicious}")
    print(f"    Synthetic:      {synthetic}")
    print(f"    Unique SHA256:  {unique_sha}")
    print(f"    Real-world APK: {real_apk}")
    print(f"    Synthetic:      {total - real_apk}")

    return validated


# ---------------------------------------------------------------------------
# 2. EMBER inference on all samples
# ---------------------------------------------------------------------------

def run_ember_inference(corpus: list[dict]) -> list[dict]:
    separator("2. EMBER Inference (all samples)")
    reset_model()
    results = []

    for entry in corpus:
        p = entry["path"]
        if not entry["exists"]:
            results.append({**entry, "ember_score": None, "inference_success": False,
                            "feature_dimension": None, "error": "file missing",
                            "total_time_s": 0})
            continue

        t0 = time.perf_counter()
        result = classify_apk(p, model_path=str(MODEL_PATH))
        elapsed = time.perf_counter() - t0

        row = {
            **entry,
            "ember_score": result.score,
            "inference_success": result.inference_success,
            "feature_dimension": result.feature_dimension,
            "error": result.error,
            "total_time_s": round(elapsed, 4),
        }
        results.append(row)

        status = "OK" if result.inference_success else "FAIL"
        print(f"  [{status}] {entry['filename']}  label={entry['label']}  "
              f"score={result.score}  dim={result.feature_dimension}  time={elapsed:.4f}s")

    return results


# ---------------------------------------------------------------------------
# 3. Feature activation analysis
# ---------------------------------------------------------------------------

def run_feature_activation_analysis(corpus: list[dict]) -> dict:
    separator("3. Feature Activation Analysis")

    from thrember.features import PEFeatureExtractor

    extractor = PEFeatureExtractor()

    # Map feature groups with their offsets/dimensions
    feature_groups = []
    offset = 0
    for fe in extractor.features:
        feature_groups.append({
            "name": fe.name,
            "dim": fe.dim,
            "offset": offset,
        })
        offset += fe.dim

    activation_results = {}

    for entry in corpus:
        p = entry["path"]
        if not entry["exists"] or entry["size_bytes"] == 0:
            continue

        file_bytes = Path(p).read_bytes()
        features = extractor.feature_vector(file_bytes)

        sample_activation = {}
        for fg in feature_groups:
            start = fg["offset"]
            end = start + fg["dim"]
            group_vec = features[start:end]
            non_zero = int((group_vec != 0).sum())
            total = fg["dim"]
            pct = round(100.0 * non_zero / total, 1) if total > 0 else 0.0
            sample_activation[fg["name"]] = {
                "non_zero": non_zero,
                "total": total,
                "activation_pct": pct,
            }

        activation_results[entry["filename"]] = sample_activation

        print(f"  {entry['filename']} ({entry['label']}):")
        for fg_name, act in sample_activation.items():
            bar = "#" * int(act["activation_pct"] / 5) + "." * (20 - int(act["activation_pct"] / 5))
            print(f"    {fg_name:25s}  {act['non_zero']:4d}/{act['total']:4d}  "
                  f"({act['activation_pct']:5.1f}%)  [{bar}]")
        print()

    return {
        "feature_groups": [{k: v for k, v in fg.items()} for fg in feature_groups],
        "per_sample": activation_results,
    }


# ---------------------------------------------------------------------------
# 4. CiphR static analysis comparison (offline)
# ---------------------------------------------------------------------------

def run_ciphr_comparison(ember_results: list[dict]) -> list[dict]:
    separator("4. CiphR Static Analysis Comparison (offline)")
    comparison = []

    for entry in ember_results:
        if not entry["is_real_apk"] or not entry["exists"] or not entry["inference_success"]:
            continue

        # Run CiphR static analysis offline (no DB writes)
        try:
            from androguard.core.apk import APK
            from app.services.apk_analysis_service import INDICATOR_RULES
            from app.services.tlsh_service import calculate_tlsh

            a = APK(entry["path"])
            permissions = set(list(a.get_permissions())[:500])

            # Calculate risk score the same way CiphR does
            risk_score = 0
            risk_factors = []
            for perm in permissions:
                if perm in INDICATOR_RULES:
                    rule = INDICATOR_RULES[perm]
                    risk_score += int(rule.get("weight", 0))
                    risk_factors.append(perm)

            risk_score = min(risk_score, 100)
            tlsh_hash = calculate_tlsh(entry["path"])

            # DEX analysis
            dex_risk = 0
            try:
                from app.services.dex_analysis_service import analyze_dex
                dex_results = analyze_dex(a.get_all_dex())
                if "risk_factors" in dex_results:
                    for r in dex_results["risk_factors"]:
                        dex_risk += r.get("weight", 0)
            except Exception:
                dex_results = {}

            rec = {
                "filename": entry["filename"],
                "label": entry["label"],
                "ember_score": entry["ember_score"],
                "ciphr_risk_score": risk_score,
                "ciphr_dex_risk": dex_risk,
                "ciphr_total_risk": min(risk_score + dex_risk, 100),
                "ciphr_permission_count": len(permissions),
                "ciphr_risky_permissions": risk_factors,
                "ciphr_tlsh": tlsh_hash,
                "ciphr_activities": len(a.get_activities()),
                "ciphr_services": len(a.get_services()),
                "ciphr_receivers": len(a.get_receivers()),
                "package_name": a.get_package(),
            }
            comparison.append(rec)

            print(f"  {entry['filename']}:")
            print(f"    EMBER score:       {entry['ember_score']:.6f}")
            print(f"    CiphR risk score:  {risk_score}")
            print(f"    CiphR DEX risk:    {dex_risk}")
            print(f"    Permissions:       {len(permissions)} total, {len(risk_factors)} risky")
            print(f"    Package:           {a.get_package()}")
            print()

        except Exception as e:
            print(f"  [SKIP] {entry['filename']}: {e}")

    return comparison


# ---------------------------------------------------------------------------
# 5. Determinism test
# ---------------------------------------------------------------------------

def run_determinism_test(corpus: list[dict]) -> list[dict]:
    separator("5. Determinism Test (3 runs x 3 samples)")
    results = []

    # Pick up to 3 samples that exist
    targets = [e for e in corpus if e["exists"] and e["non_empty"]][:3]

    for entry in targets:
        runs = []
        for i in range(1, 4):
            reset_model()
            r = classify_apk(entry["path"], model_path=str(MODEL_PATH))
            runs.append({
                "run": i,
                "score": r.score,
                "feature_dimension": r.feature_dimension,
                "inference_success": r.inference_success,
            })

        scores = [r["score"] for r in runs]
        deterministic = len(set(str(s) for s in scores)) == 1

        results.append({
            "filename": entry["filename"],
            "label": entry["label"],
            "runs": runs,
            "deterministic": deterministic,
        })

        det_str = "DETERMINISTIC" if deterministic else "NON-DETERMINISTIC"
        print(f"  {entry['filename']}: {det_str}")
        for r in runs:
            print(f"    Run {r['run']}: score={r['score']}  dim={r['feature_dimension']}")

    return results


# ---------------------------------------------------------------------------
# 6. Performance measurement
# ---------------------------------------------------------------------------

def run_performance_measurement(corpus: list[dict]) -> list[dict]:
    separator("6. Performance Measurement")
    perf_results = []

    for entry in corpus:
        if not entry["exists"] or not entry["non_empty"]:
            continue

        reset_model()
        file_bytes = Path(entry["path"]).read_bytes()

        # Model load
        import lightgbm as lgb
        t0 = time.perf_counter()
        booster = lgb.Booster(model_file=str(MODEL_PATH))
        model_load = time.perf_counter() - t0

        # Feature extraction
        t0 = time.perf_counter()
        features, dim, err, _ = _extract_features(file_bytes)
        feat_time = time.perf_counter() - t0

        # Inference
        if features is not None:
            t0 = time.perf_counter()
            import numpy as np
            _ = booster.predict(np.array([features]))
            inf_time = time.perf_counter() - t0
        else:
            inf_time = None

        rec = {
            "filename": entry["filename"],
            "size_bytes": entry["size_bytes"],
            "model_load_s": round(model_load, 4),
            "feature_extraction_s": round(feat_time, 4),
            "inference_s": round(inf_time, 4) if inf_time is not None else None,
            "total_s": round(model_load + feat_time + (inf_time or 0), 4),
        }
        perf_results.append(rec)

        print(f"  {entry['filename']} ({entry['size_bytes']:,} bytes):")
        print(f"    Model load:     {rec['model_load_s']:.4f}s")
        print(f"    Features:       {rec['feature_extraction_s']:.4f}s")
        print(f"    Inference:      {rec['inference_s']}s")
        print(f"    Total:          {rec['total_s']:.4f}s")
        print()

    return perf_results


# ---------------------------------------------------------------------------
# 7. Score distribution analysis
# ---------------------------------------------------------------------------

def score_distribution_analysis(ember_results: list[dict]) -> dict:
    separator("7. Score Distribution Analysis")

    groups = {}
    for label in ["benign", "malicious", "synthetic"]:
        scores = [r["ember_score"] for r in ember_results
                  if r["label"] == label and r["inference_success"] and r["ember_score"] is not None]
        if not scores:
            groups[label] = {"count": 0, "note": "No samples in this category"}
            continue

        groups[label] = {
            "count": len(scores),
            "min": round(min(scores), 6),
            "max": round(max(scores), 6),
            "mean": round(statistics.mean(scores), 6),
            "median": round(statistics.median(scores), 6),
            "stdev": round(statistics.stdev(scores), 6) if len(scores) > 1 else None,
            "scores": [round(s, 6) for s in sorted(scores)],
        }

        print(f"  {label.upper()} (n={len(scores)}):")
        print(f"    Min:    {groups[label]['min']}")
        print(f"    Max:    {groups[label]['max']}")
        print(f"    Mean:   {groups[label]['mean']}")
        print(f"    Median: {groups[label]['median']}")
        if groups[label].get("stdev") is not None:
            print(f"    StDev:  {groups[label]['stdev']}")
        print()

    # Classification metrics assessment
    has_benign = groups.get("benign", {}).get("count", 0) > 0
    has_malicious = groups.get("malicious", {}).get("count", 0) > 0

    if has_benign and has_malicious:
        groups["classification_metrics_possible"] = True
    else:
        groups["classification_metrics_possible"] = False
        print("  [BLOCKED] ROC-AUC and PR-AUC cannot be computed:")
        if not has_malicious:
            print("    No confirmed malicious samples in corpus.")
        if not has_benign:
            print("    No confirmed benign samples in corpus.")
        print("    Threshold-dependent classification metrics were not used because")
        print("    no validated APK-specific operating threshold has been established.")

    return groups


# ---------------------------------------------------------------------------
# 8. Ranking analysis
# ---------------------------------------------------------------------------

def ranking_analysis(ember_results: list[dict]) -> dict:
    separator("8. Ranking Analysis")

    labeled = [r for r in ember_results
               if r["inference_success"] and r["ember_score"] is not None
               and r["label"] in ("benign", "malicious")]

    if not labeled:
        print("  No labeled samples with successful inference.")
        return {"note": "No labeled samples available"}

    sorted_by_score = sorted(labeled, key=lambda x: x["ember_score"], reverse=True)

    print("  Ranked by EMBER score (descending):")
    for i, r in enumerate(sorted_by_score, 1):
        print(f"    {i}. {r['filename']}  label={r['label']}  score={r['ember_score']:.6f}")

    benign_scores = [r["ember_score"] for r in labeled if r["label"] == "benign"]
    malicious_scores = [r["ember_score"] for r in labeled if r["label"] == "malicious"]

    from typing import Any
    result: dict[str, Any] = {
        "ranked_samples": [{
            "filename": r["filename"],
            "label": r["label"],
            "score": r["ember_score"],
        } for r in sorted_by_score],
    }

    if benign_scores:
        result["highest_benign_score"] = max(benign_scores)
        result["lowest_benign_score"] = min(benign_scores)
    if malicious_scores:
        result["highest_malicious_score"] = max(malicious_scores)
        result["lowest_malicious_score"] = min(malicious_scores)
    if benign_scores and malicious_scores:
        overlap_low = max(min(benign_scores), min(malicious_scores))
        overlap_high = min(max(benign_scores), max(malicious_scores))
        if overlap_low <= overlap_high:
            result["overlap_region"] = [overlap_low, overlap_high]
        else:
            result["overlap_region"] = None
            result["perfect_separation"] = True
    else:
        result["note"] = "Cannot compute overlap -- missing benign or malicious samples"

    print()
    if benign_scores:
        print(f"  Highest benign score: {max(benign_scores):.6f}")
        print(f"  Lowest benign score:  {min(benign_scores):.6f}")
    if malicious_scores:
        print(f"  Highest malicious:    {max(malicious_scores):.6f}")
        print(f"  Lowest malicious:     {min(malicious_scores):.6f}")

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("  PHASE 6D.1 -- EMBER2024 Android Discriminative Validation")
    print("=" * 70)
    print(f"  Model:    {MODEL_PATH}")
    print(f"  Model exists: {MODEL_PATH.is_file()}")
    print(f"  Expected dimension: {EMBER_EXPECTED_DIMENSION}")
    print()

    all_results = {}

    # 1. Corpus validation
    corpus = validate_corpus()
    all_results["corpus"] = corpus

    # 2. EMBER inference
    ember_results = run_ember_inference(corpus)
    all_results["ember_inference"] = [{k: v for k, v in r.items() if k != "path"}
                                       for r in ember_results]

    # 3. Feature activation analysis
    feature_analysis = run_feature_activation_analysis(corpus)
    all_results["feature_activation"] = feature_analysis

    # 4. CiphR comparison
    ciphr_comparison = run_ciphr_comparison(ember_results)
    all_results["ciphr_comparison"] = ciphr_comparison

    # 5. Determinism
    determinism = run_determinism_test(corpus)
    all_results["determinism"] = determinism

    # 6. Performance
    performance = run_performance_measurement(corpus)
    all_results["performance"] = performance

    # 7. Score distribution
    score_dist = score_distribution_analysis(ember_results)
    all_results["score_distribution"] = score_dist

    # 8. Ranking
    ranking = ranking_analysis(ember_results)
    all_results["ranking"] = ranking

    # Save results
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_FILE, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    separator("Results saved")
    print(f"  {RESULTS_FILE}")
    print()


if __name__ == "__main__":
    main()
