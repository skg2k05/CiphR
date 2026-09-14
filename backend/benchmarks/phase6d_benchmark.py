#!/usr/bin/env python
"""
Phase 6D -- EMBER2024 Integration Readiness Benchmark.

Run from the backend directory:
    python benchmarks/phase6d_benchmark.py

Reports:
  A. Inference on all available fixture APKs
  B. Determinism test (3 identical runs)
  C. Failure isolation tests
  D. Performance measurement
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import numpy as np

# Ensure backend root is on sys.path so `app.*` imports work
BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.ember.classifier import classify_apk, reset_model, _model, _extract_features
from app.ember.result import EMBER_EXPECTED_DIMENSION

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
FIXTURES_DIR = BACKEND_ROOT / "tests" / "fixtures"
MODEL_PATH = BACKEND_ROOT / "scratch" / "ember2024_benchmark" / "EMBER2024_APK.model"
RESULTS_FILE = Path(__file__).parent / "phase6d_results.json"

# Collect all APK fixtures
APK_FILES = sorted(FIXTURES_DIR.glob("*.apk"))


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def separator(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


# ---------------------------------------------------------------------------
# A. Benchmark all fixture APKs
# ---------------------------------------------------------------------------

def run_apk_benchmark() -> list[dict]:
    separator("A. APK Inference Benchmark")
    results = []

    for apk in APK_FILES:
        sha = sha256_of(apk)
        reset_model()

        t0 = time.perf_counter()
        result = classify_apk(str(apk), model_path=str(MODEL_PATH))
        elapsed = time.perf_counter() - t0

        row = {
            "filename": apk.name,
            "sha256": sha,
            "feature_extraction_success": result.feature_dimension is not None,
            "feature_dimension": result.feature_dimension,
            "inference_success": result.inference_success,
            "raw_score": result.score,
            "total_time_s": round(elapsed, 4),
            "error": result.error,
        }
        results.append(row)

        status = "OK" if result.inference_success else "FAIL"
        print(f"  [{status}] {apk.name}")
        print(f"       SHA256: {sha[:16]}...")
        print(f"       Features: dim={result.feature_dimension}  expected={EMBER_EXPECTED_DIMENSION}")
        print(f"       Score: {result.score}")
        print(f"       Time: {elapsed:.4f}s")
        if result.error:
            print(f"       Error: {result.error}")
        print()

    return results


# ---------------------------------------------------------------------------
# B. Determinism test
# ---------------------------------------------------------------------------

def run_determinism_test() -> list[dict]:
    separator("B. Determinism Test (3 runs)")

    if not APK_FILES:
        print("  No APK fixtures found — skipping.")
        return []

    target = APK_FILES[0]  # Use first available
    reset_model()

    runs = []
    for i in range(1, 4):
        result = classify_apk(str(target), model_path=str(MODEL_PATH))
        row = {
            "run": i,
            "score": result.score,
            "feature_dimension": result.feature_dimension,
            "inference_success": result.inference_success,
        }
        runs.append(row)
        print(f"  Run {i}: score={result.score}  dim={result.feature_dimension}  success={result.inference_success}")

    # Check determinism
    scores = [r["score"] for r in runs]
    if len(set(str(s) for s in scores)) == 1:
        print(f"\n  [OK] DETERMINISTIC -- all scores identical: {scores[0]}")
    else:
        print(f"\n  [FAIL] NON-DETERMINISTIC -- scores differ: {scores}")

    return runs


# ---------------------------------------------------------------------------
# C. Failure isolation tests
# ---------------------------------------------------------------------------

def run_failure_tests() -> list[dict]:
    separator("C. Failure Isolation Tests")
    results = []

    tests = [
        {
            "name": "Nonexistent file",
            "apk_path": "/nonexistent/path/to/malware.apk",
            "model_path": str(MODEL_PATH),
            "expected": "controlled failure (file not found)",
        },
        {
            "name": "Directory instead of file",
            "apk_path": str(FIXTURES_DIR),
            "model_path": str(MODEL_PATH),
            "expected": "controlled failure (is directory)",
        },
        {
            "name": "Empty path",
            "apk_path": "",
            "model_path": str(MODEL_PATH),
            "expected": "controlled failure (empty path)",
        },
        {
            "name": "Missing model",
            "apk_path": str(APK_FILES[0]) if APK_FILES else "/any/path.apk",
            "model_path": "/nonexistent/model/EMBER2024_APK.model",
            "expected": "controlled failure (model not found)",
        },
    ]

    for t in tests:
        reset_model()
        result = classify_apk(t["apk_path"], model_path=t["model_path"])
        status = "PASS" if not result.inference_success else "FAIL"
        row = {
            "test": t["name"],
            "expected": t["expected"],
            "actual": f"inference_success={result.inference_success}, error={result.error}",
            "status": status,
        }
        results.append(row)
        print(f"  [{status}] {t['name']}")
        print(f"       Expected: {t['expected']}")
        print(f"       Got: inference_success={result.inference_success}")
        print(f"       Error: {result.error}")
        print()

    return results


# ---------------------------------------------------------------------------
# D. Performance measurement
# ---------------------------------------------------------------------------

def run_performance_test() -> dict:
    separator("D. Performance Measurement")

    if not APK_FILES or not MODEL_PATH.is_file():
        print("  Prerequisites missing — skipping.")
        return {}

    target = APK_FILES[0]
    reset_model()

    # 1. Model load time
    import lightgbm as lgb
    t0 = time.perf_counter()
    booster = lgb.Booster(model_file=str(MODEL_PATH))
    model_load_time = time.perf_counter() - t0

    # 2. Feature extraction time
    file_bytes = target.read_bytes()
    t0 = time.perf_counter()
    features, dim, err, _ = _extract_features(file_bytes)
    feat_time = time.perf_counter() - t0

    # 3. Inference time
    if features is not None:
        t0 = time.perf_counter()
        _ = booster.predict(np.array([features]))
        inf_time = time.perf_counter() - t0
    else:
        inf_time = None

    # 4. Total end-to-end
    reset_model()
    t0 = time.perf_counter()
    _ = classify_apk(str(target), model_path=str(MODEL_PATH))
    total_time = time.perf_counter() - t0

    perf = {
        "model_load_s": round(model_load_time, 4),
        "feature_extraction_s": round(feat_time, 4),
        "inference_s": round(inf_time, 4) if inf_time is not None else None,
        "total_end_to_end_s": round(total_time, 4),
        "sample": target.name,
    }

    print(f"  Model load:          {perf['model_load_s']:.4f}s")
    print(f"  Feature extraction:  {perf['feature_extraction_s']:.4f}s")
    print(f"  Inference:           {perf['inference_s']}s")
    print(f"  Total end-to-end:    {perf['total_end_to_end_s']:.4f}s")
    print(f"  Sample:              {target.name}")

    return perf


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  PHASE 6D — EMBER2024 Integration Readiness Benchmark")
    print("=" * 60)
    print(f"  Model:    {MODEL_PATH}")
    print(f"  Fixtures: {FIXTURES_DIR}")
    print(f"  APKs:     {[a.name for a in APK_FILES]}")
    print(f"  Model exists: {MODEL_PATH.is_file()}")
    print()

    all_results = {}

    all_results["apk_benchmark"] = run_apk_benchmark()
    all_results["determinism"] = run_determinism_test()
    all_results["failure_tests"] = run_failure_tests()
    all_results["performance"] = run_performance_test()

    # Save JSON results
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_FILE, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    separator("Results saved")
    print(f"  {RESULTS_FILE}")
    print()


if __name__ == "__main__":
    main()
