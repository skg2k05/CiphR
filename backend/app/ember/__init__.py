"""
EMBER2024 APK Classifier — Independent Evidence Provider for CiphR.

This package provides a clean, isolated interface for running EMBER2024
LightGBM-based binary classification on APK files.

EMBER is an ADDITIONAL signal source — it does NOT replace any existing
CiphR analysis (static analysis, TLSH, VirusTotal, LLM narrative, etc.).

Usage:
    from app.ember import classify_apk, EmberResult

    result: EmberResult = classify_apk("/path/to/sample.apk")
    if result.inference_success:
        print(f"EMBER score: {result.score}")
    else:
        print(f"EMBER failed: {result.error}")
"""

from app.ember.result import EmberResult
from app.ember.classifier import classify_apk

__all__ = ["classify_apk", "EmberResult"]
