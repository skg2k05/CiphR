"""
EMBER2024 APK Classifier — core inference adapter.

Provides a single entry-point ``classify_apk(apk_path)`` that:

1. Validates the input file.
2. Lazy-loads the pretrained LightGBM model (once, thread-safe).
3. Extracts the 2568-dimensional feature vector via thrember.
4. Runs inference.
5. Returns a stable ``EmberResult``.

The adapter never executes APK code, makes network requests, or modifies
the filesystem.  All failures are caught and returned as ``EmberResult``
with ``inference_success=False``.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

import numpy as np

from app.ember.result import (
    EMBER_EXPECTED_DIMENSION,
    EmberResult,
)

logger = logging.getLogger("ciphr.ember")

# ---------------------------------------------------------------------------
# Model path resolution
# ---------------------------------------------------------------------------

def _resolve_model_path() -> str:
    """Return the EMBER model path from settings (lazy import to avoid
    circular imports or import-time crashes)."""
    try:
        from app.core.config import settings
        return str(settings.EMBER_MODEL_PATH)
    except Exception:
        # Fallback: environment variable
        return os.environ.get(
            "EMBER_MODEL_PATH",
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "..", "scratch", "ember2024_benchmark", "EMBER2024_APK.model",
            ),
        )


# ---------------------------------------------------------------------------
# Lazy, thread-safe model singleton
# ---------------------------------------------------------------------------

class _ModelHolder:
    """Holds the LightGBM Booster so it is loaded at most once."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._booster = None  # type: ignore[assignment]
        self._load_error: Optional[str] = None
        self._loaded = False
        self._load_time: Optional[float] = None

    def get(self, model_path: Optional[str] = None) -> tuple:
        """Return (booster | None, error_string | None, load_time_seconds | None).

        Thread-safe.  The model is loaded on first call and reused
        thereafter.  If *model_path* differs from the previously loaded
        path the holder reloads (this is mainly useful for testing).
        """
        if model_path is None:
            model_path = _resolve_model_path()

        with self._lock:
            if self._loaded and self._load_error is None:
                return self._booster, None, self._load_time

            # Reset state for (re-)load
            self._booster = None
            self._load_error = None
            self._loaded = False
            self._load_time = None

            try:
                import lightgbm as lgb
            except ImportError as exc:
                self._load_error = f"lightgbm not installed: {exc}"
                self._loaded = True
                return None, self._load_error, None

            if not os.path.isfile(model_path):
                self._load_error = f"Model file not found: {model_path}"
                self._loaded = True
                return None, self._load_error, None

            try:
                t0 = time.perf_counter()
                booster = lgb.Booster(model_file=model_path)
                elapsed = time.perf_counter() - t0
                self._booster = booster
                self._load_time = elapsed
                self._loaded = True
                logger.info(
                    "EMBER2024 model loaded in %.4fs from %s",
                    elapsed, model_path,
                )
                return self._booster, None, self._load_time
            except Exception as exc:
                self._load_error = f"Failed to load model: {exc}"
                self._loaded = True
                logger.error("EMBER model load failed: %s", self._load_error)
                return None, self._load_error, None

    def reset(self) -> None:
        """Force re-load on next access (useful for tests)."""
        with self._lock:
            self._booster = None
            self._load_error = None
            self._loaded = False
            self._load_time = None


# Module-level singleton
_model = _ModelHolder()


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _extract_features(file_bytes: bytes) -> tuple:
    """Extract the EMBER feature vector from raw file bytes.

    Returns (feature_vector | None, dimension | None, error | None,
             extraction_time_seconds).
    """
    try:
        from thrember.features import PEFeatureExtractor
    except ImportError as exc:
        return None, None, f"thrember not installed: {exc}", 0.0

    t0 = time.perf_counter()
    try:
        extractor = PEFeatureExtractor()
        features = extractor.feature_vector(file_bytes)
        elapsed = time.perf_counter() - t0

        if not isinstance(features, np.ndarray):
            features = np.array(features, dtype=np.float32)

        dim = features.shape[0] if features.ndim == 1 else features.shape[-1]
        return features, dim, None, elapsed

    except Exception as exc:
        elapsed = time.perf_counter() - t0
        return None, None, f"Feature extraction failed: {exc}", elapsed


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_apk(
    apk_path: str,
    *,
    model_path: Optional[str] = None,
) -> EmberResult:
    """Run EMBER2024 inference on a local APK file.

    Parameters
    ----------
    apk_path : str
        Absolute or relative path to an APK file on disk.
    model_path : str, optional
        Override the model file path (mainly for testing).

    Returns
    -------
    EmberResult
        Always returns a valid result object — never raises.
    """
    # ---- 1. Input validation ------------------------------------------------
    if not apk_path:
        return EmberResult.failure("APK path is empty or None")

    path = Path(apk_path)

    if not path.exists():
        return EmberResult.failure(f"File does not exist: {apk_path}")

    if path.is_dir():
        return EmberResult.failure(f"Path is a directory, not a file: {apk_path}")

    if path.stat().st_size == 0:
        return EmberResult.failure(f"File is empty (0 bytes): {apk_path}")

    # ---- 2. Read file bytes -------------------------------------------------
    try:
        file_bytes = path.read_bytes()
    except Exception as exc:
        return EmberResult.failure(f"Failed to read file: {exc}")

    # ---- 3. Load model ------------------------------------------------------
    booster, model_error, _load_time = _model.get(model_path)
    if model_error is not None:
        return EmberResult.failure(model_error)

    # ---- 4. Feature extraction ----------------------------------------------
    features, dim, feat_error, _feat_time = _extract_features(file_bytes)
    if feat_error is not None:
        return EmberResult.failure(feat_error, feature_dimension=dim)

    # ---- 5. Dimension validation --------------------------------------------
    if dim != EMBER_EXPECTED_DIMENSION:
        return EmberResult.failure(
            f"Feature dimension mismatch: got {dim}, "
            f"expected {EMBER_EXPECTED_DIMENSION}",
            feature_dimension=dim,
        )

    # ---- 6. Inference -------------------------------------------------------
    try:
        t0 = time.perf_counter()
        prediction = booster.predict([features])
        _inf_time = time.perf_counter() - t0
        score = float(prediction[0])
    except Exception as exc:
        return EmberResult.failure(
            f"Inference failed: {exc}",
            feature_dimension=dim,
        )

    # ---- 7. Success ---------------------------------------------------------
    logger.info(
        "EMBER2024 inference OK — score=%.6f  dim=%d  file=%s",
        score, dim, path.name,
    )
    return EmberResult.success(score=score, feature_dimension=dim)


def reset_model() -> None:
    """Force the model to be reloaded on the next ``classify_apk`` call.

    This is exposed for testing only — production code should not need it.
    """
    _model.reset()
