"""
Phase 6D — EMBER2024 adapter tests.

Tests:
  1. Valid APK → successful inference
  2. Same APK repeated → deterministic result
  3. Missing APK → controlled failure
  4. Invalid APK → controlled failure
  5. Missing model → controlled failure
  6. Feature dimension mismatch → controlled failure
  7. Result contract always contains required fields
"""

import os
import pytest
from unittest.mock import patch
from pathlib import Path

# Paths
FIXTURES_DIR = Path(__file__).parent / "fixtures"
VALID_APK = FIXTURES_DIR / "ApiDemos-debug.apk"
DUMMY_APK = FIXTURES_DIR / "dummy.apk"  # 177 bytes, likely not a real APK
DUMMY2_APK = FIXTURES_DIR / "dummy2.apk"  # 6 bytes

# Resolve model path — use the Phase 6C model
MODEL_PATH = Path(__file__).parent.parent / "scratch" / "ember2024_benchmark" / "EMBER2024_APK.model"

# Required fields in every EmberResult
REQUIRED_FIELDS = {
    "model_name",
    "model_version",
    "feature_version",
    "score",
    "score_semantics",
    "feature_dimension",
    "expected_dimension",
    "inference_success",
    "error",
}


def _have_model() -> bool:
    return MODEL_PATH.is_file()


def _have_valid_apk() -> bool:
    return VALID_APK.is_file()


def _have_thrember() -> bool:
    try:
        import thrember
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Imports (deferred to allow collection even when deps missing)
# ---------------------------------------------------------------------------

from app.ember.result import EmberResult, EMBER_EXPECTED_DIMENSION
from app.ember.classifier import classify_apk, reset_model


# ---------------------------------------------------------------------------
# Test 1: Valid APK → successful inference
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _have_model(), reason="EMBER model not available")
@pytest.mark.skipif(not _have_valid_apk(), reason="ApiDemos-debug.apk not available")
@pytest.mark.skipif(not _have_thrember(), reason="thrember not installed")
def test_valid_apk_inference():
    """A known-good APK should produce a successful EmberResult."""
    reset_model()
    result = classify_apk(str(VALID_APK), model_path=str(MODEL_PATH))

    assert isinstance(result, EmberResult)
    assert result.inference_success is True
    assert result.error is None
    assert result.score is not None
    assert isinstance(result.score, float)
    assert result.feature_dimension == EMBER_EXPECTED_DIMENSION
    assert result.model_name == "EMBER2024"


# ---------------------------------------------------------------------------
# Test 2: Same APK repeated → deterministic result
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _have_model(), reason="EMBER model not available")
@pytest.mark.skipif(not _have_valid_apk(), reason="ApiDemos-debug.apk not available")
@pytest.mark.skipif(not _have_thrember(), reason="thrember not installed")
def test_deterministic_inference():
    """Running inference on the same APK multiple times must produce
    identical scores (within floating-point tolerance)."""
    reset_model()
    results = [
        classify_apk(str(VALID_APK), model_path=str(MODEL_PATH))
        for _ in range(3)
    ]

    assert all(r.inference_success for r in results)
    scores = [r.score for r in results]
    dims = [r.feature_dimension for r in results]

    # Scores must be exactly equal (deterministic model + deterministic features)
    assert scores[0] == scores[1] == scores[2], f"Non-deterministic scores: {scores}"
    assert dims[0] == dims[1] == dims[2], f"Non-deterministic dimensions: {dims}"


# ---------------------------------------------------------------------------
# Test 3: Missing APK → controlled failure
# ---------------------------------------------------------------------------

def test_missing_apk():
    """A path to a nonexistent file must produce a controlled failure."""
    result = classify_apk("/nonexistent/path/to/sample.apk", model_path=str(MODEL_PATH))

    assert isinstance(result, EmberResult)
    assert result.inference_success is False
    assert result.error is not None
    assert "does not exist" in result.error
    assert result.score is None


# ---------------------------------------------------------------------------
# Test 4: Invalid APK → controlled failure (not crash)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _have_model(), reason="EMBER model not available")
def test_invalid_apk():
    """An empty or tiny file should either produce a controlled failure
    or (since EMBER treats files as binary blobs) a low-confidence result.
    It must NEVER crash."""
    reset_model()

    # Test with empty-ish files
    for apk in [DUMMY_APK, DUMMY2_APK]:
        if not apk.is_file():
            continue
        result = classify_apk(str(apk), model_path=str(MODEL_PATH))
        assert isinstance(result, EmberResult)
        # Should either succeed (EMBER processes any bytes) or fail gracefully
        if not result.inference_success:
            assert result.error is not None

    # Test with a directory
    result = classify_apk(str(FIXTURES_DIR), model_path=str(MODEL_PATH))
    assert result.inference_success is False
    assert "directory" in result.error.lower()

    # Test with empty path
    result = classify_apk("", model_path=str(MODEL_PATH))
    assert result.inference_success is False
    assert result.error is not None


# ---------------------------------------------------------------------------
# Test 5: Missing model → controlled failure
# ---------------------------------------------------------------------------

def test_missing_model():
    """If the model file doesn't exist, inference must fail gracefully."""
    reset_model()
    result = classify_apk(
        str(VALID_APK) if _have_valid_apk() else "/any/path.apk",
        model_path="/nonexistent/model/EMBER2024_APK.model",
    )

    assert isinstance(result, EmberResult)
    assert result.inference_success is False
    assert result.error is not None
    assert "not found" in result.error.lower() or "not exist" in result.error.lower() or "model" in result.error.lower()
    assert result.score is None


# ---------------------------------------------------------------------------
# Test 6: Feature dimension mismatch → controlled failure
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _have_model(), reason="EMBER model not available")
@pytest.mark.skipif(not _have_valid_apk(), reason="ApiDemos-debug.apk not available")
def test_feature_dimension_mismatch():
    """If the feature extractor produces wrong dimensions, must fail cleanly."""
    import numpy as np

    reset_model()

    # Patch _extract_features to return wrong-dimension vector
    wrong_dim = 100
    fake_features = np.zeros(wrong_dim, dtype=np.float32)

    with patch("app.ember.classifier._extract_features") as mock_extract:
        mock_extract.return_value = (fake_features, wrong_dim, None, 0.01)
        result = classify_apk(str(VALID_APK), model_path=str(MODEL_PATH))

    assert isinstance(result, EmberResult)
    assert result.inference_success is False
    assert result.error is not None
    assert "dimension mismatch" in result.error.lower()
    assert result.feature_dimension == wrong_dim


# ---------------------------------------------------------------------------
# Test 7: Result contract — all required fields present
# ---------------------------------------------------------------------------

def test_result_contract_success():
    """A successful EmberResult must contain all required fields."""
    result = EmberResult.success(score=0.42, feature_dimension=2568)
    d = result.to_dict()
    assert REQUIRED_FIELDS.issubset(d.keys()), f"Missing fields: {REQUIRED_FIELDS - d.keys()}"
    assert d["inference_success"] is True
    assert d["error"] is None
    assert d["score"] == 0.42


def test_result_contract_failure():
    """A failed EmberResult must contain all required fields."""
    result = EmberResult.failure(error="something broke")
    d = result.to_dict()
    assert REQUIRED_FIELDS.issubset(d.keys()), f"Missing fields: {REQUIRED_FIELDS - d.keys()}"
    assert d["inference_success"] is False
    assert d["score"] is None
    assert d["error"] == "something broke"


def test_result_immutable():
    """EmberResult should be immutable (frozen dataclass)."""
    result = EmberResult.success(score=0.5, feature_dimension=2568)
    with pytest.raises(AttributeError):
        result.score = 0.9  # type: ignore[misc]
