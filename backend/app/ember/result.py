"""
EMBER2024 inference result contract.

Provides a stable, well-documented result representation for EMBER
classifier output. All fields are always present — consumers never
need to guess what happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EMBER_MODEL_NAME = "EMBER2024"
EMBER_MODEL_VERSION = "thrember-0.1.0 / EMBER2024_APK.model"
EMBER_FEATURE_VERSION = "thrember-PEFeatureExtractor-v3"
EMBER_EXPECTED_DIMENSION = 2568

SCORE_SEMANTICS = (
    "Raw LightGBM classifier output for binary (benign=0 / malicious=1) "
    "classification. This is a model confidence score, NOT a calibrated "
    "probability of maliciousness. Do not interpret as a percentage or "
    "apply naive thresholds (e.g. >0.5 = malware)."
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EmberResult:
    """Immutable result of a single EMBER2024 inference run.

    Every field is always populated so consumers never encounter
    missing keys.

    Attributes:
        model_name:         Fixed identifier "EMBER2024".
        model_version:      Identifies the pretrained model artefact.
        feature_version:    Identifies the feature extraction pipeline.
        score:              Raw numeric classifier output, or None on failure.
        score_semantics:    Human-readable description of what `score` means.
        feature_dimension:  Actual feature vector length produced, or None.
        expected_dimension: The dimension the model was trained on (2568).
        inference_success:  True iff a valid score was produced.
        error:              Diagnostic string on failure; None on success.
    """

    model_name: str = EMBER_MODEL_NAME
    model_version: str = EMBER_MODEL_VERSION
    feature_version: str = EMBER_FEATURE_VERSION
    score: Optional[float] = None
    score_semantics: str = SCORE_SEMANTICS
    feature_dimension: Optional[int] = None
    expected_dimension: int = EMBER_EXPECTED_DIMENSION
    inference_success: bool = False
    error: Optional[str] = None

    # -- Convenience -----------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise to a plain dict (JSON-safe)."""
        return asdict(self)

    # -- Factory helpers -------------------------------------------------------

    @classmethod
    def success(
        cls,
        score: float,
        feature_dimension: int,
    ) -> "EmberResult":
        """Create a successful result."""
        return cls(
            score=score,
            feature_dimension=feature_dimension,
            inference_success=True,
            error=None,
        )

    @classmethod
    def failure(
        cls,
        error: str,
        feature_dimension: Optional[int] = None,
    ) -> "EmberResult":
        """Create a failed result with a diagnostic message."""
        return cls(
            score=None,
            feature_dimension=feature_dimension,
            inference_success=False,
            error=error,
        )
