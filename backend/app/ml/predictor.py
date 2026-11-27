"""Thread-safe, cached ML model loader and inference service."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

import joblib

from app.core.config import settings

_DEFAULT_ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
_DEFAULT_DISCLAIMER = "ML predictions are probabilistic and may be incorrect."


@dataclass(frozen=True)
class MLPredictionResult:
    """Structured ML prediction output."""

    available: bool
    prediction: str
    confidence: float | None = None
    calibrated: bool = False
    probabilities: dict[str, float] = field(default_factory=dict)
    model_version: str | None = None
    disclaimer: str = _DEFAULT_DISCLAIMER
    error: str | None = None


class MLModelRegistry:
    """Lazy-loading singleton cache for URL and Message ML pipelines."""

    def __init__(self, artifacts_dir: Path = _DEFAULT_ARTIFACTS_DIR) -> None:
        self._artifacts_dir = artifacts_dir
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[object, dict]] = {}

    def clear_cache(self) -> None:
        """Clear cached models (primarily for tests)."""
        with self._lock:
            self._cache.clear()

    def _load_model(self, kind: str) -> tuple[object, dict] | None:
        """Load model and metadata once into memory; return None if missing or corrupt."""
        if not settings.ml_config.enabled:
            return None

        with self._lock:
            if kind in self._cache:
                return self._cache[kind]

            model_path = self._artifacts_dir / f"{kind}_model.joblib"
            meta_path = self._artifacts_dir / f"{kind}_model_meta.json"
            if not model_path.exists():
                return None

            try:
                model = joblib.load(model_path)
                meta: dict = {}
                if meta_path.exists():
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                self._cache[kind] = (model, meta)
                return self._cache[kind]
            except Exception:
                return None

    def predict(self, kind: str, text: str) -> MLPredictionResult:
        """Run inference for 'url' or 'message' safely without exposing internal paths."""
        if not settings.ml_config.enabled:
            return MLPredictionResult(
                available=False,
                prediction="Model unavailable",
                error="ML inference is disabled by server configuration.",
            )

        loaded = self._load_model(kind)
        if loaded is None:
            return MLPredictionResult(
                available=False,
                prediction="Model unavailable",
                error=f"The {kind} ML model is currently unavailable.",
            )

        model, meta = loaded
        version = meta.get("model_version")
        calibrated = bool(meta.get("calibrated_probabilities", False))

        try:
            pred_label = str(model.predict([text])[0])
            probs_dict: dict[str, float] = {}
            confidence: float | None = None

            if hasattr(model, "predict_proba") and hasattr(model, "classes_"):
                raw_probs = model.predict_proba([text])[0]
                classes = [str(c) for c in model.classes_]
                probs_dict = {
                    cls: round(float(prob), 4) for cls, prob in zip(classes, raw_probs)
                }
                if calibrated and pred_label in probs_dict:
                    confidence = probs_dict[pred_label]

            return MLPredictionResult(
                available=True,
                prediction=pred_label,
                confidence=confidence,
                calibrated=calibrated,
                probabilities=probs_dict,
                model_version=version,
            )
        except Exception:
            return MLPredictionResult(
                available=False,
                prediction="Model unavailable",
                model_version=version,
                error=f"ML inference failed for {kind} input.",
            )


_registry = MLModelRegistry()


def get_ml_registry() -> MLModelRegistry:
    """Return the shared MLModelRegistry singleton."""
    return _registry


def predict_url_ml(url: str) -> MLPredictionResult:
    """Predict whether a URL string is Legitimate or Phishing using cached ML model."""
    return _registry.predict("url", url)


def predict_message_ml(message: str) -> MLPredictionResult:
    """Predict whether a message is Legitimate, Spam, Phishing, or Scam."""
    return _registry.predict("message", message)
