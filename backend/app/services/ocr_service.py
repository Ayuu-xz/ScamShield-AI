"""Image validation and OCR text-extraction service (kept separate from URL risk scoring).

Uploaded images are validated in memory and NEVER permanently stored on disk.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path

from app.core.config import ImageUploadConfig, settings


class ImageValidationError(ValueError):
    """Raised when an uploaded image fails format, size, dimension, or integrity checks."""


class OcrUnavailableError(RuntimeError):
    """Raised when the OCR engine is not installed or fails to execute."""


@dataclass(frozen=True)
class OcrExtractionResult:
    """Result of OCR text extraction from a validated image."""

    extracted_text: str
    ocr_confidence: float | None
    low_confidence_warning: str | None


_ocr_engine = None


def _get_ocr_engine():
    """Lazily initialize RapidOCR so startup stays fast and tests can mock cleanly."""
    global _ocr_engine
    if _ocr_engine is not None:
        return _ocr_engine
    try:
        from rapidocr_onnxruntime import RapidOCR  # type: ignore[import-not-found]
    except ImportError as exc:
        raise OcrUnavailableError(
            "OCR engine (rapidocr-onnxruntime) is not installed on the server."
        ) from exc

    try:
        _ocr_engine = RapidOCR()
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        raise OcrUnavailableError("Failed to initialize the OCR engine.") from exc
    return _ocr_engine


def validate_and_load_image(
    file_bytes: bytes,
    filename: str | None,
    content_type: str | None,
    config: ImageUploadConfig = settings.image_config,
) -> bytes:
    """Validate file size, extension, MIME type, image integrity, and dimensions."""
    if not file_bytes:
        raise ImageValidationError("Uploaded image file is empty.")

    if len(file_bytes) > config.max_file_size_bytes:
        max_mb = config.max_file_size_bytes // (1024 * 1024)
        raise ImageValidationError(f"Image exceeds the maximum allowed size of {max_mb} MB.")

    ext = Path(filename or "").suffix.lower()
    if ext not in config.allowed_extensions:
        raise ImageValidationError(
            "Unsupported file extension. Please upload a JPG, JPEG, PNG, or WEBP image."
        )

    normalized_mime = (content_type or "").split(";")[0].strip().lower()
    if normalized_mime and normalized_mime not in config.allowed_mime_types:
        raise ImageValidationError(
            "Unsupported MIME type. Please upload a valid JPG, PNG, or WEBP image."
        )

    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as exc:  # pragma: no cover
        raise OcrUnavailableError("Pillow image library is not installed on the server.") from exc

    try:
        with Image.open(io.BytesIO(file_bytes)) as img:
            img.verify()
        with Image.open(io.BytesIO(file_bytes)) as verified_img:
            if verified_img.format not in config.allowed_pil_formats:
                raise ImageValidationError(
                    "Invalid image format. Only JPEG, PNG, and WEBP images are supported."
                )
            width, height = verified_img.size
    except ImageValidationError:
        raise
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ImageValidationError(
            "Corrupted or unreadable image file. Please upload a valid screenshot or photo."
        ) from exc

    if width < config.min_dimension_px or height < config.min_dimension_px:
        raise ImageValidationError(
            f"Image dimensions ({width}x{height}) are too small for OCR."
        )
    if width > config.max_dimension_px or height > config.max_dimension_px:
        raise ImageValidationError(
            f"Image dimensions ({width}x{height}) exceed the maximum "
            f"{config.max_dimension_px}x{config.max_dimension_px} limit."
        )

    return file_bytes


def extract_text_from_image(
    file_bytes: bytes,
    config: ImageUploadConfig = settings.image_config,
) -> OcrExtractionResult:
    """Run OCR on validated image bytes and return exact extracted text + confidence."""
    engine = _get_ocr_engine()

    try:
        from PIL import Image
        import numpy as np

        with Image.open(io.BytesIO(file_bytes)) as img:
            rgb_img = img.convert("RGB")
            img_array = np.array(rgb_img)

        ocr_output, _ = engine(img_array)
    except OcrUnavailableError:
        raise
    except Exception as exc:
        raise OcrUnavailableError("OCR processing failed for the uploaded image.") from exc

    if not ocr_output:
        return OcrExtractionResult(
            extracted_text="",
            ocr_confidence=None,
            low_confidence_warning=None,
        )

    lines: list[str] = []
    confidences: list[float] = []
    for item in ocr_output:
        # RapidOCR returns [box, text, confidence]
        if len(item) >= 2 and isinstance(item[1], str):
            lines.append(item[1])
        if len(item) >= 3:
            try:
                confidences.append(float(item[2]))
            except (TypeError, ValueError):
                pass

    extracted_text = "\n".join(lines).strip()
    mean_confidence = (
        round(sum(confidences) / len(confidences), 4) if confidences else None
    )

    low_warning = None
    if mean_confidence is not None and mean_confidence < config.low_confidence_threshold:
        low_warning = (
            f"OCR confidence is low ({int(mean_confidence * 100)}%). "
            "Extracted text or URLs may be incomplete or inaccurate—please review carefully."
        )

    return OcrExtractionResult(
        extracted_text=extracted_text,
        ocr_confidence=mean_confidence,
        low_confidence_warning=low_warning,
    )
