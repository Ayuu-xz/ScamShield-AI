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
    ocr_status: str = "completed"
    ocr_warnings: tuple[str, ...] = ()


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


def _parse_rapidocr_output(ocr_output) -> tuple[str, float | None]:
    """Extract ordered text lines and mean confidence from RapidOCR output."""
    if not ocr_output:
        return "", None

    lines: list[str] = []
    confidences: list[float] = []
    for item in ocr_output:
        # RapidOCR returns [box, text, confidence]
        if len(item) >= 2 and isinstance(item[1], str):
            text_line = item[1].strip()
            if text_line:
                lines.append(text_line)
        if len(item) >= 3:
            try:
                confidences.append(float(item[2]))
            except (TypeError, ValueError):
                pass

    extracted_text = "\n".join(lines).strip()
    mean_confidence = (
        round(sum(confidences) / len(confidences), 4) if confidences else None
    )
    return extracted_text, mean_confidence


def _prepare_image_variants(img, config: ImageUploadConfig):
    """Apply EXIF orientation fix, safe upscaling for small screenshots, and contrast variants."""
    from PIL import Image, ImageOps

    oriented = ImageOps.exif_transpose(img).convert("RGB")
    width, height = oriented.size
    min_side = min(width, height)

    # Upscale small screenshots/crops so URLs and small characters are legible to RapidOCR
    if min_side > 0 and min_side < 800:
        scale = 2 if min_side >= 400 else 3
        new_w = min(width * scale, config.max_dimension_px)
        new_h = min(height * scale, config.max_dimension_px)
        if new_w > width or new_h > height:
            oriented = oriented.resize((new_w, new_h), Image.Resampling.LANCZOS)

    gray_auto = ImageOps.autocontrast(ImageOps.grayscale(oriented)).convert("RGB")
    inverted_auto = ImageOps.invert(ImageOps.autocontrast(ImageOps.grayscale(oriented))).convert("RGB")
    return oriented, gray_auto, inverted_auto


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
            primary_img, contrast_img, inverted_img = _prepare_image_variants(img, config)

        primary_out, _ = engine(np.array(primary_img))
        best_text, best_conf = _parse_rapidocr_output(primary_out)

        # Fallback passes only if primary pass found no text or had low confidence
        if not best_text or (best_conf is not None and best_conf < 0.7):
            for variant in (contrast_img, inverted_img):
                alt_out, _ = engine(np.array(variant))
                alt_text, alt_conf = _parse_rapidocr_output(alt_out)
                if alt_text and (
                    not best_text
                    or (len(alt_text) > len(best_text) and (alt_conf or 0.0) >= (best_conf or 0.0) - 0.05)
                    or ((alt_conf or 0.0) > (best_conf or 0.0) + 0.08)
                ):
                    best_text, best_conf = alt_text, alt_conf
    except OcrUnavailableError:
        raise
    except Exception as exc:
        raise OcrUnavailableError("OCR processing failed for the uploaded image.") from exc

    if not best_text:
        return OcrExtractionResult(
            extracted_text="",
            ocr_confidence=None,
            low_confidence_warning=None,
            ocr_status="no_text",
            ocr_warnings=("No readable text was detected in the uploaded image.",),
        )

    warnings: list[str] = []
    low_warning = None
    if best_conf is not None and best_conf < config.low_confidence_threshold:
        low_warning = (
            f"OCR confidence is low ({int(best_conf * 100)}%). "
            "Extracted text or URLs may be incomplete or inaccurate—please review carefully."
        )
        warnings.append(low_warning)

    return OcrExtractionResult(
        extracted_text=best_text,
        ocr_confidence=best_conf,
        low_confidence_warning=low_warning,
        ocr_status="completed",
        ocr_warnings=tuple(warnings),
    )
