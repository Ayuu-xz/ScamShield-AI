"""Comprehensive tests for shared URL extraction, OCR preprocessing, and message/image endpoints."""

import io

from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFont

from app.main import app
from app.services import ocr_service
from app.services.url_extractor import extract_urls_from_text

client = TestClient(app)


def _render_text_image(
    lines: list[str],
    *,
    size: tuple[int, int] = (720, 180),
    bg: tuple[int, int, int] = (255, 255, 255),
    fg: tuple[int, int, int] = (0, 0, 0),
) -> bytes:
    """Render readable text onto an in-memory PNG image for real RapidOCR testing."""
    img = Image.new("RGB", size, color=bg)
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 22)
    except OSError:
        font = ImageFont.load_default()

    y = 24
    for line in lines:
        draw.text((20, y), line, fill=fg, font=font)
        y += 32

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_extract_urls_full_www_and_bare_domains() -> None:
    text = (
        "Visit https://example.com/path?a=1#top, www.bank-help.org/login, "
        "bit.ly/3xYz9, and sbi-kyc-update.xyz:8443/verify?id=42!"
    )
    res = extract_urls_from_text(text, source="message")
    assert res.detected_urls == [
        "https://example.com/path?a=1#top",
        "www.bank-help.org/login",
        "bit.ly/3xYz9",
        "sbi-kyc-update.xyz:8443/verify?id=42",
    ]


def test_extract_urls_handles_markdown_brackets_and_balanced_parens() -> None:
    text = (
        "See [Verify Account](https://phish-demo.com/auth) or "
        "(http://example.org/help) and https://en.wikipedia.org/wiki/Phishing_(security)."
    )
    res = extract_urls_from_text(text, source="message")
    assert res.detected_urls == [
        "https://phish-demo.com/auth",
        "http://example.org/help",
        "https://en.wikipedia.org/wiki/Phishing_(security)",
    ]


def test_extract_urls_excludes_emails_filenames_and_decimals() -> None:
    text = (
        "Email support@example.com or admin@sbi-verify.com. "
        "Attached invoice.pdf (v1.2) for Rs.500.00."
    )
    res = extract_urls_from_text(text, source="message")
    assert res.detected_urls == []


def test_extract_urls_reconstructs_line_split_urls() -> None:
    text = "Urgent! Click:\nhttps://secure-login-update.com/verify/\naccount?id=9981\nThank you"
    res = extract_urls_from_text(text, source="ocr")
    assert res.line_split_reconstructed is True
    assert res.detected_urls == ["https://secure-login-update.com/verify/account?id=9981"]


def test_extract_urls_repairs_ocr_spaces_without_mutating_suggested_candidates() -> None:
    text = "Open https : //paypa1-verify.c0m/login or bit .ly/abc123"
    res = extract_urls_from_text(text, source="ocr")
    assert res.detected_urls == ["https://paypa1-verify.c0m/login", "bit.ly/abc123"]
    assert len(res.suggested_candidates) == 1
    assert res.suggested_candidates[0].original == "https://paypa1-verify.c0m/login"
    assert res.suggested_candidates[0].suggested == "https://paypa1-verify.com/login"


def test_extract_urls_deduplicates_preserving_order() -> None:
    text = "Check HTTPS://Example.COM/a and https://example.com/a and www.test.org"
    res = extract_urls_from_text(text, source="message")
    assert res.detected_urls == ["HTTPS://Example.COM/a", "www.test.org"]


def test_message_endpoint_detects_bare_domain_and_matches_url_scanner() -> None:
    bare_url = "paypa1-secure-login.com/verify"
    url_res = client.post("/api/scan/url", json={"url": bare_url}).json()
    msg_res = client.post(
        "/api/scan/message",
        json={"message": f"Urgent alert: please verify at {bare_url} immediately."},
    ).json()

    assert msg_res["status"] == "completed"
    assert msg_res["detected_urls"] == [bare_url]
    assert msg_res["overall_risk_score"] == url_res["risk_score"]
    assert msg_res["overall_risk_level"] == url_res["risk_level"]


def test_real_ocr_extracts_bare_and_https_urls_from_light_and_dark_screenshots() -> None:
    light_png = _render_text_image(
        ["Urgent KYC Update", "Visit https://paypa1-secure-login.com/verify"],
        bg=(255, 255, 255),
        fg=(0, 0, 0),
    )
    light_ocr = ocr_service.extract_text_from_image(light_png)
    assert light_ocr.ocr_status == "completed"
    assert "paypa1" in light_ocr.extracted_text.lower()

    res_light = client.post(
        "/api/scan/message-image",
        files={"file": ("light.png", light_png, "image/png")},
    )
    assert res_light.status_code == 200
    data_light = res_light.json()
    assert data_light["status"] == "completed"
    assert len(data_light["detected_urls"]) >= 1
    assert data_light["overall_risk_score"] >= 45

    dark_png = _render_text_image(
        ["Account Alert", "Click bit.ly/verify-kyc-now"],
        size=(520, 140),
        bg=(15, 23, 42),
        fg=(241, 245, 249),
    )
    res_dark = client.post(
        "/api/scan/message-image",
        files={"file": ("dark.png", dark_png, "image/png")},
    )
    assert res_dark.status_code == 200
    data_dark = res_dark.json()
    assert data_dark["extracted_text"]
    assert data_dark["status"] == "completed"
    assert any("bit.ly" in u.lower() for u in data_dark["detected_urls"])
