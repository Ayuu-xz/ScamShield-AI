"""Shared text-only feature extraction for ML training and inference.

Important: URLs are never visited, fetched, or executed during feature extraction.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qs, urlsplit

import numpy as np

_PERCENT_ENCODING_RE = re.compile(r"%[0-9a-fA-F]{2}")
_SPECIAL_CHARS_RE = re.compile(r"[^a-zA-Z0-9]")
_URL_IN_MSG_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'{}\\|^`\[\]]+", re.IGNORECASE)
_SUSPICIOUS_URL_TOKENS_RE = re.compile(
    r"(login|signin|verify|kyc|password|update|secure|account|bank|paypal|redirect|next=|\.exe|\.apk)",
    re.IGNORECASE,
)

LEXICAL_FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "has_ip",
    "subdomain_count",
    "param_count",
    "encoding_count",
    "has_https",
    "has_at_symbol",
    "suspicious_token_count",
)


def extract_single_url_lexical_features(raw_url: str) -> list[float]:
    """Extract 15 deterministic lexical features from a URL string (text-only)."""
    cleaned = (raw_url or "").strip()
    candidate = cleaned if "://" in cleaned else f"http://{cleaned}"
    try:
        parsed = urlsplit(candidate)
        hostname = (parsed.hostname or "").lower()
    except ValueError:
        hostname = ""
        parsed = urlsplit("http://invalid.local")

    has_ip = 0.0
    if hostname:
        try:
            ipaddress.ip_address(hostname)
            has_ip = 1.0
        except ValueError:
            has_ip = 0.0

    labels = [lbl for lbl in hostname.split(".") if lbl]
    if labels and labels[0] == "www":
        labels = labels[1:]
    subdomain_count = float(max(0, len(labels) - 2)) if not has_ip else 0.0

    param_count = float(len(parse_qs(parsed.query, keep_blank_values=True)))
    encoding_count = float(len(_PERCENT_ENCODING_RE.findall(cleaned)))
    suspicious_tokens = float(len(_SUSPICIOUS_URL_TOKENS_RE.findall(cleaned)))

    return [
        float(len(cleaned)),
        float(len(hostname)),
        float(len(parsed.path or "")),
        float(len(parsed.query or "")),
        float(cleaned.count(".")),
        float(cleaned.count("-")),
        float(sum(ch.isdigit() for ch in cleaned)),
        float(len(_SPECIAL_CHARS_RE.findall(cleaned))),
        has_ip,
        subdomain_count,
        param_count,
        encoding_count,
        1.0 if parsed.scheme.lower() == "https" else 0.0,
        1.0 if "@" in parsed.netloc else 0.0,
        suspicious_tokens,
    ]


def extract_url_lexical_matrix(urls) -> np.ndarray:
    """Scikit-learn FunctionTransformer-compatible batch lexical feature extractor."""
    return np.asarray([extract_single_url_lexical_features(u) for u in urls], dtype=np.float64)


def preprocess_message_text(raw_text: str) -> str:
    """Normalize message text for TF-IDF without leaking raw URLs."""
    text = (raw_text or "").strip().lower()
    text = _URL_IN_MSG_RE.sub(" __url__ ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text
