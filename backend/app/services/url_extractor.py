"""Shared URL extraction utility for both typed messages and OCR-extracted text.

All URLs are extracted and normalized using text-only operations.
No URLs are ever opened, fetched, resolved, or executed here.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Common non-web file extensions that should not be treated as bare-domain TLDs
# unless they have an explicit scheme (http(s)://), www. prefix, or URL path.
_NON_DOMAIN_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "webp",
        "gif",
        "svg",
        "ico",
        "bmp",
        "tiff",
        "txt",
        "md",
        "csv",
        "tsv",
        "json",
        "xml",
        "yaml",
        "yml",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "py",
        "js",
        "ts",
        "jsx",
        "tsx",
        "html",
        "css",
        "scss",
        "java",
        "cpp",
        "c",
        "h",
        "go",
        "rs",
        "rb",
        "php",
        "sh",
        "bat",
        "ps1",
        "mp3",
        "mp4",
        "wav",
        "avi",
        "mkv",
        "mov",
        "exe",
        "msi",
        "apk",
        "dmg",
        "iso",
        "tar",
        "gz",
        "rar",
        "7z",
    }
)

# Zero-width and soft-hyphen characters that break regex matching in copied/OCR text
_INVISIBLE_CHARS_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")

# Scheme spacing artifacts from OCR, e.g. "https : //example.com" or "http: //example.com"
_OCR_SCHEME_SPACE_RE = re.compile(r"\b(https?)\s*:\s*/\s*/\s*", re.IGNORECASE)

# Spacing before a dot in domain-like tokens from OCR, e.g. "example .com" or "bit .ly/abc"
_OCR_SPACE_BEFORE_DOT_RE = re.compile(
    r"([a-zA-Z0-9-])\s+\.([a-zA-Z]{2,24}(?:[/:\?#]|$|\s))"
)

# Spacing after a dot when followed by a short TLD + path/query, e.g. "bit. ly/abc"
_OCR_SPACE_AFTER_DOT_PATH_RE = re.compile(
    r"([a-zA-Z0-9-])\.\s+([a-zA-Z]{2,10}(?:/[^\s]*|:\d{1,5}))"
)

# Markdown link pattern: [anchor](url) -> extract url cleanly
_MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")

# Explicit scheme URLs (http:// or https://)
_EXPLICIT_URL_RE = re.compile(
    r"https?://[^\s<>\"'{}\\|^`\[\]]+",
    re.IGNORECASE,
)

# www.-prefixed URLs without scheme
_WWW_URL_RE = re.compile(
    r"(?<![a-zA-Z0-9@._-])www\.[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?::\d{1,5})?(?:[/?#][^\s<>\"'{}\\|^`\[\]]*)?",
    re.IGNORECASE,
)

# Bare domain URLs (e.g., bit.ly/abc, sbi-kyc.xyz/login, example.com:8080/path)
# Negative lookbehind prevents matching email addresses (user@example.com) or partial tokens.
_BARE_DOMAIN_RE = re.compile(
    r"(?<![a-zA-Z0-9@._:/-])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"([a-zA-Z]{2,24})"
    r"(?::\d{1,5})?"
    r"(?:[/?#][^\s<>\"'{}\\|^`\[\]]*)?",
    re.IGNORECASE,
)

# Bare IPv4 with port or path (e.g. 192.168.1.50/login or 192.168.1.50:8080/auth)
_BARE_IPV4_URL_RE = re.compile(
    r"(?<![a-zA-Z0-9@._:/-])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?::\d{1,5})?"
    r"(?:/[^\s<>\"'{}\\|^`\[\]]*)",
)

_COMMON_TLD_OCR_FIXES: dict[str, str] = {
    "c0m": "com",
    "0rg": "org",
    "n3t": "net",
    "1n": "in",
    "c0": "co",
    "i0": "io",
}


@dataclass(frozen=True)
class SuggestedUrlCandidate:
    """Optional conservative OCR ambiguity candidate shown separately for user review."""

    original: str
    suggested: str
    reason: str


@dataclass(frozen=True)
class UrlExtractionResult:
    """Structured result from shared URL extraction."""

    detected_urls: list[str] = field(default_factory=list)
    suggested_candidates: list[SuggestedUrlCandidate] = field(default_factory=list)
    line_split_reconstructed: bool = False


def _reconstruct_line_split_urls(text: str) -> tuple[str, bool]:
    """Rejoin URLs that wrapped across line breaks in SMS/OCR screenshots."""
    lines = text.splitlines()
    if len(lines) <= 1:
        return text, False

    reconstructed_lines: list[str] = []
    changed = False
    i = 0

    while i < len(lines):
        current = lines[i].rstrip()
        while i + 1 < len(lines):
            nxt = lines[i + 1].strip()
            if not nxt:
                break
            # Never merge if next line starts a brand new explicit URL
            if re.match(r"^(?:https?://|www\.)", nxt, re.IGNORECASE):
                break
            # Check if current line ends with an active URL fragment or break character
            ends_with_url_prefix = bool(
                re.search(
                    r"(?:https?://[^\s]*|www\.[^\s]*|[a-zA-Z0-9-]+\.[a-zA-Z]{2,24}/[^\s]*)$",
                    current,
                    re.IGNORECASE,
                )
            )
            ends_with_break_char = current.endswith(("/", "-", "?", "&", "=", ".", "%", "_"))
            # Next line must look like a single URL continuation token (no spaces, or starts with / or ?)
            next_first_token = nxt.split()[0]
            next_is_continuation = bool(
                re.match(r"^[/?#&=%a-zA-Z0-9._~+-]+$", next_first_token)
            ) and (
                nxt.startswith(("/", "?", "&", "=", ".", "-"))
                or (ends_with_break_char and " " not in nxt.strip())
                or (
                    ends_with_url_prefix
                    and current.endswith(("/", "-", "?", "&", "=", "%", "_"))
                )
            )
            if ends_with_url_prefix and next_is_continuation:
                current = current + nxt
                changed = True
                i += 1
            else:
                break
        reconstructed_lines.append(current)
        i += 1

    return "\n".join(reconstructed_lines), changed


def _prepare_working_text(raw_text: str, *, allow_ocr_repairs: bool) -> tuple[str, bool]:
    """Prepare a working copy for regex extraction without mutating displayed OCR text."""
    working = _INVISIBLE_CHARS_RE.sub("", raw_text)
    working, split_changed = _reconstruct_line_split_urls(working)

    if allow_ocr_repairs:
        working = _OCR_SCHEME_SPACE_RE.sub(lambda m: f"{m.group(1).lower()}://", working)
        working = _OCR_SPACE_BEFORE_DOT_RE.sub(r"\1.\2", working)
        working = _OCR_SPACE_AFTER_DOT_PATH_RE.sub(r"\1.\2", working)

    return working, split_changed


def _trim_trailing_punctuation(candidate: str) -> str:
    """Strip trailing punctuation and unmatched closing brackets from extracted URLs."""
    url = candidate.strip()
    while url:
        last = url[-1]
        if last in ".,!?;:\"'":
            url = url[:-1]
            continue
        if last == ")" and url.count(")") > url.count("("):
            url = url[:-1]
            continue
        if last == "]" and url.count("]") > url.count("["):
            url = url[:-1]
            continue
        if last == "}" and url.count("}") > url.count("{"):
            url = url[:-1]
            continue
        break
    return url


def _dedup_key(url: str) -> str:
    """Build a case-insensitive scheme/host deduplication key while preserving path case."""
    probe = url if "://" in url else f"http://{url}"
    try:
        parts = urlsplit(probe)
        host = (parts.hostname or "").lower()
        port = f":{parts.port}" if parts.port else ""
        path = parts.path or ""
        query = f"?{parts.query}" if parts.query else ""
        return f"{parts.scheme.lower()}://{host}{port}{path}{query}"
    except ValueError:
        return url.lower()


def _collect_ocr_candidates(urls: list[str]) -> list[SuggestedUrlCandidate]:
    """Suggest conservative OCR TLD corrections separately without mutating originals."""
    suggestions: list[SuggestedUrlCandidate] = []
    seen_pairs: set[tuple[str, str]] = set()

    for url in urls:
        probe = url if "://" in url else f"http://{url}"
        try:
            parts = urlsplit(probe)
            host = parts.hostname or ""
        except ValueError:
            continue

        if "." not in host:
            continue
        tld = host.rsplit(".", 1)[-1].lower()
        if tld in _COMMON_TLD_OCR_FIXES:
            fixed_tld = _COMMON_TLD_OCR_FIXES[tld]
            fixed_host = host[: -len(tld)] + fixed_tld
            suggested = url.replace(host, fixed_host, 1)
            pair = (url, suggested)
            if pair not in seen_pairs and suggested != url:
                seen_pairs.add(pair)
                suggestions.append(
                    SuggestedUrlCandidate(
                        original=url,
                        suggested=suggested,
                        reason=f"Possible OCR character substitution in TLD (.{tld} -> .{fixed_tld}).",
                    )
                )

    return suggestions


def extract_urls_from_text(
    raw_text: str,
    *,
    source: str = "message",
) -> UrlExtractionResult:
    """Extract, clean, and deduplicate URLs from typed messages or OCR text.

    Supports:
    - Full http:// and https:// URLs
    - www.-prefixed URLs
    - Bare domains with TLDs, ports, paths, queries, and fragments
    - Bare IPv4 URLs with paths/ports
    - Markdown/WhatsApp bracketed links and trailing punctuation stripping
    - Line-split URL reconstruction
    - Email exclusion (user@domain.com is NOT extracted)
    """
    if not raw_text or not raw_text.strip():
        return UrlExtractionResult()

    allow_ocr_repairs = source == "ocr"
    working, split_changed = _prepare_working_text(raw_text, allow_ocr_repairs=allow_ocr_repairs)

    spans_and_urls: list[tuple[int, int, str]] = []

    def _overlaps(start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e, _ in spans_and_urls)

    # 0. Markdown links [label](url)
    for match in _MARKDOWN_LINK_RE.finditer(working):
        inner = _trim_trailing_punctuation(match.group(1))
        if inner and not _overlaps(match.start(1), match.end(1)):
            spans_and_urls.append((match.start(1), match.end(1), inner))

    # 1. Explicit http:// / https:// URLs
    for match in _EXPLICIT_URL_RE.finditer(working):
        cleaned = _trim_trailing_punctuation(match.group(0))
        if cleaned and not _overlaps(match.start(), match.end()):
            spans_and_urls.append((match.start(), match.end(), cleaned))

    # 2. www.-prefixed URLs
    for match in _WWW_URL_RE.finditer(working):
        cleaned = _trim_trailing_punctuation(match.group(0))
        if cleaned and not _overlaps(match.start(), match.end()):
            spans_and_urls.append((match.start(), match.end(), cleaned))

    # 3. Bare IPv4 URLs with path/port
    for match in _BARE_IPV4_URL_RE.finditer(working):
        cleaned = _trim_trailing_punctuation(match.group(0))
        if cleaned and not _overlaps(match.start(), match.end()):
            spans_and_urls.append((match.start(), match.end(), cleaned))

    # 4. Bare domain URLs (excluding email addresses and non-web filenames)
    for match in _BARE_DOMAIN_RE.finditer(working):
        if _overlaps(match.start(), match.end()):
            continue
        cleaned = _trim_trailing_punctuation(match.group(0))
        if not cleaned:
            continue
        tld = match.group(1).lower()
        has_path_or_port = any(ch in cleaned for ch in ("/", "?", "#", ":"))
        if tld in _NON_DOMAIN_FILE_EXTENSIONS and not has_path_or_port:
            continue
        # Double-check email context (e.g. "name@sub.domain.com")
        prefix_idx = match.start() - 1
        if prefix_idx >= 0 and working[prefix_idx] == "@":
            continue
        spans_and_urls.append((match.start(), match.end(), cleaned))

    # Sort by position in text so original order is preserved
    spans_and_urls.sort(key=lambda item: item[0])

    unique_urls: list[str] = []
    seen_keys: set[str] = set()
    for _, _, url in spans_and_urls:
        key = _dedup_key(url)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_urls.append(url)

    suggested = _collect_ocr_candidates(unique_urls) if allow_ocr_repairs else []

    logger.info(
        "URL extraction completed",
        extra={
            "source": source,
            "input_length": len(raw_text),
            "extracted_url_count": len(unique_urls),
            "line_split_reconstructed": split_changed,
            "suggested_candidate_count": len(suggested),
        },
    )

    return UrlExtractionResult(
        detected_urls=unique_urls,
        suggested_candidates=suggested,
        line_split_reconstructed=split_changed,
    )
