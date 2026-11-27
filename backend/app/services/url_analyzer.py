"""Centralized URL analysis engine combining URL-text rules and optional isolated inspection."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import SplitResult, parse_qsl, urlencode, urlsplit

from app.core.config import ThreatIntelConfig, UrlAnalyzerConfig, UrlScoringWeights, settings
from app.services.indicators import RuleFinding
from app.services.rules.file_download_detector import (
    detect_file_download_indicators,
    detect_page_resource_indicators,
)
from app.services.rules.phishing_detector import (
    detect_page_phishing_indicators,
    detect_phishing_indicators,
)
from app.services.rules.redirect_detector import detect_redirect_indicators
from app.services.rules.threat_intel_service import (
    ThreatIntelResult,
    evaluate_threat_and_domain_intel,
)
from app.services.rules.tracker_detector import (
    TRACKING_QUERY_PARAMS,
    detect_page_tracker_indicators,
    detect_tracker_indicators,
)
from app.services.website_inspector import InspectionOutcome, inspect_website_safely

SHORTENER_DOMAINS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "tiny.cc",
        "rebrand.ly",
        "bl.ink",
        "s.id",
        "v.gd",
        "clck.ru",
    }
)

SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "xyz",
        "top",
        "click",
        "zip",
        "mov",
        "work",
        "support",
        "country",
        "stream",
        "download",
        "loan",
        "win",
        "bid",
    }
)

_PERCENT_ENCODING_RE = re.compile(r"%[0-9a-fA-F]{2}")
_CONTROL_OR_WHITESPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")


@dataclass(frozen=True)
class NormalizedUrl:
    """Validated and normalized URL components (text-only)."""

    original: str
    normalized: str
    scheme: str
    hostname: str
    netloc: str
    path: str
    query: str


def normalize_and_validate_url(
    raw_url: str,
    config: UrlAnalyzerConfig = settings.url_config,
) -> NormalizedUrl:
    """Validate and normalize an untrusted URL string without network calls."""
    if not isinstance(raw_url, str):
        raise ValueError("URL must be a text string.")

    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("URL cannot be empty.")

    if len(cleaned) > config.max_url_length:
        raise ValueError(
            f"URL exceeds maximum allowed length of {config.max_url_length} characters."
        )

    if _CONTROL_OR_WHITESPACE_RE.search(cleaned):
        raise ValueError("Malformed URL: URLs cannot contain spaces or control characters.")

    if "://" in cleaned:
        candidate = cleaned
    elif re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", cleaned):
        scheme_prefix = cleaned.split(":", 1)[0].lower()
        if scheme_prefix not in {"http", "https"}:
            raise ValueError(f"Unsupported or unsafe URL scheme: '{scheme_prefix}:'.")
        raise ValueError("Malformed URL: missing '//' after scheme.")
    else:
        candidate = f"http://{cleaned}"

    try:
        parsed: SplitResult = urlsplit(candidate)
    except ValueError as exc:
        raise ValueError("Malformed URL: could not parse URL structure.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported or unsafe URL scheme: '{scheme}'.")

    try:
        hostname = (parsed.hostname or "").lower().rstrip(".")
    except ValueError as exc:
        raise ValueError("Malformed URL: invalid hostname or IPv6 syntax.") from exc

    if not hostname:
        raise ValueError("Malformed URL: missing hostname.")

    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Malformed URL: invalid port number.") from exc

    if not _is_ip_address(hostname):
        if "." not in hostname and hostname != "localhost":
            raise ValueError("Malformed URL: hostname must include a valid domain suffix.")
        if hostname.startswith(".") or ".." in hostname:
            raise ValueError("Malformed URL: invalid dot placement in hostname.")

    normalized = parsed.geturl()
    return NormalizedUrl(
        original=cleaned,
        normalized=normalized,
        scheme=scheme,
        hostname=hostname,
        netloc=parsed.netloc,
        path=parsed.path or "",
        query=parsed.query or "",
    )


def _is_ip_address(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 literal (pure string check)."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _count_subdomains(hostname: str) -> int:
    """Count subdomains excluding a standard leading 'www.' prefix."""
    labels = [lbl for lbl in hostname.split(".") if lbl]
    if labels and labels[0] == "www":
        labels = labels[1:]
    return max(0, len(labels) - 2)


def analyze_url_full(
    raw_url: str,
    *,
    inspect_website: bool = False,
    weights: UrlScoringWeights = settings.url_weights,
    config: UrlAnalyzerConfig = settings.url_config,
    threat_config: ThreatIntelConfig = settings.threat_intel,
    provider_fn: Callable[[str, str, ThreatIntelConfig], ThreatIntelResult] | None = None,
    inspector_fn: Callable[[str], InspectionOutcome] | None = None,
) -> tuple[NormalizedUrl, list[RuleFinding], dict, InspectionOutcome]:
    """Run centralized URL-text rules and optional isolated website inspection."""
    parsed = normalize_and_validate_url(raw_url, config=config)
    findings: list[RuleFinding] = []

    is_ip = _is_ip_address(parsed.hostname)
    is_shortener = parsed.hostname in SHORTENER_DOMAINS

    # 1. Suspicious domain / IP / obfuscation structure (+15)
    structure_reasons: list[str] = []
    if is_ip:
        structure_reasons.append(f"raw IP host '{parsed.hostname}'")
    if not is_ip and not is_shortener:
        subdomain_count = _count_subdomains(parsed.hostname)
        if subdomain_count >= config.excessive_subdomain_threshold:
            structure_reasons.append(f"{subdomain_count} subdomains")
        tld = parsed.hostname.rsplit(".", 1)[-1] if "." in parsed.hostname else ""
        if tld in SUSPICIOUS_TLDS:
            structure_reasons.append(f"commonly abused TLD '.{tld}'")
        if parsed.hostname.count("-") >= config.excessive_hyphen_threshold:
            structure_reasons.append("excessive hyphens in hostname")
    if "@" in parsed.netloc:
        structure_reasons.append("contains '@' in authority")
    percent_encodings = len(_PERCENT_ENCODING_RE.findall(parsed.normalized))
    if percent_encodings >= config.excessive_encoding_threshold:
        structure_reasons.append(f"{percent_encodings} percent-encoded sequences")
    if "//" in parsed.path:
        structure_reasons.append("contains '//' in path")

    non_tracking_query = urlencode(
        [
            (k, v)
            for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if k.lower() not in TRACKING_QUERY_PARAMS
        ]
    )
    effective_len = len(f"{parsed.scheme}://{parsed.netloc}{parsed.path}") + (
        len(non_tracking_query) + 1 if non_tracking_query else 0
    )
    if effective_len > config.long_url_threshold:
        structure_reasons.append(f"long URL ({effective_len} chars)")

    if structure_reasons:
        findings.append(
            RuleFinding(
                rule_id="suspicious_domain_structure",
                rule_name="Suspicious Domain or URL Structure",
                category="url_structure",
                severity="medium" if is_ip else "low",
                evidence="; ".join(structure_reasons),
                explanation=(
                    "The URL exhibits structural or obfuscation patterns "
                    f"({'; '.join(structure_reasons)})."
                ),
                recommendation="Inspect the main domain carefully before trusting this link.",
                score_contribution=weights.suspicious_domain_structure,
                detection_status="Detected",
                dedup_group="url_structure",
            )
        )

    # 2. URL shortener (+10)
    if is_shortener:
        findings.append(
            RuleFinding(
                rule_id="url_shortener",
                rule_name="URL Shortener",
                category="url_structure",
                severity="low",
                evidence=f"Domain '{parsed.hostname}' is a known URL shortener.",
                explanation=f"The domain '{parsed.hostname}' masks the final destination URL.",
                recommendation="Verify shortened links with the sender before clicking.",
                score_contribution=weights.url_shortener,
                detection_status="Detected",
            )
        )

    # 3. Missing HTTPS (+5)
    if parsed.scheme != "https":
        findings.append(
            RuleFinding(
                rule_id="missing_https",
                rule_name="Missing HTTPS Encryption",
                category="url_structure",
                severity="low",
                evidence=f"URL uses '{parsed.scheme}://' instead of 'https://'.",
                explanation=(
                    "The URL uses unencrypted HTTP rather than HTTPS. Missing HTTPS alone does "
                    "not make a URL Dangerous, but sensitive data should not be submitted over HTTP."
                ),
                recommendation="Never submit passwords or payment details on non-HTTPS pages.",
                score_contribution=weights.missing_https,
                detection_status="Detected",
            )
        )

    # 4. URL-based Tracker Indicators (informational, 0 pts)
    findings.extend(detect_tracker_indicators(parsed.hostname, parsed.query))

    # 5. URL-based Phishing Indicators
    findings.extend(
        detect_phishing_indicators(
            hostname=parsed.hostname,
            path=parsed.path,
            query=parsed.query,
            is_ip=is_ip,
            is_shortener=is_shortener,
            weights=weights,
        )
    )

    # 6. Rule A: Redirect Indicators
    findings.extend(detect_redirect_indicators(parsed.query, weights=weights))

    # 7. Rule C: File & Download Indicators
    findings.extend(detect_file_download_indicators(parsed.path, parsed.query, weights=weights))

    # 8. Rule B & Malware: Threat Intel & Domain Intelligence
    intel_findings, domain_summary = evaluate_threat_and_domain_intel(
        normalized_url=parsed.normalized,
        hostname=parsed.hostname,
        is_ip=is_ip,
        weights=weights,
        config=threat_config,
        provider_fn=provider_fn,
    )
    findings.extend(intel_findings)

    # 9. Optional Isolated Read-Only Website Inspection
    if inspect_website:
        outcome = (
            inspector_fn(parsed.normalized)
            if inspector_fn is not None
            else inspect_website_safely(parsed.normalized)
        )
        if outcome.status == "completed" and outcome.observation is not None:
            findings.extend(detect_page_tracker_indicators(outcome.observation))
            findings.extend(
                detect_page_phishing_indicators(
                    observation=outcome.observation,
                    initial_hostname=parsed.hostname,
                    weights=weights,
                )
            )
            findings.extend(detect_page_resource_indicators(outcome.observation, weights=weights))
    else:
        outcome = InspectionOutcome(
            status="not_requested",
            reason="URL-only analysis — website content was not inspected.",
        )

    return parsed, findings, domain_summary, outcome


def analyze_url(
    raw_url: str,
    weights: UrlScoringWeights = settings.url_weights,
    config: UrlAnalyzerConfig = settings.url_config,
) -> tuple[NormalizedUrl, list[RuleFinding]]:
    """Backward-compatible wrapper returning (normalized_url, findings)."""
    parsed, findings, _, _ = analyze_url_full(raw_url, weights=weights, config=config)
    return parsed, findings
