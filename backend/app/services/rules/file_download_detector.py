"""Rule C: Suspicious file, download, and third-party script indicator module."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qs, urljoin, urlsplit

from app.core.config import UrlScoringWeights, settings
from app.services.indicators import RuleFinding
from app.services.website_inspector import PageObservation

EXECUTABLE_EXTENSIONS: tuple[str, ...] = (
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".ps1",
    ".apk",
    ".js",
    ".vbs",
)

_DOWNLOAD_PARAM_NAMES: frozenset[str] = frozenset(
    {"file", "filename", "download", "attachment", "payload", "installer"}
)
_EXT_PATTERN = re.compile(
    r"(" + "|".join(re.escape(ext) for ext in EXECUTABLE_EXTENSIONS) + r")(?=$|[?#&])",
    re.IGNORECASE,
)

_SUSPICIOUS_SCRIPT_TLDS: frozenset[str] = frozenset(
    {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "mov", "loan", "win"}
)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def detect_file_download_indicators(
    path: str,
    query: str,
    weights: UrlScoringWeights = settings.url_weights,
) -> list[RuleFinding]:
    """Detect executable file extensions or risky download query patterns in URL text."""
    matched_ext: str | None = None
    evidence_parts: list[str] = []

    path_match = _EXT_PATTERN.search(path.lower())
    if path_match:
        matched_ext = path_match.group(1).lower()
        evidence_parts.append(f"Executable extension '{matched_ext}' in URL path '{path[:80]}'")

    parsed_qs = parse_qs(query, keep_blank_values=True)
    for param, values in parsed_qs.items():
        if param.lower() in _DOWNLOAD_PARAM_NAMES:
            for val in values:
                q_match = _EXT_PATTERN.search(val.lower())
                if q_match:
                    matched_ext = matched_ext or q_match.group(1).lower()
                    evidence_parts.append(f"Download parameter '{param}={val[:60]}'")

    if not evidence_parts:
        return []

    return [
        RuleFinding(
            rule_id="suspicious_file_download",
            rule_name="Executable or Risky File Extension in URL",
            category="file_download",
            severity="medium",
            evidence="; ".join(evidence_parts[:2]),
            explanation=(
                f"The URL references an executable or script file type ({matched_ext}). "
                "File extensions in a URL are a risk signal, not confirmation of malware."
            ),
            recommendation=(
                "Do not download or run executable files from unsolicited links or untrusted sources."
            ),
            score_contribution=weights.suspicious_download,
            detection_status="Detected",
            dedup_group="file_download",
        )
    ]


def detect_page_resource_indicators(
    observation: PageObservation,
    weights: UrlScoringWeights = settings.url_weights,
) -> list[RuleFinding]:
    """Inspect safely parsed HTML script/resource references without executing them."""
    findings: list[RuleFinding] = []
    suspicious_scripts: list[str] = []
    download_refs: list[str] = []

    for raw_src in observation.script_srcs:
        full_src = urljoin(observation.final_url, raw_src)
        src_host = (urlsplit(full_src).hostname or "").lower()
        if not src_host:
            continue
        tld = src_host.rsplit(".", 1)[-1] if "." in src_host else ""
        if _is_ip_literal(src_host) or tld in _SUSPICIOUS_SCRIPT_TLDS:
            suspicious_scripts.append(full_src[:100])

    if suspicious_scripts:
        findings.append(
            RuleFinding(
                rule_id="suspicious_third_party_script",
                rule_name="Suspicious Third-Party Script Resource",
                category="malware",
                severity="medium",
                evidence=f"External script(s): {'; '.join(suspicious_scripts[:2])}",
                explanation=(
                    "The page loads JavaScript from an IP-address host or an unusual top-level domain. "
                    "This is a suspicious indicator (not confirmed malware); scripts are never executed by the scanner."
                ),
                recommendation="Avoid interacting with pages that load scripts from untrusted hosts.",
                score_contribution=weights.suspicious_third_party_script,
                detection_status="Detected",
                detection_source="html_script",
            )
        )

    for href in observation.link_hrefs + observation.iframe_srcs:
        full_href = urljoin(observation.final_url, href)
        path = urlsplit(full_href).path
        if _EXT_PATTERN.search(path.lower()):
            download_refs.append(full_href[:100])

    if download_refs:
        findings.append(
            RuleFinding(
                rule_id="page_executable_download_ref",
                rule_name="Executable Download Reference on Page",
                category="file_download",
                severity="medium",
                evidence=f"Referenced resource(s): {'; '.join(download_refs[:2])}",
                explanation=(
                    "The page references an executable file download. File references are risk "
                    "signals only and are never downloaded or executed by ScamShield AI."
                ),
                recommendation="Do not download executable files from unverified websites.",
                score_contribution=weights.suspicious_download,
                detection_status="Detected",
                dedup_group="file_download",
                detection_source="html_page",
            )
        )

    return findings
