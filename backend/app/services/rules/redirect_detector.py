"""Rule A: Defensive URL redirect-pattern detection module (URL-text only)."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote

from app.core.config import UrlScoringWeights, settings
from app.services.indicators import RuleFinding

REDIRECT_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "redirect",
        "redirect_uri",
        "redirect_url",
        "next",
        "url",
        "target",
        "dest",
        "destination",
        "return",
        "return_to",
        "returnto",
        "continue",
        "goto",
        "out",
    }
)

_NESTED_URL_RE = re.compile(r"(?:https?://|//)[a-zA-Z0-9.-]+", re.IGNORECASE)
_ENCODED_SCHEME_RE = re.compile(r"(?:https?|%2f%2f|%3a%2f%2f)", re.IGNORECASE)


def detect_redirect_indicators(
    query: str,
    weights: UrlScoringWeights = settings.url_weights,
) -> list[RuleFinding]:
    """Inspect query parameters as plain text for deceptive or nested redirect patterns.

    Never follows redirects or requests destinations. Benign relative paths
    such as `?next=/dashboard` are not flagged as suspicious.
    """
    if not query:
        return []

    parsed_qs = parse_qs(query, keep_blank_values=True)
    nested_evidence: list[str] = []
    suspicious_param_evidence: list[str] = []

    for param, values in parsed_qs.items():
        lower_param = param.lower()
        for raw_val in values:
            decoded_once = unquote(raw_val)
            decoded_twice = unquote(decoded_once)

            has_nested_url = bool(
                _NESTED_URL_RE.search(raw_val)
                or _NESTED_URL_RE.search(decoded_once)
                or _NESTED_URL_RE.search(decoded_twice)
            )
            has_multi_encoded_dest = (
                raw_val != decoded_once
                and decoded_once != decoded_twice
                and bool(_ENCODED_SCHEME_RE.search(decoded_twice))
            )

            if has_nested_url or has_multi_encoded_dest:
                nested_evidence.append(f"{param}={raw_val[:80]}")
            elif lower_param in REDIRECT_PARAM_NAMES and raw_val.strip() and not raw_val.startswith("/"):
                suspicious_param_evidence.append(f"{param}={raw_val[:80]}")

    findings: list[RuleFinding] = []
    if nested_evidence:
        findings.append(
            RuleFinding(
                rule_id="nested_redirect",
                rule_name="Nested or Deceptive Redirect Destination",
                category="redirect",
                severity="medium",
                evidence=f"Nested redirect parameter(s): {'; '.join(nested_evidence[:3])}",
                explanation=(
                    "A query parameter embeds an external or encoded URL destination, which can "
                    "be abused in open-redirect phishing to disguise where the link ultimately sends you."
                ),
                recommendation="Inspect the embedded destination domain carefully before clicking.",
                score_contribution=weights.nested_redirect,
                detection_status="Detected",
                dedup_group="redirect_pattern",
            )
        )
    elif suspicious_param_evidence:
        findings.append(
            RuleFinding(
                rule_id="suspicious_redirect",
                rule_name="Suspicious Redirect Query Parameter",
                category="redirect",
                severity="low",
                evidence=f"Redirect parameter(s): {'; '.join(suspicious_param_evidence[:3])}",
                explanation=(
                    "The URL contains a redirect-style query parameter pointing to a non-relative target, "
                    "which may forward you to another destination."
                ),
                recommendation="Confirm you trust both the host site and the redirect target.",
                score_contribution=weights.suspicious_redirect,
                detection_status="Detected",
                dedup_group="redirect_pattern",
            )
        )

    return findings
