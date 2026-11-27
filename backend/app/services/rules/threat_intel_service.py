"""Rule B & Malware Indicator: Multi-Provider Threat Intelligence & Domain Intelligence.

Supported providers (all optional, configured via backend environment variables):
1. Google Safe Browsing API v4 (requires GOOGLE_SAFE_BROWSING_API_KEY)
2. URLhaus by abuse.ch (enabled via URLHAUS_ENABLED=true + optional URLHAUS_AUTH_KEY)
3. Custom JSON threat-intel endpoint (THREAT_INTEL_PROVIDER + ENDPOINT_URL + API_KEY)

Security & privacy rules:
- Never exposes API keys in responses or logs.
- Never treats timeouts, rate limits, or auth errors as clean results.
- Never double-counts the same threat across multiple providers.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

import httpx

from app.core.config import ThreatIntelConfig, UrlScoringWeights, settings
from app.services.indicators import RuleFinding

GOOGLE_SB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


@dataclass(frozen=True)
class ProviderLookupRecord:
    """Per-provider lookup outcome for transparent dashboard reporting."""

    provider_name: str
    lookup_status: str  # Detected | Not detected | Check unavailable | Rate limited | Invalid credentials | Timeout | Error
    threat_category: str = "Unavailable"
    checked_at: str = ""
    cached: bool = False
    error: str | None = None


@dataclass(frozen=True)
class ThreatIntelResult:
    """Normalized response from one or aggregated threat-intelligence providers."""

    provider_status: str  # "available" | "unavailable" | "error"
    provider_name: str
    is_phishing: bool = False
    is_malware: bool = False
    is_malicious_domain: bool = False
    domain_age_days: int | None = None
    confidence: str | None = None
    error_message: str | None = None
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cached: bool = False
    provider_results: list[ProviderLookupRecord] = field(default_factory=list)


_CACHE_LOCK = threading.Lock()
_INTEL_CACHE: dict[str, tuple[float, ThreatIntelResult]] = {}


def clear_threat_intel_cache() -> None:
    """Clear the in-memory threat-intelligence cache (primarily for tests)."""
    with _CACHE_LOCK:
        _INTEL_CACHE.clear()


def _query_google_safe_browsing(
    normalized_url: str,
    config: ThreatIntelConfig,
) -> tuple[ThreatIntelResult, ProviderLookupRecord]:
    """Query Google Safe Browsing Lookup API v4 with minimum required payload."""
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        response = httpx.post(
            GOOGLE_SB_ENDPOINT,
            params={"key": config.google_safe_browsing_api_key},
            json={
                "client": {"clientId": "scamshield-ai", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": normalized_url}],
                },
            },
            timeout=config.timeout_seconds,
        )
        if response.status_code in {400, 401, 403}:
            rec = ProviderLookupRecord(
                provider_name="Google Safe Browsing",
                lookup_status="Invalid credentials",
                checked_at=checked_at,
                error="Invalid or unauthorized Google Safe Browsing API key.",
            )
            return ThreatIntelResult(provider_status="error", provider_name="Google Safe Browsing", error_message=rec.error), rec
        if response.status_code == 429:
            rec = ProviderLookupRecord(
                provider_name="Google Safe Browsing",
                lookup_status="Rate limited",
                checked_at=checked_at,
                error="Google Safe Browsing rate limit exceeded.",
            )
            return ThreatIntelResult(provider_status="error", provider_name="Google Safe Browsing", error_message=rec.error), rec
        response.raise_for_status()

        payload = response.json()
        matches = payload.get("matches") or []
        threat_types = {m.get("threatType", "") for m in matches if isinstance(m, dict)}
        is_phish = "SOCIAL_ENGINEERING" in threat_types
        is_mal = bool(
            threat_types
            & {"MALWARE", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"}
        )

        if is_phish or is_mal:
            cat = "Phishing & Malware" if (is_phish and is_mal) else ("Phishing" if is_phish else "Malware")
            rec = ProviderLookupRecord(
                provider_name="Google Safe Browsing",
                lookup_status="Detected",
                threat_category=cat,
                checked_at=checked_at,
            )
        else:
            rec = ProviderLookupRecord(
                provider_name="Google Safe Browsing",
                lookup_status="Not detected",
                threat_category="None",
                checked_at=checked_at,
            )

        return (
            ThreatIntelResult(
                provider_status="available",
                provider_name="Google Safe Browsing",
                is_phishing=is_phish,
                is_malware=is_mal,
                confidence="high" if (is_phish or is_mal) else None,
                checked_at=checked_at,
            ),
            rec,
        )
    except httpx.TimeoutException:
        rec = ProviderLookupRecord(
            provider_name="Google Safe Browsing",
            lookup_status="Timeout",
            checked_at=checked_at,
            error="Google Safe Browsing request timed out.",
        )
        return ThreatIntelResult(provider_status="error", provider_name="Google Safe Browsing", error_message=rec.error), rec
    except (httpx.HTTPError, ValueError, TypeError):
        rec = ProviderLookupRecord(
            provider_name="Google Safe Browsing",
            lookup_status="Error",
            checked_at=checked_at,
            error="Google Safe Browsing lookup failed.",
        )
        return ThreatIntelResult(provider_status="error", provider_name="Google Safe Browsing", error_message=rec.error), rec


def _query_urlhaus(
    normalized_url: str,
    config: ThreatIntelConfig,
) -> tuple[ThreatIntelResult, ProviderLookupRecord]:
    """Query URLhaus (abuse.ch) API for known malware distribution URLs."""
    checked_at = datetime.now(timezone.utc).isoformat()
    headers = {"Auth-Key": config.urlhaus_auth_key} if config.urlhaus_auth_key else {}
    try:
        response = httpx.post(
            URLHAUS_ENDPOINT,
            data={"url": normalized_url},
            headers=headers,
            timeout=config.timeout_seconds,
        )
        if response.status_code in {401, 403}:
            rec = ProviderLookupRecord(
                provider_name="URLhaus (abuse.ch)",
                lookup_status="Invalid credentials",
                checked_at=checked_at,
                error="URLhaus API requires a valid Auth-Key.",
            )
            return ThreatIntelResult(provider_status="error", provider_name="URLhaus (abuse.ch)", error_message=rec.error), rec
        if response.status_code == 429:
            rec = ProviderLookupRecord(
                provider_name="URLhaus (abuse.ch)",
                lookup_status="Rate limited",
                checked_at=checked_at,
                error="URLhaus rate limit exceeded.",
            )
            return ThreatIntelResult(provider_status="error", provider_name="URLhaus (abuse.ch)", error_message=rec.error), rec
        response.raise_for_status()

        payload = response.json()
        q_status = str(payload.get("query_status", "")).lower()
        if q_status == "ok":
            threat_tag = str(payload.get("threat", "malware_download"))
            rec = ProviderLookupRecord(
                provider_name="URLhaus (abuse.ch)",
                lookup_status="Detected",
                threat_category=threat_tag,
                checked_at=checked_at,
            )
            return (
                ThreatIntelResult(
                    provider_status="available",
                    provider_name="URLhaus (abuse.ch)",
                    is_malware=True,
                    confidence="high",
                    checked_at=checked_at,
                ),
                rec,
            )

        rec = ProviderLookupRecord(
            provider_name="URLhaus (abuse.ch)",
            lookup_status="Not detected",
            threat_category="None",
            checked_at=checked_at,
        )
        return (
            ThreatIntelResult(
                provider_status="available",
                provider_name="URLhaus (abuse.ch)",
                checked_at=checked_at,
            ),
            rec,
        )
    except httpx.TimeoutException:
        rec = ProviderLookupRecord(
            provider_name="URLhaus (abuse.ch)",
            lookup_status="Timeout",
            checked_at=checked_at,
            error="URLhaus request timed out.",
        )
        return ThreatIntelResult(provider_status="error", provider_name="URLhaus (abuse.ch)", error_message=rec.error), rec
    except (httpx.HTTPError, ValueError, TypeError):
        rec = ProviderLookupRecord(
            provider_name="URLhaus (abuse.ch)",
            lookup_status="Error",
            checked_at=checked_at,
            error="URLhaus lookup failed.",
        )
        return ThreatIntelResult(provider_status="error", provider_name="URLhaus (abuse.ch)", error_message=rec.error), rec


def _query_custom_provider(
    normalized_url: str,
    hostname: str,
    config: ThreatIntelConfig,
) -> tuple[ThreatIntelResult, ProviderLookupRecord]:
    """Query an explicitly configured custom HTTP threat-intelligence provider."""
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        response = httpx.post(
            config.endpoint_url,
            json={"url": normalized_url, "domain": hostname},
            headers={"Authorization": f"Bearer {config.api_key}"},
            timeout=config.timeout_seconds,
        )
        if response.status_code in {401, 403}:
            rec = ProviderLookupRecord(
                provider_name=config.provider_name,
                lookup_status="Invalid credentials",
                checked_at=checked_at,
                error=f"Invalid API credentials for {config.provider_name}.",
            )
            return ThreatIntelResult(provider_status="error", provider_name=config.provider_name, error_message=rec.error), rec
        if response.status_code == 429:
            rec = ProviderLookupRecord(
                provider_name=config.provider_name,
                lookup_status="Rate limited",
                checked_at=checked_at,
                error=f"Rate limit exceeded for {config.provider_name}.",
            )
            return ThreatIntelResult(provider_status="error", provider_name=config.provider_name, error_message=rec.error), rec
        response.raise_for_status()

        payload = response.json()
        is_phish = bool(payload.get("is_phishing", False))
        is_mal = bool(payload.get("is_malware", False))
        is_dom = bool(payload.get("is_malicious_domain", False))
        age_days = (
            int(payload["domain_age_days"])
            if payload.get("domain_age_days") is not None
            else None
        )
        cat = "Phishing" if is_phish else ("Malware" if is_mal else ("Malicious Domain" if is_dom else "None"))
        rec = ProviderLookupRecord(
            provider_name=config.provider_name,
            lookup_status="Detected" if (is_phish or is_mal or is_dom) else "Not detected",
            threat_category=cat,
            checked_at=checked_at,
        )
        return (
            ThreatIntelResult(
                provider_status="available",
                provider_name=config.provider_name,
                is_phishing=is_phish,
                is_malware=is_mal,
                is_malicious_domain=is_dom,
                domain_age_days=age_days,
                confidence=payload.get("confidence"),
                checked_at=checked_at,
            ),
            rec,
        )
    except httpx.TimeoutException:
        rec = ProviderLookupRecord(
            provider_name=config.provider_name,
            lookup_status="Timeout",
            checked_at=checked_at,
            error=f"{config.provider_name} request timed out.",
        )
        return ThreatIntelResult(provider_status="error", provider_name=config.provider_name, error_message=rec.error), rec
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        rec = ProviderLookupRecord(
            provider_name=config.provider_name,
            lookup_status="Error",
            checked_at=checked_at,
            error=f"{config.provider_name} lookup failed.",
        )
        return ThreatIntelResult(provider_status="error", provider_name=config.provider_name, error_message=rec.error), rec


def _query_configured_providers(
    normalized_url: str,
    hostname: str,
    config: ThreatIntelConfig,
) -> ThreatIntelResult:
    """Query all configured threat-intelligence providers with TTL caching."""
    has_gsb = bool(config.google_safe_browsing_api_key)
    has_urlhaus = bool(config.urlhaus_enabled)
    has_custom = bool(config.provider_name and config.endpoint_url and config.api_key)

    if not (has_gsb or has_urlhaus or has_custom):
        return ThreatIntelResult(
            provider_status="unavailable",
            provider_name="unconfigured",
            error_message="No external threat-intelligence provider is configured.",
        )

    cache_key = f"{has_gsb}:{has_urlhaus}:{config.provider_name}:{normalized_url}"
    now = time.monotonic()
    with _CACHE_LOCK:
        cached_entry = _INTEL_CACHE.get(cache_key)
        if cached_entry and cached_entry[0] > now:
            base = cached_entry[1]
            cached_records = [
                ProviderLookupRecord(
                    provider_name=r.provider_name,
                    lookup_status=r.lookup_status,
                    threat_category=r.threat_category,
                    checked_at=r.checked_at,
                    cached=True,
                    error=r.error,
                )
                for r in base.provider_results
            ]
            return ThreatIntelResult(
                provider_status=base.provider_status,
                provider_name=base.provider_name,
                is_phishing=base.is_phishing,
                is_malware=base.is_malware,
                is_malicious_domain=base.is_malicious_domain,
                domain_age_days=base.domain_age_days,
                confidence=base.confidence,
                error_message=base.error_message,
                checked_at=base.checked_at,
                cached=True,
                provider_results=cached_records,
            )

    sub_results: list[ThreatIntelResult] = []
    records: list[ProviderLookupRecord] = []

    if has_gsb:
        res, rec = _query_google_safe_browsing(normalized_url, config)
        sub_results.append(res)
        records.append(rec)
    if has_urlhaus:
        res, rec = _query_urlhaus(normalized_url, config)
        sub_results.append(res)
        records.append(rec)
    if has_custom:
        res, rec = _query_custom_provider(normalized_url, hostname, config)
        sub_results.append(res)
        records.append(rec)

    available_results = [r for r in sub_results if r.provider_status == "available"]
    if not available_results:
        first_err = next((r.error_message for r in sub_results if r.error_message), "All threat-intel providers failed.")
        return ThreatIntelResult(
            provider_status="error",
            provider_name=", ".join(r.provider_name for r in records),
            error_message=first_err,
            provider_results=records,
        )

    # Conflict resolution: confirmed threat from ANY provider wins over no-match.
    is_phish = any(r.is_phishing for r in available_results)
    is_mal = any(r.is_malware for r in available_results)
    is_dom = any(r.is_malicious_domain for r in available_results)
    age_days = next((r.domain_age_days for r in available_results if r.domain_age_days is not None), None)
    conf = next((r.confidence for r in available_results if r.confidence), None)

    aggregated = ThreatIntelResult(
        provider_status="available",
        provider_name=", ".join(r.provider_name for r in available_results),
        is_phishing=is_phish,
        is_malware=is_mal,
        is_malicious_domain=is_dom,
        domain_age_days=age_days,
        confidence=conf,
        checked_at=datetime.now(timezone.utc).isoformat(),
        cached=False,
        provider_results=records,
    )

    with _CACHE_LOCK:
        _INTEL_CACHE[cache_key] = (now + max(1, config.cache_ttl_seconds), aggregated)

    return aggregated


def evaluate_threat_and_domain_intel(
    *,
    normalized_url: str,
    hostname: str,
    is_ip: bool,
    weights: UrlScoringWeights = settings.url_weights,
    config: ThreatIntelConfig = settings.threat_intel,
    provider_fn: Callable[[str, str, ThreatIntelConfig], ThreatIntelResult] | None = None,
) -> tuple[list[RuleFinding], dict]:
    """Evaluate phishing/malware reputation and domain age safely."""
    lookup_fn = provider_fn or _query_configured_providers
    intel = lookup_fn(normalized_url, hostname, config)
    findings: list[RuleFinding] = []

    serialized_records = [
        {
            "provider_name": r.provider_name,
            "lookup_status": r.lookup_status,
            "threat_category": r.threat_category,
            "checked_at": r.checked_at,
            "cached": r.cached,
            "error": r.error,
        }
        for r in intel.provider_results
    ]

    if intel.provider_status != "available":
        reason = intel.error_message or "External reputation provider is unavailable."
        findings.append(
            RuleFinding(
                rule_id="malware_reputation_unavailable",
                rule_name="Malware Reputation Check",
                category="malware",
                severity="info",
                evidence=reason,
                explanation=(
                    "Malware reputation could not be verified because no external threat-intelligence "
                    "provider is configured or reachable. This does not mean the URL is safe."
                ),
                recommendation="Exercise caution and do not download files from unverified links.",
                score_contribution=0,
                detection_status="Check unavailable",
                detection_source="provider",
            )
        )
        domain_summary = {
            "provider_name": intel.provider_name,
            "reputation_status": "Check unavailable",
            "domain_age_status": "Check unavailable",
            "domain_age_days": None,
            "confidence": None,
            "checked_at": intel.checked_at,
            "cached": intel.cached,
            "provider_results": serialized_records,
            "note": reason,
        }
        return findings, domain_summary

    if intel.is_malware:
        findings.append(
            RuleFinding(
                rule_id="malware_reputation_match",
                rule_name="Known Malware Reputation Match",
                category="malware",
                severity="critical",
                evidence=f"Confirmed malware match reported by {intel.provider_name}.",
                explanation=(
                    "An external threat-intelligence provider flagged this URL or domain as "
                    "associated with malware distribution."
                ),
                recommendation="Do not visit this link or download any files from it.",
                score_contribution=weights.confirmed_malware_reputation,
                detection_status="Detected",
                detection_source="provider",
            )
        )
    else:
        findings.append(
            RuleFinding(
                rule_id="malware_reputation_clean",
                rule_name="Malware Reputation Check",
                category="malware",
                severity="info",
                evidence=f"No malware match reported by {intel.provider_name}.",
                explanation=(
                    "No known malware match was reported by the configured provider. "
                    "No match does not guarantee the site is safe."
                ),
                recommendation="Continue verifying unfamiliar links before interacting.",
                score_contribution=0,
                detection_status="Not detected",
                detection_source="provider",
            )
        )

    if intel.is_phishing:
        findings.append(
            RuleFinding(
                rule_id="phishing_reputation_match",
                rule_name="Confirmed Phishing Reputation Match",
                category="phishing",
                severity="critical",
                evidence=f"Confirmed phishing match reported by {intel.provider_name}.",
                explanation="The configured threat-intelligence provider flagged this URL as phishing.",
                recommendation="Do not open this link or enter any credentials.",
                score_contribution=weights.confirmed_phishing_reputation,
                detection_status="Detected",
                dedup_group="provider_reputation",
                detection_source="provider",
            )
        )

    if intel.is_malicious_domain and not intel.is_phishing:
        findings.append(
            RuleFinding(
                rule_id="malicious_domain_reputation",
                rule_name="Confirmed Malicious Domain Reputation",
                category="domain_intel",
                severity="critical",
                evidence=f"Domain '{hostname}' flagged as malicious by {intel.provider_name}.",
                explanation="The configured domain-reputation provider flagged this domain as malicious.",
                recommendation="Avoid interacting with this domain.",
                score_contribution=weights.confirmed_phishing_reputation,
                detection_status="Detected",
                dedup_group="provider_reputation",
                detection_source="provider",
            )
        )

    domain_age_status = "Check unavailable"
    if not is_ip and intel.domain_age_days is not None:
        if intel.domain_age_days < 30:
            domain_age_status = f"Newly registered ({intel.domain_age_days} days)"
            findings.append(
                RuleFinding(
                    rule_id="domain_age_new",
                    rule_name="Newly Registered Domain",
                    category="domain_intel",
                    severity="info",
                    evidence=f"Domain age: {intel.domain_age_days} days.",
                    explanation=(
                        "This domain appears recently registered. New domains are not automatically "
                        "malicious, though they warrant extra verification."
                    ),
                    recommendation="Verify the organization's identity through official channels.",
                    score_contribution=weights.domain_age_info,
                    detection_status="Informational",
                    detection_source="provider",
                )
            )
        else:
            domain_age_status = f"Established ({intel.domain_age_days} days)"

    rep_status = (
        "Detected"
        if (intel.is_malware or intel.is_phishing or intel.is_malicious_domain)
        else "Not detected"
    )
    domain_summary = {
        "provider_name": intel.provider_name,
        "reputation_status": rep_status,
        "domain_age_status": domain_age_status,
        "domain_age_days": intel.domain_age_days,
        "confidence": intel.confidence,
        "checked_at": intel.checked_at,
        "cached": intel.cached,
        "provider_results": serialized_records,
        "note": (
            "No match returned by configured provider(s); this does not guarantee safety."
            if rep_status == "Not detected"
            else None
        ),
    }
    return findings, domain_summary
