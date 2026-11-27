"""Automated tests for multi-provider Threat Intelligence, caching, and error handling."""

import httpx

from app.core.config import ThreatIntelConfig
from app.services.message_analyzer import analyze_message_urls
from app.services.risk_scorer import score_indicators
from app.services.rules.threat_intel_service import (
    clear_threat_intel_cache,
    evaluate_threat_and_domain_intel,
)
from app.services.url_analyzer import analyze_url_full


def test_google_safe_browsing_known_malicious_and_caching(monkeypatch) -> None:
    """1 & 9. GSB phishing/malware match increases risk and caches subsequent lookups."""
    clear_threat_intel_cache()
    call_count = 0

    def _mock_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            200,
            request=httpx.Request("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find"),
            json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]},
        )

    monkeypatch.setattr("httpx.post", _mock_post)
    cfg = ThreatIntelConfig(google_safe_browsing_api_key="test-key-secret-value")

    findings1, dom1 = evaluate_threat_and_domain_intel(
        normalized_url="https://testsafebrowsing.appspot.com/s/phishing.html",
        hostname="testsafebrowsing.appspot.com",
        is_ip=False,
        config=cfg,
    )
    assert call_count == 1
    assert dom1["reputation_status"] == "Detected"
    assert dom1["cached"] is False
    assert dom1["provider_results"][0]["lookup_status"] == "Detected"
    assert score_indicators(findings1, domain_intelligence=dom1).risk_score == 50

    # Second lookup hits TTL cache without another HTTP call
    findings2, dom2 = evaluate_threat_and_domain_intel(
        normalized_url="https://testsafebrowsing.appspot.com/s/phishing.html",
        hostname="testsafebrowsing.appspot.com",
        is_ip=False,
        config=cfg,
    )
    assert call_count == 1
    assert dom2["cached"] is True
    assert dom2["provider_results"][0]["cached"] is True


def test_clean_provider_result_never_claims_safe(monkeypatch) -> None:
    """2. Clean provider response returns Not detected and notes safety is not guaranteed."""
    clear_threat_intel_cache()
    monkeypatch.setattr(
        "httpx.post",
        lambda *a, **kw: httpx.Response(
            200,
            request=httpx.Request("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find"),
            json={},
        ),
    )
    cfg = ThreatIntelConfig(google_safe_browsing_api_key="test-key")
    findings, dom = evaluate_threat_and_domain_intel(
        normalized_url="https://example.com/clean",
        hostname="example.com",
        is_ip=False,
        config=cfg,
    )
    assert dom["reputation_status"] == "Not detected"
    assert "does not guarantee safety" in (dom["note"] or "").lower()
    assert score_indicators(findings, domain_intelligence=dom).risk_level != "Safe"


def test_provider_timeout_invalid_creds_and_rate_limit(monkeypatch) -> None:
    """4, 5, 6. Timeouts, 403 invalid creds, and 429 rate limits return Check unavailable without leaking keys."""
    clear_threat_intel_cache()
    secret_key = "SUPER_SECRET_GSB_KEY_123"
    cfg = ThreatIntelConfig(google_safe_browsing_api_key=secret_key)

    def _timeout(*a, **kw):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr("httpx.post", _timeout)
    _, dom_to = evaluate_threat_and_domain_intel(
        normalized_url="https://example.com/to",
        hostname="example.com",
        is_ip=False,
        config=cfg,
    )
    assert dom_to["reputation_status"] == "Check unavailable"
    assert dom_to["provider_results"][0]["lookup_status"] == "Timeout"
    assert secret_key not in str(dom_to)

    monkeypatch.setattr(
        "httpx.post",
        lambda *a, **kw: httpx.Response(
            403,
            request=httpx.Request("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find"),
        ),
    )
    _, dom_auth = evaluate_threat_and_domain_intel(
        normalized_url="https://example.com/auth",
        hostname="example.com",
        is_ip=False,
        config=cfg,
    )
    assert dom_auth["reputation_status"] == "Check unavailable"
    assert dom_auth["provider_results"][0]["lookup_status"] == "Invalid credentials"
    assert secret_key not in str(dom_auth)

    monkeypatch.setattr(
        "httpx.post",
        lambda *a, **kw: httpx.Response(
            429,
            request=httpx.Request("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find"),
        ),
    )
    _, dom_rl = evaluate_threat_and_domain_intel(
        normalized_url="https://example.com/rl",
        hostname="example.com",
        is_ip=False,
        config=cfg,
    )
    assert dom_rl["reputation_status"] == "Check unavailable"
    assert dom_rl["provider_results"][0]["lookup_status"] == "Rate limited"


def test_conflicting_providers_and_duplicate_evidence_prevention(monkeypatch) -> None:
    """7 & 8. Conflicting providers resolve to Detected, and duplicate phishing matches do not double-count."""
    clear_threat_intel_cache()

    def _mock_multi(url, *args, **kwargs):
        if "safebrowsing" in url:
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={},  # GSB says no match
            )
        if "urlhaus" in url:
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"query_status": "ok", "threat": "malware_download"},
            )
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={"is_phishing": True, "is_malicious_domain": True},
        )

    monkeypatch.setattr("httpx.post", _mock_multi)
    cfg = ThreatIntelConfig(
        google_safe_browsing_api_key="gsb-key",
        urlhaus_enabled=True,
        provider_name="custom-ti",
        endpoint_url="https://intel.example.internal/check",
        api_key="custom-key",
    )
    findings, dom = evaluate_threat_and_domain_intel(
        normalized_url="https://conflict-test.example.com/bad",
        hostname="conflict-test.example.com",
        is_ip=False,
        config=cfg,
    )
    assert dom["reputation_status"] == "Detected"
    assert len(dom["provider_results"]) == 3
    assessment = score_indicators(findings, domain_intelligence=dom)
    assert assessment.risk_score == 100  # +50 malware + +50 phishing (not +150)
    assert assessment.risk_level == "Dangerous"


def test_message_with_multiple_urls_uses_threat_intel() -> None:
    """10. Message with multiple URLs checks each via centralized engine without crashing when unconfigured."""
    res = analyze_message_urls(
        "Check https://example.com/a and http://paypa1-secure-login.com/verify"
    )
    assert len(res.url_results) == 2
    assert res.reputation_status == "Check unavailable"
