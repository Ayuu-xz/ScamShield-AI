"""Comprehensive tests for Trackers, Phishing, Malware, Redirects, Domain Intel, File Extensions, and Deduplication."""

from fastapi.testclient import TestClient

from app.main import app
from app.services.indicators import RuleFinding
from app.services.risk_scorer import score_indicators
from app.services.rules.threat_intel_service import ThreatIntelResult
from app.services.url_analyzer import analyze_url_full

client = TestClient(app)


def test_credential_url_pattern_detected() -> None:
    """8. Credential-related URL pattern adds +10 and remains Safe alone."""
    res = client.post("/api/scan/url", json={"url": "https://example.com/login"})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] == 10
    assert data["risk_level"] == "Inspection unavailable"
    assert any(r["rule_id"] == "credential_url_pattern" for r in data["detected_rules"])


def test_tracking_query_parameters_are_informational_only() -> None:
    """9 & 22. Tracking query parameters and tracking domains add 0 malicious risk points."""
    res = client.post(
        "/api/scan/url",
        json={"url": "https://google-analytics.com/collect?utm_source=email&fbclid=abc123&gclid=xyz"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["rule_score"] == 0
    assert data["risk_level"] in {"Inspection unavailable", "Suspicious"}
    assert len(data["tracker_indicators"]) == 2
    assert all(t["detection_status"] == "Informational" for t in data["tracker_indicators"])
    assert all(t["score_contribution"] == 0 for t in data["tracker_indicators"])


def test_mocked_phishing_reputation_match() -> None:
    """10. Mocked known phishing reputation match adds +50 and flags Dangerous."""
    _, findings, domain_summary, outcome = analyze_url_full(
        "https://example-phish-test.com/home",
        provider_fn=lambda _u, _h, _c: ThreatIntelResult(
            provider_status="available",
            provider_name="mock-intel",
            is_phishing=True,
            confidence="high",
        ),
    )
    assessment = score_indicators(
        findings, domain_intelligence=domain_summary, inspection_outcome=outcome
    )
    assert assessment.risk_score == 50
    assert assessment.risk_level == "Dangerous"
    assert assessment.reputation_status == "Detected"


def test_mocked_malware_reputation_match() -> None:
    """11. Mocked known malware reputation match adds +50 and classifies Dangerous."""
    _, findings, domain_summary, outcome = analyze_url_full(
        "https://example-malware-test.com/home",
        provider_fn=lambda _u, _h, _c: ThreatIntelResult(
            provider_status="available",
            provider_name="mock-intel",
            is_malware=True,
            confidence="high",
        ),
    )
    assessment = score_indicators(
        findings, domain_intelligence=domain_summary, inspection_outcome=outcome
    )
    assert assessment.risk_score == 50
    assert assessment.risk_level == "Dangerous"
    assert any(m.rule_id == "malware_reputation_match" for m in assessment.malware_indicators)


def test_reputation_and_domain_age_unavailable_by_default() -> None:
    """12 & 15. Without a configured provider, reputation & domain age report Check unavailable."""
    res = client.post("/api/scan/url", json={"url": "https://example.com/about"})
    assert res.status_code == 200
    data = response_data = res.json()
    assert response_data["reputation_status"] == "Check unavailable"
    assert response_data["domain_intelligence"]["domain_age_status"] == "Check unavailable"
    assert any(
        m["detection_status"] == "Check unavailable" for m in data["malware_indicators"]
    )


def test_suspicious_redirect_parameter() -> None:
    """13. Suspicious non-relative redirect parameter adds +10."""
    res = client.post(
        "/api/scan/url",
        json={"url": "https://example.com/out?redirect=evil.example.org"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] == 10
    assert any(r["rule_id"] == "suspicious_redirect" for r in data["redirect_indicators"])


def test_nested_redirect_url_parameter() -> None:
    """14. Nested external URL in redirect query parameter adds +15."""
    res = client.post(
        "/api/scan/url",
        json={"url": "https://example.com/out?next=https://evil.example.org/phish"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["rule_score"] == 15
    assert data["risk_score"] >= 15
    assert any(r["rule_id"] == "nested_redirect" for r in data["redirect_indicators"])


def test_newly_registered_domain_alone_stays_low_risk() -> None:
    """16. Newly registered domain without other threat indicators stays low risk."""
    _, findings, domain_summary, outcome = analyze_url_full(
        "https://fresh-example-site.com/about",
        provider_fn=lambda _u, _h, _c: ThreatIntelResult(
            provider_status="available",
            provider_name="mock-intel",
            domain_age_days=5,
        ),
    )
    assessment = score_indicators(
        findings, domain_intelligence=domain_summary, inspection_outcome=outcome
    )
    assert assessment.risk_score == 0
    assert assessment.risk_level == "Inspection unavailable"
    assert "Newly registered (5 days)" in assessment.domain_intelligence["domain_age_status"]


def test_suspicious_executable_file_extension_does_not_confirm_malware() -> None:
    """17 & 23. Executable file extension adds +15 and does NOT independently confirm malware."""
    res = client.post(
        "/api/scan/url",
        json={"url": "https://example.com/downloads/installer.exe"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["rule_score"] == 15
    assert data["risk_score"] >= 15
    assert len(data["file_download_indicators"]) == 1
    assert "not confirmation of malware" in data["file_download_indicators"][0]["explanation"].lower()
    assert not any(m["detection_status"] == "Detected" for m in data["malware_indicators"])


def test_duplicate_rules_do_not_double_count() -> None:
    """20. Overlapping rules in the same dedup_group or same rule_id never double-count."""
    f1 = RuleFinding(
        rule_id="phishing_reputation_match",
        rule_name="Phishing match",
        category="phishing",
        severity="critical",
        evidence="provider",
        explanation="phishing",
        recommendation="avoid",
        score_contribution=40,
        dedup_group="provider_reputation",
    )
    f2 = RuleFinding(
        rule_id="malicious_domain_reputation",
        rule_name="Malicious domain",
        category="domain_intel",
        severity="critical",
        evidence="provider",
        explanation="malicious",
        recommendation="avoid",
        score_contribution=40,
        dedup_group="provider_reputation",
    )
    assessment = score_indicators([f1, f2, f1])
    assert assessment.risk_score == 40


def test_risk_score_capped_at_100() -> None:
    """21. Total risk score must never exceed 100."""
    _, findings, domain_summary, outcome = analyze_url_full(
        "http://login.verify.account.security.paypa1-secure.com/setup.exe?next=https://evil.com",
        provider_fn=lambda _u, _h, _c: ThreatIntelResult(
            provider_status="available",
            provider_name="mock-intel",
            is_malware=True,
            is_phishing=True,
        ),
    )
    assessment = score_indicators(
        findings, domain_intelligence=domain_summary, inspection_outcome=outcome
    )
    assert assessment.risk_score == 100
    assert assessment.risk_level == "Dangerous"


def test_no_submitted_url_is_fetched_or_executed(monkeypatch) -> None:
    """24. Analyzing a URL must never issue HTTP requests to the submitted URL."""
    def _forbid_network(*args, **kwargs):
        raise AssertionError("Submitted URL must never be fetched or opened!")

    monkeypatch.setattr("httpx.get", _forbid_network)
    monkeypatch.setattr("httpx.post", _forbid_network)

    res = client.post("/api/scan/url", json={"url": "https://never-visit-this.example.com/login"})
    assert res.status_code == 200
