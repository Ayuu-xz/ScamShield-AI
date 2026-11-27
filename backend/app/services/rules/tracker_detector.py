"""Website tracker indicator module (URL-text and read-only HTML/cookie inspection)."""

from __future__ import annotations

from urllib.parse import parse_qs, urljoin, urlsplit

from app.services.indicators import RuleFinding
from app.services.website_inspector import PageObservation

KNOWN_TRACKING_DOMAINS: frozenset[str] = frozenset(
    {
        "google-analytics.com",
        "www.google-analytics.com",
        "googletagmanager.com",
        "www.googletagmanager.com",
        "doubleclick.net",
        "connect.facebook.net",
        "www.facebook.com",
        "analytics.tiktok.com",
        "mixpanel.com",
        "api.mixpanel.com",
        "segment.io",
        "api.segment.io",
        "hotjar.com",
        "static.hotjar.com",
        "clarity.ms",
    }
)

TRACKER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("google-analytics.com", "Google Analytics", "Analytics"),
    ("gtag/js", "Google Analytics (gtag.js)", "Analytics"),
    ("googletagmanager.com", "Google Tag Manager", "Tag Manager"),
    ("connect.facebook.net", "Meta Pixel", "Advertising Tracker"),
    ("fbevents.js", "Meta Pixel", "Advertising Tracker"),
    ("facebook.com/tr", "Meta Pixel", "Advertising Tracker"),
    ("doubleclick.net", "Google DoubleClick", "Advertising Tracker"),
    ("analytics.tiktok.com", "TikTok Pixel", "Advertising Tracker"),
    ("static.hotjar.com", "Hotjar", "Session Analytics"),
    ("clarity.ms", "Microsoft Clarity", "Session Analytics"),
    ("mixpanel.com", "Mixpanel", "Product Analytics"),
    ("segment.io", "Segment", "Customer Data Platform"),
)

ANALYTICS_COOKIES: dict[str, str] = {
    "_ga": "Google Analytics",
    "_gid": "Google Analytics",
    "_gat": "Google Analytics",
    "_fbp": "Meta Pixel",
    "_fbc": "Meta Pixel",
    "_gcl_au": "Google Ads Conversion",
    "_hjsession": "Hotjar",
    "ajs_anonymous_id": "Segment",
}

TRACKING_QUERY_PARAMS: frozenset[str] = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "utm_id",
        "fbclid",
        "gclid",
        "dclid",
        "msclkid",
        "mc_cid",
        "mc_eid",
        "_ga",
        "_gl",
        "igshid",
    }
)


def detect_tracker_indicators(hostname: str, query: str) -> list[RuleFinding]:
    """Identify URL-based tracking domains and query parameters (informational, 0 pts)."""
    findings: list[RuleFinding] = []

    if hostname in KNOWN_TRACKING_DOMAINS or any(
        hostname.endswith(f".{domain}") for domain in KNOWN_TRACKING_DOMAINS
    ):
        findings.append(
            RuleFinding(
                rule_id="tracker_domain_url",
                rule_name="Known Analytics or Advertising Domain",
                category="tracker",
                severity="info",
                evidence=f"URL hostname '{hostname}' matches a known analytics/tracking domain.",
                explanation=(
                    "The URL points to a known analytics or advertising domain. Tracking alone "
                    "is not malicious."
                ),
                recommendation="Be aware that tracking domains may log referral or campaign metadata.",
                score_contribution=0,
                detection_status="Informational",
                detection_source="url",
                tracker_domain=hostname,
                confidence="high",
            )
        )

    parsed_qs = parse_qs(query, keep_blank_values=True)
    matched_params = sorted(
        key for key in parsed_qs.keys() if key.lower() in TRACKING_QUERY_PARAMS
    )
    if matched_params:
        findings.append(
            RuleFinding(
                rule_id="tracker_query_params_url",
                rule_name="Tracking Query Parameters",
                category="tracker",
                severity="info",
                evidence=f"Parameters: {', '.join(matched_params)}",
                explanation=(
                    "Common marketing or analytics tracking parameters were found in the URL query. "
                    "These are ordinary tracking identifiers and do not indicate phishing or malware."
                ),
                recommendation="You may remove tracking parameters before sharing links for privacy.",
                score_contribution=0,
                detection_status="Informational",
                detection_source="url",
                tracker_domain=hostname,
                confidence="high",
            )
        )

    return findings


def detect_page_tracker_indicators(observation: PageObservation) -> list[RuleFinding]:
    """Identify actual trackers from safely inspected HTML scripts, pixels, and cookies."""
    findings: list[RuleFinding] = []
    seen_trackers: set[tuple[str, str]] = set()

    # 1. Script src tags
    for raw_src in observation.script_srcs:
        full_src = urljoin(observation.final_url, raw_src)
        src_host = (urlsplit(full_src).hostname or "").lower()
        lower_src = full_src.lower()
        for pattern, tracker_name, _cat in TRACKER_SIGNATURES:
            if pattern in lower_src and (tracker_name, "html_script") not in seen_trackers:
                seen_trackers.add((tracker_name, "html_script"))
                findings.append(
                    RuleFinding(
                        rule_id=f"tracker_script_{tracker_name.lower().replace(' ', '_')}",
                        rule_name=f"{tracker_name} (Script)",
                        category="tracker",
                        severity="info",
                        evidence=f"<script src=\"{full_src[:120]}\">",
                        explanation=(
                            f"Detected {tracker_name} script reference in the page HTML. "
                            "Analytics trackers are common on legitimate sites and do not increase phishing risk."
                        ),
                        recommendation="Informational only; no action required unless other risks exist.",
                        score_contribution=0,
                        detection_status="Informational",
                        detection_source="html_script",
                        tracker_domain=src_host or observation.final_hostname,
                        confidence="high",
                    )
                )

    # 2. Inline script snippets
    for snippet in observation.inline_script_snippets:
        lower_snip = snippet.lower()
        if ("gtag(" in lower_snip or "google-analytics" in lower_snip) and (
            "Google Analytics",
            "html_script",
        ) not in seen_trackers:
            seen_trackers.add(("Google Analytics", "html_script"))
            findings.append(
                RuleFinding(
                    rule_id="tracker_inline_ga",
                    rule_name="Google Analytics (Inline Script)",
                    category="tracker",
                    severity="info",
                    evidence="Inline script references gtag() or google-analytics.",
                    explanation="Detected Google Analytics initialization in inline HTML script.",
                    recommendation="Informational only; analytics trackers are not automatically malicious.",
                    score_contribution=0,
                    detection_status="Informational",
                    detection_source="html_script",
                    tracker_domain=observation.final_hostname,
                    confidence="medium",
                )
            )
        if ("fbq(" in lower_snip or "fbevents.js" in lower_snip) and (
            "Meta Pixel",
            "html_script",
        ) not in seen_trackers:
            seen_trackers.add(("Meta Pixel", "html_script"))
            findings.append(
                RuleFinding(
                    rule_id="tracker_inline_meta",
                    rule_name="Meta Pixel (Inline Script)",
                    category="tracker",
                    severity="info",
                    evidence="Inline script references fbq() or fbevents.js.",
                    explanation="Detected Meta Pixel initialization in inline HTML script.",
                    recommendation="Informational only; advertising pixels are not automatically malicious.",
                    score_contribution=0,
                    detection_status="Informational",
                    detection_source="html_script",
                    tracker_domain=observation.final_hostname,
                    confidence="medium",
                )
            )

    # 3. Tracking pixels (<img src="...">)
    for raw_img in observation.img_srcs:
        full_img = urljoin(observation.final_url, raw_img)
        img_host = (urlsplit(full_img).hostname or "").lower()
        lower_img = full_img.lower()
        for pattern, tracker_name, _cat in TRACKER_SIGNATURES:
            if pattern in lower_img and (tracker_name, "tracking_pixel") not in seen_trackers:
                seen_trackers.add((tracker_name, "tracking_pixel"))
                findings.append(
                    RuleFinding(
                        rule_id=f"tracker_pixel_{tracker_name.lower().replace(' ', '_')}",
                        rule_name=f"{tracker_name} (Tracking Pixel)",
                        category="tracker",
                        severity="info",
                        evidence=f"<img src=\"{full_img[:120]}\">",
                        explanation=f"Detected {tracker_name} tracking pixel in page HTML.",
                        recommendation="Informational only; tracking pixels log page visits.",
                        score_contribution=0,
                        detection_status="Informational",
                        detection_source="tracking_pixel",
                        tracker_domain=img_host or observation.final_hostname,
                        confidence="high",
                    )
                )

    # 4. Analytics cookies (Set-Cookie headers)
    for cookie_name in observation.set_cookie_names:
        lower_cookie = cookie_name.lower()
        for prefix, tracker_name in ANALYTICS_COOKIES.items():
            if lower_cookie.startswith(prefix) and (tracker_name, "cookie") not in seen_trackers:
                seen_trackers.add((tracker_name, "cookie"))
                findings.append(
                    RuleFinding(
                        rule_id=f"tracker_cookie_{lower_cookie}",
                        rule_name=f"{tracker_name} (Cookie: {cookie_name})",
                        category="tracker",
                        severity="info",
                        evidence=f"Set-Cookie header sets '{cookie_name}'.",
                        explanation=f"Detected analytics cookie '{cookie_name}' in HTTP response headers.",
                        recommendation="Informational only; analytics cookies measure site usage.",
                        score_contribution=0,
                        detection_status="Informational",
                        detection_source="cookie",
                        tracker_domain=observation.final_hostname,
                        confidence="high",
                    )
                )

    return findings
