"""Phishing element detection module (URL-text and read-only HTML inspection)."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from app.core.config import UrlScoringWeights, settings
from app.services.indicators import RuleFinding
from app.services.rules.tracker_detector import KNOWN_TRACKING_DOMAINS
from app.services.website_inspector import PageObservation

TARGETED_BRANDS: tuple[str, ...] = (
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "chase",
    "bankofamerica",
    "wellsfargo",
    "coinbase",
    "binance",
    "dropbox",
    "linkedin",
)

_CREDENTIAL_KEYWORDS_RE = re.compile(
    r"(?:^|[/\-_.=?&])(login|signin|sign-in|log-in|verify|verification|kyc|password|passwd|"
    r"credential|webscr|banking|wallet-connect|recover-account|unlock-account)(?:$|[/\-_.=?&])",
    re.IGNORECASE,
)


def _normalize_homoglyphs(text: str) -> str:
    """Normalize common leetspeak/look-alike substitutions for brand comparison."""
    return (
        text.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("rn", "m")
        .replace("vv", "w")
    )


def _registered_domain(hostname: str) -> str:
    """Return approximate registered domain (last two labels) for comparison."""
    labels = [lbl for lbl in hostname.split(".") if lbl]
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname


def has_lookalike_domain(hostname: str) -> tuple[bool, str]:
    """Detect punycode, non-ASCII host characters, or brand impersonation patterns."""
    if "xn--" in hostname or any(ord(ch) > 127 for ch in hostname):
        return True, f"Hostname '{hostname}' contains punycode (xn--) or non-ASCII characters."

    labels = [lbl for lbl in hostname.split(".") if lbl]
    if len(labels) < 2:
        return False, ""

    reg_domain = ".".join(labels[-2:])
    subdomain_and_sld = ".".join(labels[:-1])
    normalized_host = _normalize_homoglyphs(subdomain_and_sld)

    for brand in TARGETED_BRANDS:
        if reg_domain == f"{brand}.com":
            continue

        for label in labels[:-1]:
            norm_label = _normalize_homoglyphs(label)
            if brand in norm_label and brand not in label:
                return True, f"Label '{label}' mimics '{brand}' using look-alike characters."

        if brand in subdomain_and_sld or brand in normalized_host:
            return True, f"Domain '{hostname}' embeds brand name '{brand}' outside '{brand}.com'."

    return False, ""


def detect_phishing_indicators(
    *,
    hostname: str,
    path: str,
    query: str,
    is_ip: bool,
    is_shortener: bool,
    weights: UrlScoringWeights = settings.url_weights,
) -> list[RuleFinding]:
    """Detect URL-text brand impersonation and credential-related URL patterns."""
    findings: list[RuleFinding] = []

    if not is_ip and not is_shortener and hostname not in KNOWN_TRACKING_DOMAINS:
        is_lookalike, evidence = has_lookalike_domain(hostname)
        if is_lookalike:
            findings.append(
                RuleFinding(
                    rule_id="lookalike_domain",
                    rule_name="Look-Alike or Brand-Impersonation Domain",
                    category="phishing",
                    severity="high",
                    evidence=evidence,
                    explanation=(
                        "The domain uses punycode, look-alike characters, or brand-impersonation "
                        "patterns that may imitate a trusted organization."
                    ),
                    recommendation=(
                        "Do not log in through this link; navigate directly to the official website."
                    ),
                    score_contribution=weights.brand_impersonation,
                    detection_status="Detected",
                    dedup_group="brand_impersonation",
                )
            )

    combined_target = f"{hostname}{path}?{query}" if query else f"{hostname}{path}"
    cred_matches = sorted({m.group(1).lower() for m in _CREDENTIAL_KEYWORDS_RE.finditer(combined_target)})
    if cred_matches:
        findings.append(
            RuleFinding(
                rule_id="credential_url_pattern",
                rule_name="Credential or Verification URL Pattern",
                category="phishing",
                severity="low",
                evidence=f"Matched URL terms: {', '.join(cred_matches)}",
                explanation=(
                    "The URL contains login, password, KYC, or verification keywords. While legitimate "
                    "sites also have login pages, combined with other signals this can indicate credential harvesting."
                ),
                recommendation="Verify the exact domain name before entering any password, OTP, or KYC details.",
                score_contribution=weights.credential_url_pattern,
                detection_status="Detected",
                dedup_group="credential_pattern",
            )
        )

    return findings


def detect_page_phishing_indicators(
    *,
    observation: PageObservation,
    initial_hostname: str,
    weights: UrlScoringWeights = settings.url_weights,
) -> list[RuleFinding]:
    """Inspect safely parsed HTML observations for phishing & credential harvesting."""
    findings: list[RuleFinding] = []
    final_reg_domain = _registered_domain(observation.final_hostname)

    # 1. Deceptive cross-domain redirect chain (+20)
    if observation.redirect_chain:
        initial_reg = _registered_domain(initial_hostname)
        if final_reg_domain != initial_reg:
            findings.append(
                RuleFinding(
                    rule_id="deceptive_redirect_chain",
                    rule_name="Deceptive Cross-Domain Redirect Behaviour",
                    category="redirect",
                    severity="medium",
                    evidence=(
                        f"Redirected from '{initial_hostname}' to '{observation.final_hostname}' "
                        f"({len(observation.redirect_chain)} hop(s))."
                    ),
                    explanation=(
                        "The URL redirected to a different domain than the initial link, which can "
                        "conceal the true destination."
                    ),
                    recommendation="Verify that you intended to visit the final destination domain.",
                    score_contribution=weights.deceptive_redirect,
                    detection_status="Detected",
                    dedup_group="redirect_pattern",
                    detection_source="html_page",
                )
            )

    # 2. Brand impersonation in page title/body vs domain (+30)
    page_text_lower = f"{observation.title} {observation.text_snippet}".lower()
    mismatched_brands: list[str] = []
    for brand in TARGETED_BRANDS:
        if re.search(rf"\b{re.escape(brand)}\b", page_text_lower) and final_reg_domain != f"{brand}.com":
            mismatched_brands.append(brand)

    if mismatched_brands:
        findings.append(
            RuleFinding(
                rule_id="page_brand_impersonation",
                rule_name="Mismatched Page Identity / Brand Impersonation",
                category="phishing",
                severity="high",
                evidence=(
                    f"Page title/content references {', '.join(mismatched_brands[:3])} "
                    f"on domain '{observation.final_hostname}'."
                ),
                explanation=(
                    "The page content references a well-known brand while hosted on an unrelated "
                    "domain, a common phishing indicator."
                ),
                recommendation="Do not enter credentials; visit the official brand website directly.",
                score_contribution=weights.brand_impersonation,
                detection_status="Detected",
                dedup_group="brand_impersonation",
                detection_source="html_page",
            )
        )

    # 3. Suspicious form destinations & strong credential harvesting
    cross_domain_forms: list[str] = []
    has_cred_form = False
    has_otp_or_pw = False

    for form in observation.forms:
        if form.has_password_input or form.has_otp_input:
            has_cred_form = True
            has_otp_or_pw = True
        if form.action:
            resolved_action = urljoin(observation.final_url, form.action)
            action_host = (urlsplit(resolved_action).hostname or "").lower()
            if action_host and _registered_domain(action_host) != final_reg_domain:
                cross_domain_forms.append(f"{form.method} -> {action_host}")

    if cross_domain_forms:
        findings.append(
            RuleFinding(
                rule_id="suspicious_form_destination",
                rule_name="Suspicious External Form Destination",
                category="phishing",
                severity="high",
                evidence=f"Form submits to external domain(s): {', '.join(cross_domain_forms[:2])}",
                explanation=(
                    "An HTML form on this page submits data to an unrelated external domain, "
                    "which is a strong indicator of credential harvesting."
                ),
                recommendation="Never submit passwords or personal details to forms targeting external domains.",
                score_contribution=weights.suspicious_form_destination,
                detection_status="Detected",
                detection_source="html_page",
            )
        )

    # A login form alone does not confirm phishing; require additional risk context
    # (mismatched brand, cross-domain form, or OTP + password collection).
    if has_cred_form and (mismatched_brands or cross_domain_forms or has_otp_or_pw and len(observation.forms) > 0 and observation.redirect_chain):
        findings.append(
            RuleFinding(
                rule_id="strong_credential_harvesting",
                rule_name="Strong Credential Harvesting Evidence",
                category="phishing",
                severity="critical",
                evidence=(
                    "Page collects password/OTP inputs alongside mismatched brand identity "
                    "or cross-domain form submission."
                ),
                explanation=(
                    "The inspected page combines password or OTP input fields with identity "
                    "mismatch or suspicious form routing—strong evidence of credential harvesting."
                ),
                recommendation="Close this page and do not submit any login, OTP, or banking information.",
                score_contribution=weights.strong_credential_harvesting,
                detection_status="Detected",
                dedup_group="credential_pattern",
                detection_source="html_page",
            )
        )

    return findings
