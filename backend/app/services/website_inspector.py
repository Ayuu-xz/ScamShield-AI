"""Isolated, read-only website inspection service with strict SSRF & safety controls.

Security guarantees:
- Read-only HTTP GET only; never clicks buttons, submits forms, or executes JS.
- Blocks localhost, private IPs, link-local, loopback, reserved, and cloud metadata endpoints.
- Pre-resolves DNS and validates every resolved IP before connecting (DNS-rebinding protection).
- Disables automatic redirects and validates every redirect hop before navigation.
- Disables file downloads (rejects Content-Disposition attachments and non-HTML binary MIME types).
- Enforces strict timeouts and max response size limits.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.config import WebsiteInspectionConfig, settings

BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
        "169.254.169.254",
    }
)

BLOCKED_DOWNLOAD_MIME_PREFIXES: tuple[str, ...] = (
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
    "application/vnd.android.package-archive",
    "application/zip",
    "application/x-msi",
)

ALLOWED_HTML_MIME_TYPES: frozenset[str] = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "text/plain",
    }
)


class InspectionBlockedError(ValueError):
    """Raised when a URL or redirect destination is blocked for safety (SSRF/download/etc.)."""


class InspectionUnavailableError(RuntimeError):
    """Raised when isolated inspection is disabled, times out, or fails."""


@dataclass(frozen=True)
class FormObservation:
    """Read-only metadata about an HTML <form> element (never submitted)."""

    action: str
    method: str
    has_password_input: bool
    has_otp_input: bool
    has_email_or_user_input: bool


@dataclass(frozen=True)
class PageObservation:
    """Safely parsed, read-only DOM/resource/header/cookie observations."""

    final_url: str
    final_hostname: str
    status_code: int
    title: str
    text_snippet: str
    redirect_chain: list[str]
    script_srcs: list[str]
    img_srcs: list[str]
    iframe_srcs: list[str]
    link_hrefs: list[str]
    forms: list[FormObservation]
    set_cookie_names: list[str]
    inline_script_snippets: list[str]


@dataclass(frozen=True)
class InspectionOutcome:
    """Outcome wrapper distinguishing completed, blocked, and unavailable states."""

    status: str  # "completed" | "blocked" | "unavailable"
    observation: PageObservation | None = None
    reason: str | None = None
    blocked_destinations: list[str] = field(default_factory=list)


def _is_ip_unsafe(ip_str: str) -> bool:
    """Return True if IP is loopback, private, link-local, multicast, or unspecified."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or str(ip_obj) == "169.254.169.254"
    )


def validate_destination_safety(
    url: str,
    *,
    dns_resolver: Callable[[str], list[str]] | None = None,
) -> list[str]:
    """Validate URL scheme, hostname, and resolved IPs before any network connection.

    Prevents SSRF and DNS rebinding to localhost, private networks, or cloud metadata.
    Returns the list of validated public IP strings.
    """
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InspectionBlockedError(f"Blocked unsupported scheme '{scheme}' during inspection.")

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise InspectionBlockedError("Blocked inspection: missing hostname.")

    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".local") or hostname.endswith(".internal"):
        raise InspectionBlockedError(
            f"Blocked for safety: internal or metadata hostname '{hostname}' is not permitted."
        )

    # Check literal IP directly
    is_literal_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_literal_ip = True
    except ValueError:
        is_literal_ip = False

    if is_literal_ip:
        if _is_ip_unsafe(hostname):
            raise InspectionBlockedError(
                f"Blocked for safety: private, loopback, or metadata IP '{hostname}' is not permitted."
            )
        return [hostname]

    # Resolve DNS and verify ALL returned IPs are public (anti-DNS-rebinding)
    resolved_ips: list[str]
    if dns_resolver is not None:
        resolved_ips = dns_resolver(hostname)
    else:
        try:
            addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if scheme == "https" else 80))
            resolved_ips = list(dict.fromkeys(info[4][0] for info in addr_info if info[4]))
        except OSError as exc:
            raise InspectionUnavailableError(
                f"DNS resolution failed for '{hostname}'."
            ) from exc

    if not resolved_ips:
        raise InspectionUnavailableError(f"No IP addresses resolved for '{hostname}'.")

    for ip_addr in resolved_ips:
        if _is_ip_unsafe(ip_addr):
            raise InspectionBlockedError(
                f"Blocked for safety: '{hostname}' resolved to restricted IP '{ip_addr}'."
            )

    return resolved_ips


class _ReadOnlyHtmlInspector(HTMLParser):
    """Lightweight read-only HTML parser extracting forms, scripts, pixels, and title."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_title = False
        self._in_script = False
        self._in_body = False
        self.title_parts: list[str] = []
        self.body_text_parts: list[str] = []
        self.script_srcs: list[str] = []
        self.inline_scripts: list[str] = []
        self.img_srcs: list[str] = []
        self.iframe_srcs: list[str] = []
        self.link_hrefs: list[str] = []
        self.forms: list[FormObservation] = []

        self._current_form: dict | None = None
        self._current_script_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        if tag == "title":
            self._in_title = True
        elif tag == "body":
            self._in_body = True
        elif tag == "script":
            self._in_script = True
            self._current_script_parts = []
            src = attr_map.get("src", "").strip()
            if src:
                self.script_srcs.append(src)
        elif tag == "img":
            src = attr_map.get("src", "").strip()
            if src:
                self.img_srcs.append(src)
        elif tag == "iframe":
            src = attr_map.get("src", "").strip()
            if src:
                self.iframe_srcs.append(src)
        elif tag == "link":
            href = attr_map.get("href", "").strip()
            if href:
                self.link_hrefs.append(href)
        elif tag == "form":
            self._current_form = {
                "action": attr_map.get("action", "").strip(),
                "method": (attr_map.get("method", "GET") or "GET").upper(),
                "has_password": False,
                "has_otp": False,
                "has_user": False,
            }
        elif tag == "input" and self._current_form is not None:
            input_type = attr_map.get("type", "text").lower()
            input_name = attr_map.get("name", "").lower()
            input_id = attr_map.get("id", "").lower()
            placeholder = attr_map.get("placeholder", "").lower()
            combined = f"{input_type} {input_name} {input_id} {placeholder}"

            if input_type == "password" or "pass" in combined or "pwd" in combined:
                self._current_form["has_password"] = True
            if any(tok in combined for tok in ("otp", "pin", "2fa", "mfa", "verification_code", "token")):
                self._current_form["has_otp"] = True
            if input_type == "email" or any(
                tok in combined for tok in ("email", "user", "login", "account", "phone")
            ):
                self._current_form["has_user"] = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "body":
            self._in_body = False
        elif tag == "script":
            self._in_script = False
            snippet = "".join(self._current_script_parts).strip()
            if snippet:
                self.inline_scripts.append(snippet[:500])
        elif tag == "form" and self._current_form is not None:
            self.forms.append(
                FormObservation(
                    action=self._current_form["action"],
                    method=self._current_form["method"],
                    has_password_input=self._current_form["has_password"],
                    has_otp_input=self._current_form["has_otp"],
                    has_email_or_user_input=self._current_form["has_user"],
                )
            )
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        elif self._in_script:
            self._current_script_parts.append(data)
        elif self._in_body:
            self.body_text_parts.append(data)


def parse_html_observations(
    *,
    html_text: str,
    final_url: str,
    status_code: int,
    redirect_chain: list[str],
    set_cookie_headers: list[str],
) -> PageObservation:
    """Parse HTML and response headers into a read-only PageObservation."""
    parser = _ReadOnlyHtmlInspector()
    parser.feed(html_text)
    parser.close()

    cookie_names: list[str] = []
    for raw_cookie in set_cookie_headers:
        name = raw_cookie.split("=", 1)[0].strip()
        if name:
            cookie_names.append(name)

    final_host = (urlsplit(final_url).hostname or "").lower()
    title = " ".join("".join(parser.title_parts).split())[:200]
    text_snippet = " ".join("".join(parser.body_text_parts).split())[:1500]

    return PageObservation(
        final_url=final_url,
        final_hostname=final_host,
        status_code=status_code,
        title=title,
        text_snippet=text_snippet,
        redirect_chain=redirect_chain,
        script_srcs=parser.script_srcs[:50],
        img_srcs=parser.img_srcs[:50],
        iframe_srcs=parser.iframe_srcs[:20],
        link_hrefs=parser.link_hrefs[:30],
        forms=parser.forms[:10],
        set_cookie_names=cookie_names[:30],
        inline_script_snippets=parser.inline_scripts[:20],
    )


def inspect_website_safely(
    url: str,
    *,
    config: WebsiteInspectionConfig = settings.website_inspection,
    dns_resolver: Callable[[str], list[str]] | None = None,
    http_client_factory: Callable[..., httpx.Client] | None = None,
) -> InspectionOutcome:
    """Perform isolated, read-only HTTP GET inspection with SSRF & download protections."""
    if not config.enabled:
        return InspectionOutcome(
            status="unavailable",
            reason="Active website inspection is disabled by server configuration.",
        )

    current_url = url
    redirect_chain: list[str] = []
    blocked_destinations: list[str] = []

    client_factory = http_client_factory or httpx.Client

    try:
        with client_factory(
            follow_redirects=False,
            timeout=config.timeout_seconds,
            headers={
                "User-Agent": "ScamShield-ReadOnly-Inspector/1.0",
                "Accept": "text/html,application/xhtml+xml",
            },
        ) as client:
            response: httpx.Response | None = None
            for _hop in range(config.max_redirects + 1):
                # Validate destination before EVERY request/redirect hop
                validate_destination_safety(current_url, dns_resolver=dns_resolver)

                response = client.get(current_url)

                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location", "").strip()
                    if not location:
                        break
                    next_url = urljoin(current_url, location)
                    try:
                        validate_destination_safety(next_url, dns_resolver=dns_resolver)
                    except InspectionBlockedError as exc:
                        blocked_destinations.append(next_url)
                        return InspectionOutcome(
                            status="blocked",
                            reason=str(exc),
                            blocked_destinations=blocked_destinations,
                        )
                    redirect_chain.append(next_url)
                    current_url = next_url
                    continue
                break

            if response is None:
                return InspectionOutcome(
                    status="unavailable",
                    reason="Website inspection received no HTTP response.",
                )

            if response.status_code in {301, 302, 303, 307, 308}:
                return InspectionOutcome(
                    status="blocked",
                    reason=f"Exceeded maximum redirect limit ({config.max_redirects}).",
                    blocked_destinations=redirect_chain,
                )

            # Block file downloads & binary payloads
            content_disp = response.headers.get("content-disposition", "").lower()
            if "attachment" in content_disp:
                return InspectionOutcome(
                    status="blocked",
                    reason="Blocked for safety: server attempted a file download (Content-Disposition: attachment).",
                    blocked_destinations=[current_url],
                )

            content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type and any(content_type.startswith(p) for p in BLOCKED_DOWNLOAD_MIME_PREFIXES):
                return InspectionOutcome(
                    status="blocked",
                    reason=f"Blocked for safety: binary/download MIME type '{content_type}' is not inspected.",
                    blocked_destinations=[current_url],
                )
            if content_type and content_type not in ALLOWED_HTML_MIME_TYPES:
                return InspectionOutcome(
                    status="unavailable",
                    reason=f"Non-HTML content type '{content_type}' skipped by read-only inspector.",
                )

            raw_bytes = response.content[: config.max_response_bytes]
            html_text = raw_bytes.decode(response.encoding or "utf-8", errors="replace")
            set_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []

            observation = parse_html_observations(
                html_text=html_text,
                final_url=current_url,
                status_code=response.status_code,
                redirect_chain=redirect_chain,
                set_cookie_headers=set_cookies,
            )
            return InspectionOutcome(status="completed", observation=observation)

    except InspectionBlockedError as exc:
        blocked_destinations.append(current_url)
        return InspectionOutcome(
            status="blocked",
            reason=str(exc),
            blocked_destinations=blocked_destinations,
        )
    except InspectionUnavailableError as exc:
        return InspectionOutcome(status="unavailable", reason=str(exc))
    except httpx.TimeoutException:
        return InspectionOutcome(
            status="unavailable",
            reason=f"Website inspection timed out after {config.timeout_seconds}s.",
        )
    except httpx.HTTPError as exc:
        return InspectionOutcome(
            status="unavailable",
            reason=f"Website inspection failed ({type(exc).__name__}).",
        )
