"""Application configuration loaded from environment variables."""

import os
from dataclasses import dataclass, field


def _parse_cors_origins(raw_origins: str) -> list[str]:
    """Split a comma-separated list of origins into a clean list."""
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


def _parse_bool(raw_val: str, default: bool = False) -> bool:
    """Parse boolean environment variable."""
    if not raw_val:
        return default
    return raw_val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class RiskThresholds:
    """Configurable upper bounds for 0-100 risk classification."""

    safe_max: int = 24
    suspicious_max: int = 49


@dataclass(frozen=True)
class UrlScoringWeights:
    """Configurable, evidence-based weights for URL and website inspection."""

    confirmed_phishing_reputation: int = 50
    confirmed_malware_reputation: int = 50
    strong_credential_harvesting: int = 40
    brand_impersonation: int = 30
    suspicious_form_destination: int = 25
    deceptive_redirect: int = 20
    suspicious_domain_structure: int = 15
    suspicious_third_party_script: int = 15
    suspicious_download: int = 15
    url_shortener: int = 10
    missing_https: int = 5
    # URL-text-only signals kept calibrated so single weak signals stay low
    credential_url_pattern: int = 10
    nested_redirect: int = 15
    suspicious_redirect: int = 10
    domain_age_info: int = 0


@dataclass(frozen=True)
class UrlAnalyzerConfig:
    """Configurable thresholds for text-only URL rule checks."""

    max_url_length: int = 2048
    long_url_threshold: int = 75
    excessive_subdomain_threshold: int = 3
    excessive_hyphen_threshold: int = 3
    excessive_encoding_threshold: int = 3


@dataclass(frozen=True)
class MessageAnalyzerConfig:
    """Configurable thresholds for URL-first plain-text message inspection."""

    max_message_length: int = 5000


@dataclass(frozen=True)
class ImageUploadConfig:
    """Configurable validation limits for screenshot/image OCR uploads."""

    max_file_size_bytes: int = 5 * 1024 * 1024  # 5 MB
    min_dimension_px: int = 16
    max_dimension_px: int = 4096
    allowed_extensions: tuple[str, ...] = (".jpg", ".jpeg", ".png", ".webp")
    allowed_mime_types: tuple[str, ...] = ("image/jpeg", "image/png", "image/webp")
    allowed_pil_formats: tuple[str, ...] = ("JPEG", "PNG", "WEBP")
    low_confidence_threshold: float = 0.70


@dataclass(frozen=True)
class ThreatIntelConfig:
    """Optional external threat-intelligence / domain-reputation provider settings."""

    provider_name: str = field(default_factory=lambda: os.getenv("THREAT_INTEL_PROVIDER", "").strip())
    api_key: str = field(default_factory=lambda: os.getenv("THREAT_INTEL_API_KEY", "").strip())
    endpoint_url: str = field(default_factory=lambda: os.getenv("THREAT_INTEL_ENDPOINT_URL", "").strip())
    google_safe_browsing_api_key: str = field(
        default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    )
    urlhaus_enabled: bool = field(
        default_factory=lambda: _parse_bool(os.getenv("URLHAUS_ENABLED", "false"), False)
    )
    urlhaus_auth_key: str = field(
        default_factory=lambda: os.getenv("URLHAUS_AUTH_KEY", "").strip()
    )
    timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "3.0"))
    )
    cache_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("THREAT_INTEL_CACHE_TTL_SECONDS", "300"))
    )


@dataclass(frozen=True)
class WebsiteInspectionConfig:
    """Security limits for optional isolated read-only website inspection."""

    enabled: bool = field(
        default_factory=lambda: _parse_bool(os.getenv("WEBSITE_INSPECTION_ENABLED", "true"), True)
    )
    timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("WEBSITE_INSPECTION_TIMEOUT_SECONDS", "5.0"))
    )
    max_redirects: int = field(
        default_factory=lambda: int(os.getenv("WEBSITE_INSPECTION_MAX_REDIRECTS", "3"))
    )
    max_response_bytes: int = field(
        default_factory=lambda: int(os.getenv("WEBSITE_INSPECTION_MAX_BYTES", str(512 * 1024)))
    )


@dataclass(frozen=True)
class MLConfig:
    """Configuration for optional ML phishing URL and scam message inference."""

    enabled: bool = field(
        default_factory=lambda: _parse_bool(os.getenv("ML_ENABLED", "true"), True)
    )
    high_confidence_threshold: float = 0.75
    standalone_ml_boost: int = 25
    combined_ml_boost_cap: int = 15


@dataclass(frozen=True)
class GeminiConfig:
    """Configuration for optional Google Gemini explanation and TTS audio services."""

    api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", "").strip())
    text_model: str = field(
        default_factory=lambda: os.getenv("GEMINI_TEXT_MODEL", "gemini-2.5-flash").strip()
    )
    tts_model: str = field(
        default_factory=lambda: os.getenv("GEMINI_TTS_MODEL", "gemini-3.8-flash-lite-tts").strip()
    )
    tts_voice: str = field(
        default_factory=lambda: os.getenv("GEMINI_TTS_VOICE", "Kore").strip()
    )
    timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("GEMINI_TIMEOUT_SECONDS", "15.0"))
    )
    cache_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("GEMINI_CACHE_TTL_SECONDS", "600"))
    )
    max_requests_per_minute: int = field(
        default_factory=lambda: int(os.getenv("GEMINI_MAX_REQUESTS_PER_MINUTE", "30"))
    )


@dataclass(frozen=True)
class Settings:
    """Central settings for the ScamShield AI backend."""

    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "ScamShield AI API"))
    app_version: str = field(default_factory=lambda: os.getenv("APP_VERSION", "0.1.0"))
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    cors_origins: list[str] = field(
        default_factory=lambda: _parse_cors_origins(
            os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
        )
    )
    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./scamshield.db")
    )
    risk_thresholds: RiskThresholds = field(default_factory=RiskThresholds)
    url_weights: UrlScoringWeights = field(default_factory=UrlScoringWeights)
    url_config: UrlAnalyzerConfig = field(default_factory=UrlAnalyzerConfig)
    message_config: MessageAnalyzerConfig = field(default_factory=MessageAnalyzerConfig)
    image_config: ImageUploadConfig = field(default_factory=ImageUploadConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    website_inspection: WebsiteInspectionConfig = field(default_factory=WebsiteInspectionConfig)
    ml_config: MLConfig = field(default_factory=MLConfig)
    gemini: GeminiConfig = field(default_factory=GeminiConfig)


settings = Settings()
