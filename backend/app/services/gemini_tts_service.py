"""Gemini Text-to-Speech (TTS) audio service for validated scan explanations."""

from __future__ import annotations

import io
import threading
import time
import wave
from typing import Callable

from google import genai
from google.genai import types

from app.core.config import GeminiConfig, settings
from app.schemas.explanations import GeminiExplanationPayload
from app.services.gemini_explanation_service import get_validated_explanation

_audio_lock = threading.Lock()
# Maps (explanation_id, language) -> (expires_at, wav_bytes)
_audio_cache: dict[tuple[str, str], tuple[float, bytes]] = {}


class TtsUnavailableError(RuntimeError):
    """Raised when Gemini TTS cannot generate audio."""


class ExplanationNotFoundError(LookupError):
    """Raised when the requested validated explanation ID is missing or expired."""


def clear_audio_cache() -> None:
    """Clear in-memory TTS audio cache (for tests)."""
    with _audio_lock:
        _audio_cache.clear()


def _pcm_to_wav(pcm_bytes: bytes, sample_rate: int = 24000) -> bytes:
    """Wrap raw 16-bit mono PCM bytes in a standard RIFF/WAV container."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(pcm_bytes)
    return buf.getvalue()


def _build_spoken_script(payload: GeminiExplanationPayload, language: str) -> str:
    """Construct a clear, neutral educational script solely from validated explanation fields."""
    actions = "; ".join(payload.recommended_actions[:3]) if payload.recommended_actions else ""
    parts = [
        payload.title,
        payload.short_summary,
        payload.overall_explanation,
    ]
    if actions:
        prefix = "सुझाए गए कदम: " if language == "hi" else "Recommended next steps: "
        parts.append(f"{prefix}{actions}")
    if payload.confidence_limitations:
        parts.append(payload.confidence_limitations)
    return " ".join(p.strip() for p in parts if p and p.strip())


def _default_tts_caller(
    *,
    api_key: str,
    model: str,
    voice_name: str,
    timeout_seconds: float,
    script: str,
) -> bytes:
    """Call Gemini TTS via google-genai v1beta API and return raw PCM bytes."""
    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(
            api_version="v1beta",
            timeout=max(1000, int(timeout_seconds * 1000)),
        ),
    )
    prompt = f"Read the following security explanation in a clear, neutral, educational tone:\n{script}"
    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_modalities=["AUDIO"],
            speech_config=types.SpeechConfig(
                voice_config=types.VoiceConfig(
                    prebuilt_voice_config=types.PrebuiltVoiceConfig(
                        voice_name=voice_name,
                    )
                )
            ),
        ),
    )
    part = response.candidates[0].content.parts[0]
    audio_data = part.inline_data.data
    if not isinstance(audio_data, (bytes, bytearray)) or len(audio_data) == 0:
        raise TtsUnavailableError("Gemini TTS returned empty audio data.")
    return bytes(audio_data)


def generate_explanation_audio(
    *,
    explanation_id: str,
    language: str,
    config: GeminiConfig | None = None,
    tts_caller_fn: Callable[..., bytes] | None = None,
) -> bytes:
    """Generate (or return cached) WAV audio bytes for a server-validated explanation."""
    validated = get_validated_explanation(explanation_id)
    if validated is None:
        raise ExplanationNotFoundError(
            "Validated explanation not found or expired. Please regenerate the explanation."
        )

    _stored_lang, payload = validated
    cfg = config or settings.gemini
    if not cfg.api_key:
        raise TtsUnavailableError("Audio explanation is unavailable because GEMINI_API_KEY is not configured.")

    cache_key = (explanation_id, language)
    now = time.monotonic()
    with _audio_lock:
        cached = _audio_cache.get(cache_key)
        if cached and cached[0] >= now:
            return cached[1]

    script = _build_spoken_script(payload, language)
    invoke = tts_caller_fn or _default_tts_caller
    try:
        raw_audio = invoke(
            api_key=cfg.api_key,
            model=cfg.tts_model,
            voice_name=cfg.tts_voice,
            timeout_seconds=cfg.timeout_seconds,
            script=script,
        )
    except TtsUnavailableError:
        raise
    except Exception as exc:
        raise TtsUnavailableError("Audio explanation is temporarily unavailable.") from exc

    wav_bytes = raw_audio if raw_audio.startswith(b"RIFF") else _pcm_to_wav(raw_audio)
    expires_at = time.monotonic() + cfg.cache_ttl_seconds
    with _audio_lock:
        _audio_cache[cache_key] = (expires_at, wav_bytes)
    return wav_bytes
