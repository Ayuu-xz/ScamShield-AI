import { useEffect, useRef, useState } from 'react'
import {
  Sparkles,
  Volume2,
  Play,
  Pause,
  Square,
  ChevronDown,
  ChevronUp,
  Loader2,
  AlertTriangle,
  Info,
} from 'lucide-react'
import { generateAiAudio, generateAiExplanation } from '../services/api.js'

const LANG_OPTIONS = [
  { id: 'en', label: 'English' },
  { id: 'hi', label: 'हिंदी' },
  { id: 'hinglish', label: 'Hinglish' },
]

/**
 * Gemini-powered "Why is this flagged?" explanation + TTS audio section.
 * Never alters risk scores or classifications; falls back gracefully when unavailable.
 */
export default function GeminiExplanationSection({
  scanResult,
  selectedLang,
  onSelectLang,
}) {
  const [aiState, setAiState] = useState({
    loading: false,
    data: null,
    error: '',
  })
  const [expanded, setExpanded] = useState(false)

  const [audioState, setAudioState] = useState({
    loading: false,
    status: 'idle', // idle | playing | paused
    error: '',
    url: '',
  })
  const audioRef = useRef(null)

  const cleanupAudio = () => {
    if (audioRef.current) {
      audioRef.current.pause()
      audioRef.current.currentTime = 0
      audioRef.current = null
    }
    setAudioState((prev) => {
      if (prev.url) URL.revokeObjectURL(prev.url)
      return { loading: false, status: 'idle', error: '', url: '' }
    })
  }

  useEffect(() => {
    setAiState({ loading: false, data: null, error: '' })
    setExpanded(false)
    cleanupAudio()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanResult?.scanId, scanResult?.scannedAt])

  useEffect(() => {
    return () => {
      if (audioRef.current) {
        audioRef.current.pause()
      }
    }
  }, [])

  const handleGenerate = async (lang = selectedLang) => {
    cleanupAudio()
    setAiState({ loading: true, data: null, error: '' })
    try {
      const res = await generateAiExplanation(scanResult, lang)
      setAiState({ loading: false, data: res, error: '' })
    } catch (err) {
      setAiState({
        loading: false,
        data: null,
        error: err.message || 'AI explanation is temporarily unavailable.',
      })
    }
  }

  const handleLanguageSwitch = (lang) => {
    onSelectLang?.(lang)
    if (aiState.data || aiState.loading) {
      handleGenerate(lang)
    }
  }

  const handleListen = async () => {
    const expId = aiState.data?.explanation_id
    if (!expId) return

    if (audioState.url && audioRef.current) {
      audioRef.current.play()
      setAudioState((prev) => ({ ...prev, status: 'playing', error: '' }))
      return
    }

    setAudioState((prev) => ({ ...prev, loading: true, error: '' }))
    try {
      const wavBlob = await generateAiAudio(expId, selectedLang)
      const objectUrl = URL.createObjectURL(wavBlob)
      const audio = new Audio(objectUrl)
      audio.onended = () => {
        setAudioState((prev) => ({ ...prev, status: 'idle' }))
      }
      audio.onerror = () => {
        setAudioState((prev) => ({
          ...prev,
          status: 'idle',
          error: 'Audio playback failed in browser.',
        }))
      }
      audioRef.current = audio
      await audio.play()
      setAudioState({ loading: false, status: 'playing', error: '', url: objectUrl })
    } catch (err) {
      setAudioState({
        loading: false,
        status: 'idle',
        error: err.message || 'Audio explanation is temporarily unavailable.',
        url: '',
      })
    }
  }

  const handlePause = () => {
    if (audioRef.current) {
      audioRef.current.pause()
      setAudioState((prev) => ({ ...prev, status: 'paused' }))
    }
  }

  const handleStop = () => {
    if (audioRef.current) {
      audioRef.current.pause()
      audioRef.current.currentTime = 0
      setAudioState((prev) => ({ ...prev, status: 'idle' }))
    }
  }

  const explanation = aiState.data?.explanation
  const isAvailable = Boolean(aiState.data?.available && explanation)

  return (
    <section
      aria-label="AI Explanation Assistant"
      className="rounded-lg border border-[#263449] bg-[#0B1120] p-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Sparkles className="h-4 w-4 text-[#3B82F6]" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
            Why is this flagged?
          </h3>
          <span className="rounded border border-[#3B82F6]/35 bg-[#3B82F6]/12 px-2 py-0.5 text-[10px] font-semibold text-[#93C5FD]">
            AI-Generated Explanation
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Language Selector */}
          <div
            role="group"
            aria-label="AI explanation language"
            className="inline-flex items-center rounded-md border border-[#263449] bg-[#111C30] p-0.5"
          >
            {LANG_OPTIONS.map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => handleLanguageSwitch(opt.id)}
                className={`rounded px-2 py-0.5 text-[11px] font-medium transition-colors duration-150 ${
                  selectedLang === opt.id
                    ? 'bg-[#3B82F6] text-white'
                    : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            disabled={aiState.loading}
            onClick={() => handleGenerate(selectedLang)}
            className="inline-flex items-center gap-1.5 rounded-md bg-[#3B82F6] px-3 py-1 text-[11px] font-semibold text-white transition-colors duration-150 hover:bg-[#2563EB] disabled:opacity-60"
          >
            {aiState.loading ? (
              <>
                <Loader2 className="h-3 w-3 animate-spin" />
                Explaining...
              </>
            ) : (
              <>
                <Sparkles className="h-3 w-3" />
                {isAvailable ? 'Refresh AI Explanation' : 'Explain with AI'}
              </>
            )}
          </button>

          {isAvailable && (
            <div className="inline-flex items-center gap-1">
              {audioState.status !== 'playing' ? (
                <button
                  type="button"
                  disabled={audioState.loading}
                  onClick={handleListen}
                  className="inline-flex items-center gap-1 rounded-md border border-[#263449] bg-[#172338] px-2.5 py-1 text-[11px] font-semibold text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50 disabled:opacity-60"
                >
                  {audioState.loading ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : audioState.status === 'paused' ? (
                    <Play className="h-3 w-3 text-[#3B82F6]" />
                  ) : (
                    <Volume2 className="h-3 w-3 text-[#3B82F6]" />
                  )}
                  {audioState.loading
                    ? 'Loading Audio...'
                    : audioState.status === 'paused'
                      ? 'Resume'
                      : 'Listen'}
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handlePause}
                  className="inline-flex items-center gap-1 rounded-md border border-[#3B82F6]/40 bg-[#3B82F6]/15 px-2.5 py-1 text-[11px] font-semibold text-[#93C5FD]"
                >
                  <Pause className="h-3 w-3" />
                  Pause
                </button>
              )}

              {(audioState.status === 'playing' || audioState.status === 'paused') && (
                <button
                  type="button"
                  onClick={handleStop}
                  aria-label="Stop audio"
                  className="inline-flex items-center gap-1 rounded-md border border-[#263449] bg-[#111C30] px-2 py-1 text-[11px] font-medium text-[#94A3B8] hover:text-[#F1F5F9]"
                >
                  <Square className="h-3 w-3" />
                  Stop
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Audio error */}
      {audioState.error && (
        <p className="mt-2.5 flex items-center gap-1.5 text-[11px] text-[#FCA5A5]">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-[#EF4444]" />
          {audioState.error}
        </p>
      )}

      {/* Unavailable / Fallback / Error State */}
      {(aiState.error || (aiState.data && !aiState.data.available)) && (
        <div className="mt-3 rounded-md border border-[#263449] bg-[#111C30] p-3 text-xs text-[#94A3B8]">
          <p className="flex items-center gap-1.5 font-medium text-[#FCD34D]">
            <Info className="h-3.5 w-3.5 shrink-0 text-[#F59E0B]" />
            {aiState.error || aiState.data?.error || 'AI explanation is temporarily unavailable.'}
          </p>
          {aiState.data?.fallback_explanations?.length > 0 && (
            <ul className="mt-2 list-disc space-y-1 pl-4 text-[11px] text-[#94A3B8]">
              {aiState.data.fallback_explanations.map((item, idx) => (
                <li key={`${item}-${idx}`}>{item}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Validated Gemini Explanation */}
      {isAvailable && (
        <div className="mt-3 space-y-3 text-xs">
          <div className="rounded-md border border-[#263449] bg-[#111C30] p-3.5">
            <p className="font-semibold text-[#F1F5F9]">{explanation.title}</p>
            <p className="mt-1 leading-relaxed text-[#94A3B8]">{explanation.short_summary}</p>
          </div>

          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#3B82F6] hover:text-[#60A5FA]"
          >
            {expanded ? (
              <>
                Hide Detailed AI Breakdown <ChevronUp className="h-3.5 w-3.5" />
              </>
            ) : (
              <>
                View Detailed AI Breakdown <ChevronDown className="h-3.5 w-3.5" />
              </>
            )}
          </button>

          {expanded && (
            <div className="space-y-3 rounded-md border border-[#263449] bg-[#111C30] p-3.5">
              <p className="leading-relaxed text-[#F1F5F9]">{explanation.overall_explanation}</p>

              {explanation.indicator_explanations?.length > 0 && (
                <div className="space-y-2">
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-[#94A3B8]">
                    Indicator Breakdown
                  </p>
                  {explanation.indicator_explanations.map((item, idx) => (
                    <div
                      key={`${item.indicator}-${idx}`}
                      className="rounded border border-[#263449] bg-[#0B1120] p-2.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-semibold text-[#F1F5F9]">{item.indicator}</span>
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                            item.status === 'Confirmed'
                              ? 'bg-[#EF4444]/15 text-[#FCA5A5]'
                              : 'bg-[#F59E0B]/15 text-[#FCD34D]'
                          }`}
                        >
                          {item.status}
                        </span>
                      </div>
                      <p className="mt-1 text-[11px] text-[#94A3B8]">
                        <strong className="text-[#F1F5F9]">Detected:</strong> {item.what_detected}
                      </p>
                      <p className="mt-0.5 text-[11px] text-[#94A3B8]">
                        <strong className="text-[#F1F5F9]">Why suspicious:</strong>{' '}
                        {item.why_suspicious}
                      </p>
                      <p className="mt-0.5 text-[11px] text-[#94A3B8]">
                        <strong className="text-[#F1F5F9]">Safety impact:</strong>{' '}
                        {item.safety_impact}
                      </p>
                    </div>
                  ))}
                </div>
              )}

              {explanation.recommended_actions?.length > 0 && (
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-[#94A3B8]">
                    Recommended Safe Actions
                  </p>
                  <ul className="mt-1 list-disc space-y-1 pl-4 text-[11px] text-[#94A3B8]">
                    {explanation.recommended_actions.map((act, idx) => (
                      <li key={`${act}-${idx}`}>{act}</li>
                    ))}
                  </ul>
                </div>
              )}

              <p className="text-[11px] text-[#94A3B8]">
                <strong className="text-[#F1F5F9]">Limitations:</strong>{' '}
                {explanation.confidence_limitations}
              </p>
            </div>
          )}
        </div>
      )}

      <p className="mt-2.5 text-[10px] text-[#94A3B8]">
        Privacy Notice: Sanitized scan evidence (excluding passwords, tokens, and full private
        messages) may be sent to Google&apos;s Gemini API only when you request an AI explanation.
      </p>
    </section>
  )
}
