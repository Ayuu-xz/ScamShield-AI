/**
 * API client and response normalizer for the ScamShield AI FastAPI backend.
 * Base URL can be configured via VITE_API_BASE_URL in frontend/.env.
 */

const API_BASE_URL =
  import.meta.env?.VITE_API_BASE_URL?.replace(/\/+$/, '') || ''

const DEFAULT_DISCLAIMER =
  'Automated analysis can make mistakes and a Safe result never guarantees a URL or message is 100% safe.'

/**
 * Extract a readable error message from FastAPI error responses.
 */
async function extractErrorMessage(response, fallbackMessage) {
  try {
    const payload = await response.json()
    if (typeof payload?.detail === 'string') {
      return payload.detail
    }
    if (Array.isArray(payload?.detail) && payload.detail[0]?.msg) {
      return payload.detail[0].msg
    }
  } catch {
    // Ignore JSON parse errors on non-JSON error bodies
  }
  return `${fallbackMessage} (HTTP ${response.status})`
}

/**
 * Shared fetch wrapper that handles network failures, non-OK HTTP status codes,
 * and malformed/non-object JSON responses with user-friendly error messages.
 */
async function requestJson(url, options, fallbackMessage) {
  let response
  try {
    response = await fetch(url, options)
  } catch (err) {
    if (err?.name === 'AbortError') {
      throw err
    }
    throw new Error(
      'Unable to connect to the ScamShield AI backend. Please verify the API server is running.',
    )
  }

  if (!response.ok) {
    const message = await extractErrorMessage(response, fallbackMessage)
    throw new Error(message)
  }

  let data
  try {
    data = await response.json()
  } catch {
    throw new Error('Received an invalid response from the server.')
  }

  if (typeof data !== 'object' || data === null) {
    throw new Error('Received an unexpected response format from the server.')
  }

  return data
}

/**
 * Normalize backend scan responses from /api/scan/url, /api/scan/message,
 * and /api/scan/message-image into a single unified shape.
 * @param {object} raw - Raw JSON payload from the backend.
 * @param {'url' | 'message' | 'message-image'} fallbackType - Fallback scan type.
 */
export function normalizeScanResponse(raw, fallbackType = 'url') {
  const rawScore = raw?.overall_risk_score ?? raw?.risk_score ?? null
  const score =
    rawScore === null || rawScore === undefined
      ? null
      : Math.min(100, Math.max(0, Number(rawScore)))

  const rawLevel = raw?.overall_risk_level ?? raw?.risk_level
  let riskLevel
  if (
    rawLevel === 'Safe' ||
    rawLevel === 'Suspicious' ||
    rawLevel === 'Dangerous' ||
    rawLevel === 'No strong indicators detected' ||
    rawLevel === 'Inspection unavailable' ||
    rawLevel === 'Unavailable'
  ) {
    riskLevel = rawLevel
  } else if (score === null) {
    riskLevel = 'Unavailable'
  } else if (score <= 24) {
    riskLevel = 'Inspection unavailable'
  } else if (score <= 49) {
    riskLevel = 'Suspicious'
  } else {
    riskLevel = 'Dangerous'
  }

  const scanType =
    raw?.scan_type === 'message' ||
    raw?.scan_type === 'message-image' ||
    raw?.scan_type === 'url'
      ? raw.scan_type
      : fallbackType

  return {
    success: Boolean(raw?.success ?? true),
    scanId: raw?.scan_id ?? null,
    scanType,
    riskScore: score,
    riskLevel,
    ruleScore: raw?.rule_score ?? score,
    combinedRiskScore: raw?.combined_risk_score ?? score,
    mlAnalysis: raw?.ml_analysis ?? null,
    inspectionStatus: raw?.inspection_status || 'Check unavailable',
    inspectionNote:
      raw?.inspection_note || 'URL-only analysis — website content was not inspected.',
    blockedDestinations: Array.isArray(raw?.blocked_destinations)
      ? raw.blocked_destinations
      : [],
    completedChecks: Array.isArray(raw?.completed_checks) ? raw.completed_checks : [],
    detectedRules: Array.isArray(raw?.detected_rules) ? raw.detected_rules : [],
    ruleExplanations: Array.isArray(raw?.rule_explanations) ? raw.rule_explanations : [],
    trackerIndicators: Array.isArray(raw?.tracker_indicators) ? raw.tracker_indicators : [],
    phishingIndicators: Array.isArray(raw?.phishing_indicators) ? raw.phishing_indicators : [],
    malwareIndicators: Array.isArray(raw?.malware_indicators) ? raw.malware_indicators : [],
    redirectIndicators: Array.isArray(raw?.redirect_indicators) ? raw.redirect_indicators : [],
    domainIntelligence: raw?.domain_intelligence ?? null,
    fileDownloadIndicators: Array.isArray(raw?.file_download_indicators)
      ? raw.file_download_indicators
      : [],
    reputationStatus: raw?.reputation_status || 'Check unavailable',
    detectedIndicators: Array.isArray(raw?.detected_indicators)
      ? raw.detected_indicators
      : [],
    explanations: Array.isArray(raw?.explanations) ? raw.explanations : [],
    recommendations: Array.isArray(raw?.recommendations) ? raw.recommendations : [],
    multilingualExplanations: raw?.multilingual_explanations ?? null,
    limitations: Array.isArray(raw?.limitations) ? raw.limitations : [],
    disclaimer: raw?.disclaimer || DEFAULT_DISCLAIMER,
    extractedText: raw?.extracted_text ?? null,
    detectedUrls: Array.isArray(raw?.detected_urls) ? raw.detected_urls : [],
    urlResults: Array.isArray(raw?.url_results) ? raw.url_results : [],
    ocrConfidence:
      typeof raw?.ocr_confidence === 'number' ? raw.ocr_confidence : null,
    lowOcrConfidenceWarning: raw?.low_ocr_confidence_warning ?? null,
    ocrStatus: raw?.ocr_status ?? null,
    ocrWarnings: Array.isArray(raw?.ocr_warnings) ? raw.ocr_warnings : [],
    suggestedUrlCandidates: Array.isArray(raw?.suggested_url_candidates)
      ? raw.suggested_url_candidates
      : [],
    status: raw?.status || 'completed',
    explanation: raw?.explanation ?? null,
    scannedAt: new Date().toISOString(),
  }
}

/**
 * Calls GET /api/health to verify the backend server is reachable.
 * @param {AbortSignal} [signal] - Optional abort signal for cleanup.
 */
export async function fetchHealthCheck(signal) {
  return requestJson(
    `${API_BASE_URL}/api/health`,
    {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal,
    },
    'Health check failed',
  )
}

/**
 * Sends a URL string to POST /api/scan/url for text-only or isolated inspection.
 * @param {string} url
 * @param {boolean} [inspectWebsite]
 */
export async function scanUrl(url, inspectWebsite = false) {
  const data = await requestJson(
    `${API_BASE_URL}/api/scan/url`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ url, inspect_website: inspectWebsite }),
    },
    'URL scan failed',
  )
  return normalizeScanResponse(data, 'url')
}

/**
 * Sends a message string to POST /api/scan/message for URL-first analysis.
 * @param {string} message
 * @param {boolean} [inspectWebsite]
 */
export async function scanMessage(message, inspectWebsite = false) {
  const data = await requestJson(
    `${API_BASE_URL}/api/scan/message`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ message, inspect_website: inspectWebsite }),
    },
    'Message scan failed',
  )
  return normalizeScanResponse(data, 'message')
}

/**
 * Uploads an image/screenshot to POST /api/scan/message-image for OCR + URL analysis.
 * @param {File} file
 * @param {boolean} [inspectWebsite]
 */
export async function scanMessageImage(file, inspectWebsite = false) {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('inspect_website', String(Boolean(inspectWebsite)))

  const data = await requestJson(
    `${API_BASE_URL}/api/scan/message-image`,
    {
      method: 'POST',
      headers: {
        Accept: 'application/json',
      },
      body: formData,
    },
    'Image OCR scan failed',
  )
  return normalizeScanResponse(data, 'message-image')
}

/**
 * Fetch paginated scan history from GET /api/history with optional filters, search, date range, and sorting.
 */
export async function fetchHistory({
  limit = 10,
  offset = 0,
  scanType = '',
  riskLevel = '',
  search = '',
  dateFrom = '',
  dateTo = '',
  sortBy = 'date_desc',
} = {}) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  })
  if (scanType) params.set('scan_type', scanType)
  if (riskLevel) params.set('risk_level', riskLevel)
  if (search && search.trim()) params.set('search', search.trim())
  if (dateFrom) params.set('date_from', new Date(`${dateFrom}T00:00:00Z`).toISOString())
  if (dateTo) params.set('date_to', new Date(`${dateTo}T23:59:59Z`).toISOString())
  if (sortBy) params.set('sort_by', sortBy)

  return requestJson(
    `${API_BASE_URL}/api/history?${params.toString()}`,
    {
      method: 'GET',
      headers: { Accept: 'application/json' },
    },
    'Failed to load scan history',
  )
}

/**
 * Fetch a full validated scan report from GET /api/history/{scanId}/report.
 */
export async function fetchScanReport(scanId) {
  return requestJson(
    `${API_BASE_URL}/api/history/${scanId}/report`,
    {
      method: 'GET',
      headers: { Accept: 'application/json' },
    },
    'Failed to load scan report',
  )
}

/**
 * Download an exported scan report as JSON or PDF from GET /api/history/{scanId}/export.
 */
export async function downloadScanReport(scanId, format = 'json') {
  const safeFormat = format === 'pdf' ? 'pdf' : 'json'
  const url = `${API_BASE_URL}/api/history/${scanId}/export?format=${safeFormat}`
  let response
  try {
    response = await fetch(url, { method: 'GET' })
  } catch {
    throw new Error(
      'Unable to connect to the ScamShield AI backend to export the report.',
    )
  }

  if (!response.ok) {
    const message = await extractErrorMessage(response, 'Failed to export scan report')
    throw new Error(message)
  }

  const blob = await response.blob()
  if (!blob || blob.size === 0) {
    throw new Error('Exported report file was empty.')
  }

  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = `scamshield-report-${scanId}.${safeFormat}`
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(objectUrl)
}

/**
 * Fetch real-database analytics from GET /api/analytics.
 */
export async function fetchAnalytics({
  scanType = '',
  riskLevel = '',
  dateFrom = '',
  dateTo = '',
} = {}) {
  const params = new URLSearchParams()
  if (scanType) params.set('scan_type', scanType)
  if (riskLevel) params.set('risk_level', riskLevel)
  if (dateFrom) params.set('date_from', new Date(`${dateFrom}T00:00:00Z`).toISOString())
  if (dateTo) params.set('date_to', new Date(`${dateTo}T23:59:59Z`).toISOString())

  const query = params.toString()
  return requestJson(
    `${API_BASE_URL}/api/analytics${query ? `?${query}` : ''}`,
    {
      method: 'GET',
      headers: { Accept: 'application/json' },
    },
    'Failed to load analytics',
  )
}

/**
 * Request an evidence-based Gemini explanation via POST /api/explanations/generate.
 */
export async function generateAiExplanation(scanResult, language = 'en') {
  return requestJson(
    `${API_BASE_URL}/api/explanations/generate`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        scan_type: scanResult.scanType || 'url',
        risk_level: scanResult.riskLevel || 'Inspection unavailable',
        risk_score: scanResult.riskScore ?? null,
        detected_indicators: scanResult.detectedIndicators || [],
        rule_explanations: scanResult.ruleExplanations || [],
        ml_analysis: scanResult.mlAnalysis || null,
        detected_urls: scanResult.detectedUrls || [],
        reputation_status: scanResult.reputationStatus || 'Check unavailable',
        domain_intelligence: scanResult.domainIntelligence || null,
        inspection_status: scanResult.inspectionStatus || 'Check unavailable',
        inspection_note: scanResult.inspectionNote || '',
        ocr_confidence: scanResult.ocrConfidence ?? null,
        language,
      }),
    },
    'Failed to generate AI explanation',
  )
}

/**
 * Request Gemini TTS WAV audio for a server-validated explanation_id.
 */
export async function generateAiAudio(explanationId, language = 'en') {
  let response
  try {
    response = await fetch(`${API_BASE_URL}/api/explanations/audio`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'audio/wav',
      },
      body: JSON.stringify({
        explanation_id: explanationId,
        language,
      }),
    })
  } catch {
    throw new Error('Unable to connect to the backend audio service.')
  }

  if (!response.ok) {
    const message = await extractErrorMessage(response, 'Audio explanation unavailable')
    throw new Error(message)
  }

  const blob = await response.blob()
  if (!blob || blob.size === 0) {
    throw new Error('Received empty audio response.')
  }
  return blob
}

/**
 * Fetch complete details for one scan from GET /api/history/{scanId}.
 */
export async function fetchHistoryDetail(scanId) {
  return requestJson(
    `${API_BASE_URL}/api/history/${scanId}`,
    {
      method: 'GET',
      headers: { Accept: 'application/json' },
    },
    'Failed to load scan details',
  )
}

/**
 * Delete a single scan record via DELETE /api/history/{scanId}.
 */
export async function deleteHistoryItem(scanId) {
  return requestJson(
    `${API_BASE_URL}/api/history/${scanId}`,
    {
      method: 'DELETE',
      headers: { Accept: 'application/json' },
    },
    'Failed to delete scan record',
  )
}

/**
 * Clear all scan history via DELETE /api/history.
 */
export async function clearAllHistory() {
  return requestJson(
    `${API_BASE_URL}/api/history`,
    {
      method: 'DELETE',
      headers: { Accept: 'application/json' },
    },
    'Failed to clear scan history',
  )
}

export { API_BASE_URL }
