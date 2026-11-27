import { API_BASE_URL, REQUEST_TIMEOUT_MS } from './config.js'

const UNSAFE_SCHEME_RE = /^(javascript|data|vbscript|file|chrome|chrome-extension|about):/i

/**
 * Validate a URL string on the client before sending it to the backend.
 * Never opens, fetches, or executes the URL.
 */
export function validateUrlInput(rawUrl) {
  if (typeof rawUrl !== 'string') {
    return { valid: false, error: 'URL must be a text string.' }
  }
  const trimmed = rawUrl.trim()
  if (!trimmed) {
    return { valid: false, error: 'Please enter a URL to scan.' }
  }
  if (trimmed.length > 2048) {
    return { valid: false, error: 'URL cannot exceed 2048 characters.' }
  }
  if (/\s/.test(trimmed)) {
    return { valid: false, error: 'URLs cannot contain spaces.' }
  }
  if (UNSAFE_SCHEME_RE.test(trimmed)) {
    return {
      valid: false,
      error: 'Internal browser or script URLs cannot be scanned.',
    }
  }
  return { valid: true, url: trimmed }
}

/**
 * Call GET /api/health to check backend availability.
 */
export async function checkBackendHealth(
  fetchImpl = globalThis.fetch,
  baseUrl = API_BASE_URL,
) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const res = await fetchImpl(`${baseUrl}/api/health`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    })
    if (!res.ok) {
      return { ok: false, error: `API returned HTTP ${res.status}` }
    }
    const data = await res.json()
    return { ok: data?.status === 'ok', data }
  } catch (err) {
    if (err?.name === 'AbortError') {
      return { ok: false, error: 'Backend health check timed out.' }
    }
    return { ok: false, error: 'Backend server unavailable.' }
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Send a URL string to POST /api/scan/url and return the backend risk assessment.
 */
export async function scanUrlWithBackend(
  rawUrl,
  fetchImpl = globalThis.fetch,
  baseUrl = API_BASE_URL,
) {
  const validation = validateUrlInput(rawUrl)
  if (!validation.valid) {
    throw new Error(validation.error)
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)

  let response
  try {
    response = await fetchImpl(`${baseUrl}/api/scan/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ url: validation.url, inspect_website: false }),
      signal: controller.signal,
    })
  } catch (err) {
    if (err?.name === 'AbortError') {
      throw new Error('Request timed out while contacting ScamShield AI backend.')
    }
    throw new Error(
      'Unable to reach ScamShield AI backend. Verify the FastAPI server is running.',
    )
  } finally {
    clearTimeout(timer)
  }

  let payload
  try {
    payload = await response.json()
  } catch {
    throw new Error('Received an invalid non-JSON response from the backend.')
  }

  if (!response.ok) {
    const detail =
      typeof payload?.detail === 'string'
        ? payload.detail
        : Array.isArray(payload?.detail) && payload.detail[0]?.msg
          ? payload.detail[0].msg
          : `Scan failed (HTTP ${response.status})`
    throw new Error(detail)
  }

  if (typeof payload !== 'object' || payload === null) {
    throw new Error('Unexpected response structure from backend.')
  }

  return payload
}
