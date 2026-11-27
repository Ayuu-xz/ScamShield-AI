import test from 'node:test'
import assert from 'node:assert/strict'
import {
  checkBackendHealth,
  scanUrlWithBackend,
  validateUrlInput,
} from '../src/api.js'

test('validateUrlInput accepts valid HTTP/HTTPS URLs and rejects invalid/unsafe ones', () => {
  assert.deepEqual(validateUrlInput('https://example.com/login'), {
    valid: true,
    url: 'https://example.com/login',
  })
  assert.equal(validateUrlInput('').valid, false)
  assert.equal(validateUrlInput('   ').valid, false)
  assert.equal(validateUrlInput('javascript:alert(1)').valid, false)
  assert.equal(validateUrlInput('chrome://extensions').valid, false)
  assert.equal(validateUrlInput('https://exa mple.com').valid, false)
})

test('scanUrlWithBackend handles Safe/Suspicious/Dangerous and multilingual responses', async () => {
  const mockFetch = async (_url, opts) => {
    const body = JSON.parse(opts.body)
    assert.equal(body.inspect_website, false)
    return {
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        risk_score: 45,
        risk_level: 'Suspicious',
        detected_indicators: ['Look-Alike or Brand-Impersonation Domain'],
        multilingual_explanations: {
          en: { summary: 'Risk score 45/100', explanations: ['Look-alike'], recommendations: ['Verify'] },
          hi: { summary: 'जोखिम स्कोर 45/100', explanations: ['नकल'], recommendations: ['जांचें'] },
          hinglish: { summary: 'Risk score 45/100', explanations: ['Nakal'], recommendations: ['Check karein'] },
        },
      }),
    }
  }

  const res = await scanUrlWithBackend('http://paypa1-secure-login.com/verify', mockFetch)
  assert.equal(res.risk_score, 45)
  assert.equal(res.risk_level, 'Suspicious')
  assert.ok(res.multilingual_explanations.hi.summary.includes('जोखिम स्कोर'))
})

test('scanUrlWithBackend handles backend unavailable, timeout, and invalid JSON', async () => {
  await assert.rejects(
    () =>
      scanUrlWithBackend('https://example.com', async () => {
        throw new TypeError('Failed to fetch')
      }),
    /Unable to reach ScamShield AI backend/,
  )

  await assert.rejects(
    () =>
      scanUrlWithBackend('https://example.com', async () => {
        const err = new Error('Aborted')
        err.name = 'AbortError'
        throw err
      }),
    /timed out/,
  )

  await assert.rejects(
    () =>
      scanUrlWithBackend('https://example.com', async () => ({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError('Unexpected token')
        },
      })),
    /invalid non-JSON response/,
  )
})

test('checkBackendHealth reports ok or offline cleanly', async () => {
  const okRes = await checkBackendHealth(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ status: 'ok' }),
  }))
  assert.equal(okRes.ok, true)

  const downRes = await checkBackendHealth(async () => {
    throw new TypeError('Network error')
  })
  assert.equal(downRes.ok, false)
})
