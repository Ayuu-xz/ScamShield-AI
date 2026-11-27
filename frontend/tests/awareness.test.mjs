import test from 'node:test'
import assert from 'node:assert/strict'
import {
  BEFORE_YOU_CLICK_TIPS,
  SCAM_CATEGORIES,
  SCAM_IDENTIFICATION_CHECKLIST,
  getRelevantAwarenessCards,
} from '../src/data/awarenessContent.js'

test('includes all 6 scam awareness categories, 6 checklist items, and 6 safety tips', () => {
  assert.equal(SCAM_CATEGORIES.length, 6)
  assert.equal(SCAM_IDENTIFICATION_CHECKLIST.length, 6)
  assert.equal(BEFORE_YOU_CLICK_TIPS.length, 6)
})

test('returns empty recommendations when scanResult is null or has no indicators', () => {
  assert.deepEqual(getRelevantAwarenessCards(null), [])
  assert.deepEqual(
    getRelevantAwarenessCards({ scanType: 'url', detectedIndicators: [], explanations: [] }),
    [],
  )
})

test('matches KYC and OTP cards when KYC/OTP indicators are detected', () => {
  const matched = getRelevantAwarenessCards({
    scanType: 'message',
    detectedIndicators: ['Sensitive info or KYC request', 'Unexpected reward'],
    explanations: ['Asks for urgent KYC verification and OTP.', 'Mentions a prize.'],
  })

  const ids = matched.map((c) => c.id)
  assert.ok(ids.includes('kyc'))
  assert.ok(ids.includes('otp'))
  assert.ok(ids.includes('lottery'))
})

test('matches suspicious links card for URL scans with detected indicators', () => {
  const matched = getRelevantAwarenessCards({
    scanType: 'url',
    detectedIndicators: ['URL Shortener Domain'],
    explanations: ['The domain is a URL shortener.'],
  })

  assert.deepEqual(
    matched.map((c) => c.id),
    ['shortlinks'],
  )
})
