import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeScanResponse } from '../src/services/api.js'

test('normalizes a Safe URL scan response', () => {
  const result = normalizeScanResponse(
    {
      success: true,
      scan_type: 'url',
      risk_score: 0,
      risk_level: 'Safe',
      detected_indicators: [],
      explanations: [],
      recommendations: ['Double-check the domain.'],
      disclaimer: 'A low-risk result does not guarantee that a URL is safe.',
    },
    'url',
  )

  assert.equal(result.scanType, 'url')
  assert.equal(result.riskScore, 0)
  assert.equal(result.riskLevel, 'Safe')
  assert.deepEqual(result.detectedIndicators, [])
  assert.equal(result.recommendations.length, 1)
  assert.ok(result.scannedAt)
})

test('normalizes a Suspicious URL scan response', () => {
  const result = normalizeScanResponse(
    {
      success: true,
      scan_type: 'url',
      risk_score: 55,
      risk_level: 'Suspicious',
      detected_indicators: ['Look-Alike or Brand-Impersonation Pattern'],
      explanations: ['Mimics a known brand.'],
      recommendations: ['Open the official site directly.'],
    },
    'url',
  )

  assert.equal(result.scanType, 'url')
  assert.equal(result.riskScore, 55)
  assert.equal(result.riskLevel, 'Suspicious')
})

test('normalizes a Dangerous Message scan response', () => {
  const result = normalizeScanResponse(
    {
      success: true,
      scan_type: 'message',
      risk_score: 85,
      risk_level: 'Dangerous',
      detected_indicators: ['Urgency language', 'Sensitive info or KYC request'],
      explanations: ['Creates urgency.', 'Asks for KYC.'],
      recommendations: ['Do not share OTP.'],
      disclaimer: 'Automated analysis can make mistakes.',
    },
    'message',
  )

  assert.equal(result.scanType, 'message')
  assert.equal(result.riskScore, 85)
  assert.equal(result.riskLevel, 'Dangerous')
  assert.equal(result.detectedIndicators.length, 2)
  assert.equal(result.disclaimer, 'Automated analysis can make mistakes.')
})

test('normalizes a No-URL-Detected message response as Unavailable (not Safe)', () => {
  const result = normalizeScanResponse(
    {
      success: true,
      scan_type: 'message',
      risk_score: null,
      risk_level: 'Unavailable',
      overall_risk_score: null,
      overall_risk_level: 'Unavailable',
      detected_urls: [],
      url_results: [],
      status: 'no_url_detected',
      explanation: 'No URL detected — URL-based risk assessment unavailable.',
    },
    'message',
  )

  assert.equal(result.riskScore, null)
  assert.equal(result.riskLevel, 'Unavailable')
  assert.equal(result.status, 'no_url_detected')
})

test('normalizes an Image OCR scan response with extracted text and confidence', () => {
  const result = normalizeScanResponse(
    {
      success: true,
      scan_type: 'message-image',
      extracted_text: 'Check https://bit.ly/demo',
      detected_urls: ['https://bit.ly/demo'],
      url_results: [{ url: 'https://bit.ly/demo', risk_score: 30, risk_level: 'Suspicious' }],
      overall_risk_score: 30,
      overall_risk_level: 'Suspicious',
      ocr_confidence: 0.91,
      status: 'completed',
    },
    'message-image',
  )

  assert.equal(result.scanType, 'message-image')
  assert.equal(result.extractedText, 'Check https://bit.ly/demo')
  assert.equal(result.ocrConfidence, 0.91)
  assert.equal(result.riskScore, 30)
  assert.equal(result.riskLevel, 'Suspicious')
})
