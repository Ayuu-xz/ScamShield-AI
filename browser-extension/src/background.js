import { checkBackendHealth, scanUrlWithBackend } from './api.js'

/**
 * Manifest V3 background service worker.
 * Only executes network requests when explicitly triggered by user actions in the popup.
 * Never monitors browsing history or auto-scans visited tabs.
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'CHECK_HEALTH') {
    checkBackendHealth()
      .then((result) => sendResponse({ success: true, result }))
      .catch((err) => sendResponse({ success: false, error: err.message }))
    return true
  }

  if (message?.type === 'SCAN_URL') {
    scanUrlWithBackend(message.url)
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: err.message }))
    return true
  }

  return false
})
