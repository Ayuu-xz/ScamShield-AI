import { validateUrlInput } from './src/api.js'

const apiStatusEl = document.getElementById('api-status')
const currentUrlEl = document.getElementById('current-url')
const scanCurrentBtn = document.getElementById('scan-current-btn')
const manualForm = document.getElementById('manual-form')
const manualUrlInput = document.getElementById('manual-url-input')
const scanManualBtn = document.getElementById('scan-manual-btn')
const loadingBox = document.getElementById('loading-box')
const errorBox = document.getElementById('error-box')
const resultCard = document.getElementById('result-card')
const scoreValueEl = document.getElementById('score-value')
const scoreBarEl = document.getElementById('score-bar')
const riskBadgeEl = document.getElementById('risk-badge')
const summaryTextEl = document.getElementById('summary-text')
const mlBoxEl = document.getElementById('ml-box')
const mlTextEl = document.getElementById('ml-text')
const indicatorsListEl = document.getElementById('indicators-list')
const recommendationsListEl = document.getElementById('recommendations-list')
const langButtons = Array.from(document.querySelectorAll('.lang-btn'))

let activeTabUrl = ''
let currentResult = null
let selectedLang = 'en'

function setScanningState(isScanning) {
  scanCurrentBtn.disabled = isScanning || !activeTabUrl
  scanManualBtn.disabled = isScanning
  loadingBox.classList.toggle('hidden', !isScanning)
  if (isScanning) {
    errorBox.classList.add('hidden')
    resultCard.classList.add('hidden')
  }
}

function showError(message) {
  errorBox.textContent = message
  errorBox.classList.remove('hidden')
  resultCard.classList.add('hidden')
}

function getBadgeClass(level) {
  if (level === 'Dangerous') return 'badge-danger'
  if (level === 'Suspicious') return 'badge-suspicious'
  if (level === 'Safe' || level === 'No strong indicators detected') return 'badge-safe'
  return 'badge-neutral'
}

function getBarColor(level) {
  if (level === 'Dangerous') return '#f43f5e'
  if (level === 'Suspicious') return '#f59e0b'
  if (level === 'Safe' || level === 'No strong indicators detected') return '#10b981'
  return '#64748b'
}

function renderList(listEl, items, emptyMessage) {
  listEl.replaceChildren()
  if (!items || items.length === 0) {
    const li = document.createElement('li')
    li.textContent = emptyMessage
    listEl.appendChild(li)
    return
  }
  for (const text of items) {
    const li = document.createElement('li')
    li.textContent = text
    listEl.appendChild(li)
  }
}

function renderResult() {
  if (!currentResult) return

  const score = currentResult.risk_score ?? 0
  const level = currentResult.risk_level || 'Inspection unavailable'
  scoreValueEl.textContent = String(score)
  scoreBarEl.style.width = `${score}%`
  scoreBarEl.style.backgroundColor = getBarColor(level)

  riskBadgeEl.textContent = level
  riskBadgeEl.className = `risk-badge ${getBadgeClass(level)}`

  const multi = currentResult.multilingual_explanations || {}
  const localized = multi[selectedLang] || multi.en || null

  summaryTextEl.textContent =
    localized?.summary ||
    currentResult.inspection_note ||
    'Analysis completed.'

  if (currentResult.ml_analysis) {
    const ml = currentResult.ml_analysis
    const conf =
      ml.calibrated && typeof ml.confidence === 'number'
        ? ` (${Math.round(ml.confidence * 100)}%)`
        : ''
    mlTextEl.textContent = `${ml.prediction}${conf}`
    mlBoxEl.classList.remove('hidden')
  } else {
    mlBoxEl.classList.add('hidden')
  }

  const ruleNames = currentResult.detected_indicators || []
  const ruleExps = localized?.explanations || currentResult.explanations || []
  const combinedIndicators = ruleNames.map((name, idx) =>
    ruleExps[idx] ? `${name}: ${ruleExps[idx]}` : name,
  )
  renderList(
    indicatorsListEl,
    combinedIndicators,
    'No suspicious URL-text indicators detected.',
  )

  const recs = localized?.recommendations || currentResult.recommendations || []
  renderList(recommendationsListEl, recs, 'Verify the domain before entering credentials.')

  resultCard.classList.remove('hidden')
}

async function runScan(targetUrl) {
  const check = validateUrlInput(targetUrl)
  if (!check.valid) {
    showError(check.error)
    return
  }

  setScanningState(true)
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'SCAN_URL',
      url: check.url,
    })
    if (!response?.success) {
      throw new Error(response?.error || 'Scan failed.')
    }
    currentResult = response.data
    renderResult()
  } catch (err) {
    showError(err.message || 'Unable to complete scan.')
  } finally {
    setScanningState(false)
  }
}

async function initPopup() {
  // Check backend health
  chrome.runtime.sendMessage({ type: 'CHECK_HEALTH' }, (response) => {
    if (chrome.runtime.lastError || !response?.success || !response?.result?.ok) {
      apiStatusEl.textContent = 'API Offline'
      apiStatusEl.className = 'api-badge api-offline'
      return
    }
    apiStatusEl.textContent = 'API Connected'
    apiStatusEl.className = 'api-badge api-ok'
  })

  // Read active tab URL without auto-scanning it
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabUrl = tabs?.[0]?.url || ''
    const check = validateUrlInput(tabUrl)
    if (check.valid) {
      activeTabUrl = check.url
      currentUrlEl.textContent = activeTabUrl
      scanCurrentBtn.disabled = false
    } else {
      activeTabUrl = ''
      currentUrlEl.textContent = tabUrl
        ? `Cannot scan internal/unsupported URL (${tabUrl.split(':')[0]}:)`
        : 'No active web URL detected'
      scanCurrentBtn.disabled = true
    }
  })
}

scanCurrentBtn.addEventListener('click', () => {
  if (activeTabUrl) {
    runScan(activeTabUrl)
  }
})

manualForm.addEventListener('submit', (event) => {
  event.preventDefault()
  runScan(manualUrlInput.value)
})

for (const btn of langButtons) {
  btn.addEventListener('click', () => {
    selectedLang = btn.dataset.lang || 'en'
    for (const other of langButtons) {
      other.classList.toggle('active', other === btn)
    }
    renderResult()
  })
}

initPopup()
