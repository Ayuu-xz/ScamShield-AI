import { useCallback, useEffect, useState } from 'react'
import LandingPage from './components/LandingPage.jsx'
import Sidebar from './components/Sidebar.jsx'
import TopHeader from './components/TopHeader.jsx'
import OverviewPage from './components/OverviewPage.jsx'
import ScannerPanel from './components/ScannerPanel.jsx'
import DetectionResultCard from './components/DetectionResultCard.jsx'
import ScanHistoryPage from './components/ScanHistoryPage.jsx'
import AnalyticsPage from './components/AnalyticsPage.jsx'
import ReportsPage from './components/ReportsPage.jsx'
import SettingsPage from './components/SettingsPage.jsx'
import HelpResourcesPage from './components/HelpResourcesPage.jsx'
import { ToastBanner } from './components/ui/StatusPrimitives.jsx'
import {
  API_BASE_URL,
  fetchHealthCheck,
  scanMessage,
  scanMessageImage,
  scanUrl,
} from './services/api.js'

const PREFS_STORAGE_KEY = 'scamshield_prefs_v1'
const DEFAULT_PREFS = {
  defaultLanguage: 'en',
  defaultInspectWebsite: false,
  defaultExpandTechnical: false,
}

function loadPreferences() {
  try {
    const raw = localStorage.getItem(PREFS_STORAGE_KEY)
    if (!raw) return DEFAULT_PREFS
    return { ...DEFAULT_PREFS, ...JSON.parse(raw) }
  } catch {
    return DEFAULT_PREFS
  }
}

/**
 * Root commercial SaaS shell for ScamShield AI.
 */
export default function App() {
  const [preferences, setPreferences] = useState(loadPreferences)
  const [showLanding, setShowLanding] = useState(true)
  const [activePage, setActivePage] = useState('overview')
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [selectedReportId, setSelectedReportId] = useState(null)
  const [toast, setToast] = useState(null)

  const [activeMode, setActiveMode] = useState('url')
  const [inputValue, setInputValue] = useState('')
  const [selectedImage, setSelectedImage] = useState(null)
  const [imagePreviewUrl, setImagePreviewUrl] = useState('')
  const [validationError, setValidationError] = useState('')
  const [inspectWebsite, setInspectWebsite] = useState(
    () => loadPreferences().defaultInspectWebsite,
  )
  const [isScanning, setIsScanning] = useState(false)
  const [apiError, setApiError] = useState('')
  const [scanResult, setScanResult] = useState(null)

  const [healthState, setHealthState] = useState({
    status: 'loading',
    data: null,
    error: null,
  })

  const showToast = useCallback((nextToast) => {
    setToast(nextToast)
  }, [])

  useEffect(() => {
    if (!toast) return
    const timer = setTimeout(() => setToast(null), 4000)
    return () => clearTimeout(timer)
  }, [toast])

  const updatePreferences = (patch) => {
    setPreferences((prev) => {
      const next = { ...prev, ...patch }
      try {
        localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(next))
      } catch {
        // Ignore storage quota errors
      }
      if ('defaultInspectWebsite' in patch) {
        setInspectWebsite(Boolean(patch.defaultInspectWebsite))
      }
      return next
    })
    showToast({ type: 'success', message: 'Settings saved.' })
  }

  const resetPreferences = () => {
    setPreferences(DEFAULT_PREFS)
    setInspectWebsite(DEFAULT_PREFS.defaultInspectWebsite)
    try {
      localStorage.removeItem(PREFS_STORAGE_KEY)
    } catch {
      // Ignore storage errors
    }
    showToast({ type: 'success', message: 'Settings reset to defaults.' })
  }

  const checkBackendHealth = useCallback(async (signal) => {
    setHealthState((prev) => ({ ...prev, status: 'loading', error: null }))
    try {
      const data = await fetchHealthCheck(signal)
      setHealthState({ status: 'connected', data, error: null })
    } catch (err) {
      if (err.name === 'AbortError') return
      setHealthState({
        status: 'disconnected',
        data: null,
        error: err.message || 'Unable to reach backend API',
      })
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    checkBackendHealth(controller.signal)
    return () => controller.abort()
  }, [checkBackendHealth])

  useEffect(() => {
    return () => {
      if (imagePreviewUrl) {
        URL.revokeObjectURL(imagePreviewUrl)
      }
    }
  }, [imagePreviewUrl])

  const clearSelectedImage = () => {
    if (imagePreviewUrl) {
      URL.revokeObjectURL(imagePreviewUrl)
    }
    setSelectedImage(null)
    setImagePreviewUrl('')
  }

  const handleSelectImage = (file) => {
    clearSelectedImage()
    setSelectedImage(file)
    setImagePreviewUrl(URL.createObjectURL(file))
    setValidationError('')
    setApiError('')
  }

  const handleNavigate = (pageId) => {
    if (isScanning) return
    setShowLanding(false)
    setActivePage(pageId)
    if (pageId === 'url-scanner' && activeMode !== 'url') {
      setActiveMode('url')
      setInputValue('')
      clearSelectedImage()
      setValidationError('')
      setApiError('')
    } else if (pageId === 'message-scanner' && activeMode !== 'message') {
      setActiveMode('message')
      setInputValue('')
      clearSelectedImage()
      setValidationError('')
      setApiError('')
    }
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const handleOpenReport = (scanId) => {
    setSelectedReportId(scanId)
    handleNavigate('reports')
  }

  const handleModeChange = (mode) => {
    if (isScanning) return
    setActiveMode(mode)
    setInputValue('')
    clearSelectedImage()
    setValidationError('')
    setApiError('')
    setScanResult(null)
  }

  const handleInputChange = (value) => {
    setInputValue(value)
    if (validationError) setValidationError('')
    if (apiError) setApiError('')
  }

  const handleReviewExtractedText = (text) => {
    clearSelectedImage()
    setActiveMode('message')
    setInputValue(text)
    setValidationError('')
    setApiError('')
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const handleScan = async () => {
    if (isScanning) return

    if (activeMode === 'message' && selectedImage) {
      setValidationError('')
      setApiError('')
      setIsScanning(true)
      setScanResult(null)
      try {
        const result = await scanMessageImage(selectedImage, inspectWebsite)
        setScanResult(result)
      } catch (err) {
        setApiError(
          err.message ||
            'Failed to process the uploaded image. Please check if the API is running.',
        )
      } finally {
        setIsScanning(false)
      }
      return
    }

    const trimmed = inputValue.trim()
    if (!trimmed) {
      setValidationError(
        activeMode === 'url'
          ? 'Please enter a URL to inspect.'
          : 'Please enter a message or upload an image to inspect.',
      )
      return
    }

    const maxLength = activeMode === 'url' ? 2048 : 5000
    if (trimmed.length > maxLength) {
      setValidationError(
        `${activeMode === 'url' ? 'URL' : 'Message'} cannot exceed ${maxLength} characters.`,
      )
      return
    }

    setValidationError('')
    setApiError('')
    setIsScanning(true)
    setScanResult(null)

    try {
      const result =
        activeMode === 'url'
          ? await scanUrl(trimmed, inspectWebsite)
          : await scanMessage(trimmed, inspectWebsite)
      setScanResult(result)
    } catch (err) {
      setApiError(
        err.message ||
          'Failed to reach the backend scanner. Please check if the API is running.',
      )
    } finally {
      setIsScanning(false)
    }
  }

  const handleClear = () => {
    setInputValue('')
    clearSelectedImage()
    setValidationError('')
    setApiError('')
    setScanResult(null)
  }

  if (showLanding) {
    return (
      <LandingPage
        onStartScanning={() => handleNavigate('overview')}
        onNavigateConsole={(pageId) => handleNavigate(pageId)}
      />
    )
  }

  const scannerProps = {
    activeMode,
    onModeChange: handleModeChange,
    inputValue,
    onInputChange: handleInputChange,
    selectedImage,
    imagePreviewUrl,
    onSelectImage: handleSelectImage,
    onRemoveImage: clearSelectedImage,
    validationError,
    onValidationError: setValidationError,
    inspectWebsite,
    onToggleInspectWebsite: setInspectWebsite,
    isScanning,
    onScan: handleScan,
    onClear: handleClear,
  }

  const renderPage = () => {
    if (activePage === 'url-scanner') {
      return (
        <div className="space-y-6">
          <div>
            <h2 className="text-lg font-bold text-[#F1F5F9] sm:text-xl">URL Scanner</h2>
            <p className="mt-0.5 text-xs text-[#94A3B8]">
              Inspect URLs for phishing, look-alike domains, redirects, trackers, and file indicators.
            </p>
          </div>
          <ScannerPanel {...scannerProps} activeMode="url" showModeTabs={false} />
          <DetectionResultCard
            scanResult={scanResult}
            isScanning={isScanning}
            apiError={apiError}
            activeMode="url"
            defaultLanguage={preferences.defaultLanguage}
            defaultExpandTechnical={preferences.defaultExpandTechnical}
            onOpenReport={handleOpenReport}
            onToast={showToast}
          />
        </div>
      )
    }

    if (activePage === 'message-scanner') {
      return (
        <div className="space-y-6">
          <div>
            <h2 className="text-lg font-bold text-[#F1F5F9] sm:text-xl">Message Scanner</h2>
            <p className="mt-0.5 text-xs text-[#94A3B8]">
              URL-first message inspection with screenshot OCR extraction and URL risk analysis.
            </p>
          </div>
          <ScannerPanel {...scannerProps} activeMode="message" showModeTabs={false} />
          <DetectionResultCard
            scanResult={scanResult}
            isScanning={isScanning}
            apiError={apiError}
            activeMode="message"
            defaultLanguage={preferences.defaultLanguage}
            defaultExpandTechnical={preferences.defaultExpandTechnical}
            onReviewExtractedText={handleReviewExtractedText}
            onOpenReport={handleOpenReport}
            onToast={showToast}
          />
        </div>
      )
    }

    if (activePage === 'history') {
      return (
        <ScanHistoryPage
          onNavigate={handleNavigate}
          onOpenReport={handleOpenReport}
          onToast={showToast}
        />
      )
    }

    if (activePage === 'analytics') {
      return <AnalyticsPage onNavigate={handleNavigate} />
    }

    if (activePage === 'reports') {
      return (
        <ReportsPage
          selectedScanId={selectedReportId}
          onSelectScanId={setSelectedReportId}
          onNavigate={handleNavigate}
          onToast={showToast}
        />
      )
    }

    if (activePage === 'settings') {
      return (
        <SettingsPage
          preferences={preferences}
          onUpdatePreferences={updatePreferences}
          onResetPreferences={resetPreferences}
          healthState={healthState}
          apiBaseUrl={API_BASE_URL}
        />
      )
    }

    if (activePage === 'help') {
      return <HelpResourcesPage />
    }

    return (
      <OverviewPage
        scannerProps={scannerProps}
        scanResult={scanResult}
        isScanning={isScanning}
        apiError={apiError}
        defaultLanguage={preferences.defaultLanguage}
        defaultExpandTechnical={preferences.defaultExpandTechnical}
        onReviewExtractedText={handleReviewExtractedText}
        onNavigate={handleNavigate}
        onOpenReport={handleOpenReport}
        onToast={showToast}
      />
    )
  }

  return (
    <div className="flex min-h-screen bg-[#0B1120] text-[#F1F5F9]">
      <Sidebar
        activePage={activePage}
        onNavigate={handleNavigate}
        onGoHome={() => setShowLanding(true)}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopHeader
          activePage={activePage}
          healthState={healthState}
          onRefreshHealth={() => checkBackendHealth()}
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          onGoHome={() => setShowLanding(true)}
        />

        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:px-6">
          {renderPage()}
        </main>

        <footer className="border-t border-[#263449] bg-[#0F172A] px-4 py-4 text-[11px] text-[#94A3B8] sm:px-6">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-2">
            <span>ScamShield AI — Defensive URL &amp; Message Inspection</span>
            <span>API: {API_BASE_URL}</span>
          </div>
        </footer>
      </div>

      <ToastBanner toast={toast} onDismiss={() => setToast(null)} />
    </div>
  )
}
