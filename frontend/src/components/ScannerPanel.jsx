import { useRef, useState } from 'react'
import {
  Link2,
  MessageSquareWarning,
  Search,
  Trash2,
  AlertCircle,
  Loader2,
  Upload,
  Image as ImageIcon,
  X,
  ClipboardPaste,
  Shield,
} from 'lucide-react'

const SAMPLE_URL = 'http://paypa1-secure-login.com/verify'
const SAMPLE_MESSAGE =
  'Hello! Please check your updated delivery schedule at http://bit.ly/verify-now'

const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp']
const ALLOWED_IMAGE_EXTS = ['.jpg', '.jpeg', '.png', '.webp']
const MAX_IMAGE_BYTES = 5 * 1024 * 1024

/**
 * Enterprise ScannerPanel supporting both unified (Overview) and single-mode
 * (URL Scanner / Message Scanner) views.
 */
export default function ScannerPanel({
  activeMode,
  showModeTabs = true,
  onModeChange,
  inputValue,
  onInputChange,
  selectedImage,
  imagePreviewUrl,
  onSelectImage,
  onRemoveImage,
  validationError,
  onValidationError,
  inspectWebsite = false,
  onToggleInspectWebsite,
  isScanning = false,
  onScan,
  onClear,
}) {
  const isUrlMode = activeMode === 'url'
  const maxLength = isUrlMode ? 2048 : 5000
  const fileInputRef = useRef(null)
  const [isDragging, setIsDragging] = useState(false)
  const [messageInputTab, setMessageInputTab] = useState(
    selectedImage ? 'image' : 'text',
  )

  const handleSubmit = (event) => {
    event.preventDefault()
    onScan()
  }

  const handlePasteUrl = async () => {
    try {
      const clipText = await navigator.clipboard.readText()
      if (clipText) {
        onInputChange(clipText.trim())
      }
    } catch {
      onValidationError?.('Clipboard access denied — please paste with Ctrl+V.')
    }
  }

  const handleLoadSample = () => {
    if (!isUrlMode) {
      if (selectedImage) onRemoveImage?.()
      setMessageInputTab('text')
    }
    onInputChange(isUrlMode ? SAMPLE_URL : SAMPLE_MESSAGE)
  }

  const validateAndAcceptFile = (file) => {
    if (!file) return
    const lowerName = file.name.toLowerCase()
    const hasValidExt = ALLOWED_IMAGE_EXTS.some((ext) => lowerName.endsWith(ext))
    const hasValidMime = !file.type || ALLOWED_IMAGE_TYPES.includes(file.type)

    if (!hasValidExt || !hasValidMime) {
      onValidationError?.(
        'Unsupported image format. Please upload a JPG, JPEG, PNG, or WEBP screenshot.',
      )
      return
    }

    if (file.size > MAX_IMAGE_BYTES) {
      onValidationError?.('Image size exceeds the 5 MB limit.')
      return
    }

    setMessageInputTab('image')
    onSelectImage?.(file)
  }

  const handleFileChange = (event) => {
    const file = event.target.files?.[0]
    validateAndAcceptFile(file)
    event.target.value = ''
  }

  const handleDrop = (event) => {
    event.preventDefault()
    setIsDragging(false)
    if (isScanning) return
    const file = event.dataTransfer?.files?.[0]
    validateAndAcceptFile(file)
  }

  return (
    <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5 shadow-lg shadow-black/20 sm:p-6">
      {/* Mode selector (Overview) */}
      {showModeTabs && (
        <div
          role="tablist"
          aria-label="Scanner modes"
          className="mb-5 grid grid-cols-2 gap-1.5 rounded-lg border border-slate-800 bg-[#090d16] p-1"
        >
          <button
            type="button"
            role="tab"
            aria-selected={isUrlMode}
            disabled={isScanning}
            onClick={() => onModeChange('url')}
            className={`flex items-center justify-center gap-2 rounded-md px-3 py-2 text-xs font-semibold transition-colors ${
              isUrlMode
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
            }`}
          >
            <Link2 className="h-3.5 w-3.5" />
            URL Scanner
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={!isUrlMode}
            disabled={isScanning}
            onClick={() => onModeChange('message')}
            className={`flex items-center justify-center gap-2 rounded-md px-3 py-2 text-xs font-semibold transition-colors ${
              !isUrlMode
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
            }`}
          >
            <MessageSquareWarning className="h-3.5 w-3.5" />
            Message Scanner
          </button>
        </div>
      )}

      {/* Message Scanner sub-tabs: Typed Message vs Screenshot/Image OCR */}
      {!isUrlMode && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <div className="inline-flex rounded-lg border border-slate-800 bg-[#090d16] p-1 text-xs">
            <button
              type="button"
              disabled={isScanning}
              onClick={() => {
                setMessageInputTab('text')
                if (selectedImage) onRemoveImage?.()
              }}
              className={`rounded-md px-3 py-1.5 font-medium transition-colors ${
                messageInputTab === 'text'
                  ? 'bg-[#131c2e] text-white ring-1 ring-slate-700'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Typed Message
            </button>
            <button
              type="button"
              disabled={isScanning}
              onClick={() => setMessageInputTab('image')}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition-colors ${
                messageInputTab === 'image'
                  ? 'bg-[#131c2e] text-white ring-1 ring-slate-700'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ImageIcon className="h-3.5 w-3.5" />
              Screenshot / Image OCR
            </button>
          </div>

          <button
            type="button"
            onClick={handleLoadSample}
            className="text-xs font-medium text-blue-400 transition-colors hover:text-blue-300"
          >
            Load example
          </button>
        </div>
      )}

      <form onSubmit={handleSubmit} noValidate>
        {isUrlMode ? (
          <div>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <label htmlFor="scanner-input" className="text-xs font-medium text-slate-300">
                Target URL
              </label>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handlePasteUrl}
                  className="inline-flex items-center gap-1 text-xs font-medium text-slate-300 transition-colors hover:text-blue-400"
                >
                  <ClipboardPaste className="h-3.5 w-3.5" />
                  Paste URL
                </button>
                <button
                  type="button"
                  onClick={handleLoadSample}
                  className="text-xs font-medium text-blue-400 transition-colors hover:text-blue-300"
                >
                  Load example
                </button>
              </div>
            </div>

            <input
              id="scanner-input"
              type="text"
              maxLength={maxLength}
              value={inputValue}
              disabled={isScanning}
              onChange={(e) => onInputChange(e.target.value)}
              placeholder="https://example.com/login"
              className="w-full rounded-lg border border-slate-700/80 bg-[#090d16] px-3.5 py-2.5 font-mono text-sm text-slate-100 placeholder-slate-500 transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-500/25 focus:outline-none disabled:opacity-60"
            />
          </div>
        ) : messageInputTab === 'text' && !selectedImage ? (
          <div>
            <label htmlFor="scanner-input" className="mb-2 block text-xs font-medium text-slate-300">
              Message Content (URL-First Analysis)
            </label>
            <textarea
              id="scanner-input"
              rows={4}
              maxLength={maxLength}
              value={inputValue}
              disabled={isScanning}
              onChange={(e) => onInputChange(e.target.value)}
              placeholder="Paste SMS, email, or chat message containing a link to inspect..."
              className="w-full resize-y rounded-lg border border-slate-700/80 bg-[#090d16] px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-500/25 focus:outline-none disabled:opacity-60"
            />
          </div>
        ) : (
          <div>
            {!selectedImage ? (
              <div
                onDragOver={(e) => {
                  e.preventDefault()
                  setIsDragging(true)
                }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={handleDrop}
                className={`flex flex-col items-center justify-center rounded-lg border-2 border-dashed px-4 py-7 text-center transition-colors ${
                  isDragging
                    ? 'border-blue-400 bg-blue-500/10'
                    : 'border-slate-700/80 bg-[#090d16] hover:border-blue-500/50'
                }`}
              >
                <Upload className="h-6 w-6 text-blue-400" />
                <p className="mt-2 text-xs text-slate-300">
                  Drag &amp; drop a screenshot (JPG, PNG, WEBP — max 5 MB), or{' '}
                  <button
                    type="button"
                    disabled={isScanning}
                    onClick={() => fileInputRef.current?.click()}
                    className="font-semibold text-blue-400 underline underline-offset-2 hover:text-blue-300"
                  >
                    browse files
                  </button>
                </p>
                <p className="mt-1 text-[11px] text-slate-500">
                  OCR extracts text and inspects any URLs found inside the image.
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp"
                  onChange={handleFileChange}
                  aria-label="Upload screenshot or image for OCR"
                  className="hidden"
                />
              </div>
            ) : (
              <div className="flex flex-col gap-3 rounded-lg border border-slate-700/80 bg-[#090d16] p-3.5 sm:flex-row sm:items-center">
                {imagePreviewUrl && (
                  <img
                    src={imagePreviewUrl}
                    alt="Uploaded screenshot preview"
                    className="h-24 w-36 shrink-0 rounded-md border border-slate-800 bg-slate-900 object-contain"
                  />
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
                    <ImageIcon className="h-4 w-4 shrink-0 text-blue-400" />
                    <span className="truncate">{selectedImage.name}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-400">
                    {(selectedImage.size / 1024).toFixed(1)} KB • Ready for OCR &amp; URL analysis
                  </p>
                  <div className="mt-2.5 flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={isScanning}
                      onClick={() => fileInputRef.current?.click()}
                      className="rounded-md border border-slate-700 bg-[#131c2e] px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:border-blue-500/40"
                    >
                      Replace
                    </button>
                    <button
                      type="button"
                      disabled={isScanning}
                      onClick={onRemoveImage}
                      className="inline-flex items-center gap-1 rounded-md border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-[11px] font-medium text-rose-300 hover:bg-rose-500/20"
                    >
                      <X className="h-3 w-3" />
                      Remove
                    </button>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp"
                      onChange={handleFileChange}
                      aria-label="Replace screenshot or image for OCR"
                      className="hidden"
                    />
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Validation error & character counter */}
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs">
          {validationError ? (
            <span className="inline-flex items-center gap-1.5 text-rose-400">
              <AlertCircle className="h-3.5 w-3.5" />
              {validationError}
            </span>
          ) : (
            <span className="text-[11px] text-slate-500">
              {isUrlMode
                ? 'URL-text inspection by default; links are never executed or clicked.'
                : 'Ordinary message wording does not affect URL-based risk scores.'}
            </span>
          )}
          {(isUrlMode || (messageInputTab === 'text' && !selectedImage)) && (
            <span className="text-[11px] text-slate-500">
              {inputValue.length} / {maxLength}
            </span>
          )}
        </div>

        {/* Isolated Website Inspection Toggle */}
        <label className="mt-3.5 flex cursor-pointer items-start gap-2.5 rounded-lg border border-slate-800/90 bg-[#090d16] p-3 text-xs text-slate-300 transition-colors hover:border-blue-500/40">
          <input
            type="checkbox"
            checked={inspectWebsite}
            disabled={isScanning}
            onChange={(e) => onToggleInspectWebsite?.(e.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-500 focus:ring-blue-500"
          />
          <span className="flex-1">
            <span className="inline-flex items-center gap-1.5 font-medium text-slate-200">
              <Shield className="h-3.5 w-3.5 text-blue-400" />
              Enable Isolated Read-Only Website Inspection
            </span>
            <span className="mt-0.5 block text-[11px] text-slate-400">
              Inspects HTML scripts, pixels, cookies, and forms in an SSRF-protected sandbox
              (blocks private IPs, localhost, metadata endpoints, and downloads).
            </span>
          </span>
        </label>

        {/* Actions */}
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <button
            type="submit"
            disabled={isScanning}
            className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-xs font-semibold text-white transition-colors hover:bg-blue-500 focus:ring-2 focus:ring-blue-400 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto sm:text-sm"
          >
            {isScanning ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                {selectedImage && !isUrlMode ? 'Running OCR & Scanning...' : 'Scanning...'}
              </>
            ) : (
              <>
                <Search className="h-4 w-4" />
                {isUrlMode
                  ? 'Scan URL'
                  : selectedImage
                    ? 'Extract & Scan Image'
                    : 'Scan Message'}
              </>
            )}
          </button>

          {(inputValue.length > 0 || (!isUrlMode && selectedImage)) && (
            <button
              type="button"
              disabled={isScanning}
              onClick={onClear}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-[#131c2e] px-3.5 py-2 text-xs font-medium text-slate-300 transition-colors hover:bg-slate-800 hover:text-white disabled:opacity-60"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear
            </button>
          )}
        </div>
      </form>
    </div>
  )
}
