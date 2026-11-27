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
} from 'lucide-react'

const SAMPLE_URL = 'http://secure-login-verify.example-bank-update.com/auth'
const SAMPLE_MESSAGE =
  'Hello! Please check your updated delivery schedule at http://bit.ly/verify-now'

const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp']
const ALLOWED_IMAGE_EXTS = ['.jpg', '.jpeg', '.png', '.webp']
const MAX_IMAGE_BYTES = 5 * 1024 * 1024

/**
 * ScannerCard provides the two scanner modes (URL Scanner & Message Scanner),
 * including image/screenshot drag-and-drop upload for OCR in Message Scanner mode.
 */
export default function ScannerCard({
  activeMode,
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

  const handleSubmit = (event) => {
    event.preventDefault()
    onScan()
  }

  const handleLoadSample = () => {
    if (!isUrlMode && selectedImage) {
      onRemoveImage?.()
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
    <section id="scanner" className="mx-auto max-w-4xl px-4 sm:px-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/75 p-5 shadow-2xl shadow-blue-950/30 sm:p-7">
        {/* Scanner mode tabs */}
        <div
          role="tablist"
          aria-label="Scanner modes"
          className="mb-5 grid grid-cols-2 gap-2 rounded-xl border border-slate-800 bg-slate-950/80 p-1.5"
        >
          <button
            type="button"
            role="tab"
            aria-selected={isUrlMode}
            disabled={isScanning}
            onClick={() => onModeChange('url')}
            className={`flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition ${
              isUrlMode
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/25'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Link2 className="h-4 w-4" />
            URL Scanner
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={!isUrlMode}
            disabled={isScanning}
            onClick={() => onModeChange('message')}
            className={`flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition ${
              !isUrlMode
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/25'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <MessageSquareWarning className="h-4 w-4" />
            Message Scanner
          </button>
        </div>

        {/* Input form */}
        <form onSubmit={handleSubmit} noValidate>
          <div className="mb-2 flex items-center justify-between">
            <label
              htmlFor="scanner-input"
              className="text-sm font-medium text-slate-200"
            >
              {isUrlMode
                ? 'Paste suspicious URL to inspect'
                : 'Paste suspicious SMS, email, or chat message'}
            </label>
            <button
              type="button"
              onClick={handleLoadSample}
              className="text-xs font-medium text-blue-400 transition hover:text-blue-300"
            >
              Load example
            </button>
          </div>

          <textarea
            id="scanner-input"
            rows={isUrlMode ? 3 : 4}
            maxLength={maxLength}
            value={inputValue}
            disabled={isScanning || (!isUrlMode && Boolean(selectedImage))}
            onChange={(e) => onInputChange(e.target.value)}
            placeholder={
              isUrlMode
                ? 'e.g., https://login-verify-account.example.com/security-check'
                : selectedImage
                  ? 'Image selected below — remove the image to type a message instead.'
                  : 'e.g., Hello! Please check your delivery update at https://bit.ly/example'
            }
            className="w-full resize-y rounded-xl border border-slate-700/80 bg-slate-950/90 px-4 py-3 text-sm text-slate-100 placeholder-slate-500 transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none disabled:opacity-60"
          />

          {/* Image / Screenshot OCR Upload Area (Message Scanner only) */}
          {!isUrlMode && (
            <div className="mt-4">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-xs font-medium text-slate-300">
                  Or upload a screenshot / image (JPG, PNG, WEBP — max 5 MB)
                </span>
              </div>

              {!selectedImage ? (
                <div
                  onDragOver={(e) => {
                    e.preventDefault()
                    setIsDragging(true)
                  }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={handleDrop}
                  className={`flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-4 py-5 text-center transition ${
                    isDragging
                      ? 'border-blue-400 bg-blue-500/10'
                      : 'border-slate-700/80 bg-slate-950/60 hover:border-blue-500/50'
                  }`}
                >
                  <Upload className="h-6 w-6 text-blue-400" />
                  <p className="mt-2 text-xs text-slate-300">
                    Drag &amp; drop a message screenshot here, or{' '}
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
                <div className="flex flex-col gap-3 rounded-xl border border-slate-700/80 bg-slate-950/80 p-3.5 sm:flex-row sm:items-center">
                  {imagePreviewUrl && (
                    <img
                      src={imagePreviewUrl}
                      alt="Uploaded screenshot preview"
                      className="h-24 w-36 shrink-0 rounded-lg border border-slate-800 object-contain bg-slate-900"
                    />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
                      <ImageIcon className="h-4 w-4 shrink-0 text-blue-400" />
                      <span className="truncate">{selectedImage.name}</span>
                    </div>
                    <p className="mt-1 text-[11px] text-slate-400">
                      {(selectedImage.size / 1024).toFixed(1)} KB • Ready for OCR &amp; URL extraction
                    </p>
                    <div className="mt-2.5 flex flex-wrap gap-2">
                      <button
                        type="button"
                        disabled={isScanning}
                        onClick={() => fileInputRef.current?.click()}
                        className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:border-blue-500/40"
                      >
                        Replace Image
                      </button>
                      <button
                        type="button"
                        disabled={isScanning}
                        onClick={onRemoveImage}
                        className="inline-flex items-center gap-1 rounded-lg border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-[11px] font-medium text-rose-300 hover:bg-rose-500/20"
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

          {/* Validation error or character count */}
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs">
            {validationError ? (
              <span className="inline-flex items-center gap-1.5 text-rose-400">
                <AlertCircle className="h-3.5 w-3.5" />
                {validationError}
              </span>
            ) : (
              <span className="text-slate-500">
                {isUrlMode
                  ? 'URL-text inspection by default; optional read-only inspection is SSRF-protected.'
                  : 'URL-first mode: extracts and scans links from typed text or uploaded screenshots.'}
              </span>
            )}
            <span className="text-slate-500">
              {inputValue.length} / {maxLength}
            </span>
          </div>

          {/* Optional Isolated Read-Only Website Inspection toggle */}
          <label className="mt-4 flex cursor-pointer items-start gap-2.5 rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-xs text-slate-300 transition hover:border-blue-500/40">
            <input
              type="checkbox"
              checked={inspectWebsite}
              disabled={isScanning}
              onChange={(e) => onToggleInspectWebsite?.(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-500 focus:ring-blue-500"
            />
            <span>
              <strong className="text-slate-100">
                Enable Isolated Read-Only Website Inspection
              </strong>
              <span className="block text-[11px] text-slate-400">
                Inspects HTML scripts, tracking pixels, cookies, and forms in a read-only
                sandbox (blocks private IPs, localhost, metadata endpoints, downloads, and form
                submissions).
              </span>
            </span>
          </label>

          {/* Action buttons */}
          <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <button
              type="submit"
              disabled={isScanning}
              className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-blue-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-blue-600/25 transition hover:bg-blue-500 focus:ring-2 focus:ring-blue-400 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
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
                className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-slate-700 bg-slate-800/60 px-4 py-2.5 text-xs font-medium text-slate-300 transition hover:bg-slate-800 hover:text-white disabled:opacity-60"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Clear
              </button>
            )}
          </div>
        </form>
      </div>
    </section>
  )
}
