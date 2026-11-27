import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Edit3,
  Globe,
  Link2,
  MessageSquareWarning,
  Image as ImageIcon,
  ShieldAlert,
  Bug,
  ArrowRightLeft,
  FileWarning,
  Search,
  Cpu,
  Languages,
  Download,
  FileText,
} from 'lucide-react'
import {
  EmptyState,
  LoadingState,
  RiskScoreDisplay,
  StatusBadge,
} from './ui/StatusPrimitives.jsx'
import { downloadScanReport } from '../services/api.js'

const LANG_OPTIONS = [
  { id: 'en', label: 'English' },
  { id: 'hi', label: 'हिंदी' },
  { id: 'hinglish', label: 'Hinglish' },
]

function formatTimestamp(isoString) {
  if (!isoString) return ''
  try {
    return new Date(isoString).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  } catch {
    return isoString
  }
}

function FindingCategorySection({ title, icon: Icon, items, emptyLabel = 'Not detected' }) {
  return (
    <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-3.5">
      <div className="flex items-center justify-between gap-2">
        <span className="inline-flex items-center gap-2 text-xs font-semibold text-[#F1F5F9]">
          <Icon className="h-3.5 w-3.5 text-[#3B82F6]" />
          {title}
        </span>
        {items.length === 0 && <StatusBadge label={emptyLabel} />}
      </div>

      {items.length > 0 && (
        <div className="mt-2.5 space-y-2">
          {items.map((item, idx) => (
            <div
              key={`${item.rule_id}-${idx}`}
              className="rounded-md border border-[#263449] bg-[#111C30] p-2.5 text-xs"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-[#F1F5F9]">{item.rule_name}</span>
                <div className="flex items-center gap-1.5">
                  {item.score_contribution > 0 && (
                    <span className="rounded border border-[#F59E0B]/35 bg-[#F59E0B]/12 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-[#FCD34D]">
                      +{item.score_contribution} pts
                    </span>
                  )}
                  <StatusBadge label={item.detection_status} />
                </div>
              </div>
              {item.evidence && (
                <p className="mt-1 break-all font-mono text-[11px] text-[#94A3B8]">
                  {item.evidence}
                </p>
              )}
              <p className="mt-1 text-[11px] leading-relaxed text-[#94A3B8]">
                {item.explanation}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/**
 * Refined dark-mode DetectionResultCard with clear visual hierarchy and expandable technical details.
 */
export default function DetectionResultCard({
  scanResult,
  isScanning,
  apiError,
  activeMode,
  defaultLanguage = 'en',
  defaultExpandTechnical = false,
  onReviewExtractedText,
  onOpenReport,
  onToast,
}) {
  const [selectedLang, setSelectedLang] = useState(defaultLanguage)
  const [showTechnical, setShowTechnical] = useState(defaultExpandTechnical)
  const [showUrls, setShowUrls] = useState(false)

  useEffect(() => {
    setSelectedLang(defaultLanguage)
  }, [defaultLanguage])

  useEffect(() => {
    setShowTechnical(defaultExpandTechnical)
  }, [defaultExpandTechnical, scanResult?.scanId])

  if (isScanning) {
    return (
      <LoadingState
        message={
          activeMode === 'url'
            ? 'Analyzing URL structure and defensive signals...'
            : 'Inspecting message and embedded links...'
        }
        subtext="Read-only evaluation in progress; submitted links are never executed."
      />
    )
  }

  if (apiError) {
    return (
      <div
        role="alert"
        className="rounded-[10px] border border-[#EF4444]/40 bg-[#1F1218] p-4"
      >
        <div className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-[#EF4444]" />
          <div>
            <h3 className="text-sm font-semibold text-[#FCA5A5]">Scan Error</h3>
            <p className="mt-1 text-xs leading-relaxed text-[#FCA5A5]/90">{apiError}</p>
          </div>
        </div>
      </div>
    )
  }

  if (!scanResult) {
    return (
      <EmptyState
        icon={Search}
        title="Ready to Inspect"
        description={
          activeMode === 'url'
            ? 'Enter a URL above to evaluate phishing, redirect, file-extension, and ML signals.'
            : 'Paste a message or upload a screenshot above to extract and analyze embedded URLs.'
        }
      />
    )
  }

  const isUrlResult = scanResult.scanType === 'url'
  const isImageResult = scanResult.scanType === 'message-image'
  const domainIntel = scanResult.domainIntelligence
  const localizedBundle =
    scanResult.multilingualExplanations?.[selectedLang] ||
    scanResult.multilingualExplanations?.en ||
    null

  const handleExport = async (format) => {
    if (!scanResult.scanId) return
    try {
      await downloadScanReport(scanResult.scanId, format)
      onToast?.({
        type: 'success',
        message: `Downloaded ${format.toUpperCase()} report for Scan #${scanResult.scanId}.`,
      })
    } catch (err) {
      onToast?.({
        type: 'error',
        message: err.message || `Failed to export ${format.toUpperCase()} report.`,
      })
    }
  }

  return (
    <div className="space-y-4 rounded-[10px] border border-[#263449] bg-[#111C30] p-5 sm:p-6">
      {/* Header metadata + Export + Language switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#263449] pb-3.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-md border border-[#263449] bg-[#172338] px-2.5 py-1 text-xs font-semibold text-[#F1F5F9]">
            {isUrlResult ? (
              <Link2 className="h-3.5 w-3.5 text-[#3B82F6]" />
            ) : isImageResult ? (
              <ImageIcon className="h-3.5 w-3.5 text-[#3B82F6]" />
            ) : (
              <MessageSquareWarning className="h-3.5 w-3.5 text-[#3B82F6]" />
            )}
            {isUrlResult ? 'URL Scan' : isImageResult ? 'Image OCR Scan' : 'Message Scan'}
          </span>
          <StatusBadge label={scanResult.inspectionStatus} />
          <StatusBadge label={scanResult.reputationStatus} />
        </div>

        <div className="flex flex-wrap items-center gap-2.5 text-xs text-[#94A3B8]">
          <div
            role="group"
            aria-label="Explanation language"
            className="inline-flex items-center gap-1 rounded-md border border-[#263449] bg-[#0B1120] p-0.5"
          >
            <Languages className="ml-1.5 h-3.5 w-3.5 text-[#94A3B8]" />
            {LANG_OPTIONS.map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setSelectedLang(opt.id)}
                className={`rounded px-2 py-0.5 text-[11px] font-medium transition-colors duration-150 ${
                  selectedLang === opt.id
                    ? 'bg-[#3B82F6] text-white'
                    : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {scanResult.scanId && (
            <div className="inline-flex items-center gap-1.5">
              {onOpenReport && (
                <button
                  type="button"
                  onClick={() => onOpenReport(scanResult.scanId)}
                  className="inline-flex items-center gap-1 rounded-md border border-[#263449] bg-[#172338] px-2.5 py-1 text-[11px] font-semibold text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50"
                >
                  <FileText className="h-3 w-3 text-[#3B82F6]" />
                  Report
                </button>
              )}
              <button
                type="button"
                onClick={() => handleExport('pdf')}
                className="inline-flex items-center gap-1 rounded-md border border-[#3B82F6]/35 bg-[#3B82F6]/12 px-2.5 py-1 text-[11px] font-semibold text-[#93C5FD] transition-colors duration-150 hover:bg-[#3B82F6]/20"
              >
                <Download className="h-3 w-3" />
                PDF
              </button>
              <button
                type="button"
                onClick={() => handleExport('json')}
                className="inline-flex items-center gap-1 rounded-md border border-[#263449] bg-[#172338] px-2.5 py-1 text-[11px] font-semibold text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50"
              >
                <Download className="h-3 w-3" />
                JSON
              </button>
            </div>
          )}

          {scanResult.scannedAt && (
            <span className="inline-flex items-center gap-1 text-[11px] text-[#94A3B8]">
              <Clock className="h-3 w-3" />
              {formatTimestamp(scanResult.scannedAt)}
            </span>
          )}
        </div>
      </div>

      {/* Primary Classification & Score Summary */}
      <div className="grid gap-4 rounded-lg border border-[#263449] bg-[#0B1120] p-4 sm:grid-cols-3 sm:items-center">
        <div className="sm:col-span-1">
          <RiskScoreDisplay score={scanResult.riskScore} level={scanResult.riskLevel} />
        </div>

        <div className="space-y-2 sm:col-span-2">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge label={scanResult.riskLevel} size="md" />
          </div>
          <p className="text-xs leading-relaxed text-[#F1F5F9]">
            {localizedBundle?.summary || scanResult.inspectionNote}
          </p>
          {scanResult.explanation && scanResult.explanation !== scanResult.inspectionNote && (
            <p className="text-xs leading-relaxed text-[#94A3B8]">{scanResult.explanation}</p>
          )}
        </div>
      </div>

      {/* OCR Extracted Text Review */}
      {isImageResult && (
        <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-3.5 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-semibold text-[#F1F5F9]">
              OCR Extracted Text
              {scanResult.ocrConfidence !== null && (
                <span className="ml-2 font-normal text-[#94A3B8]">
                  ({Math.round(scanResult.ocrConfidence * 100)}% confidence)
                </span>
              )}
            </span>
            {scanResult.extractedText && onReviewExtractedText && (
              <button
                type="button"
                onClick={() => onReviewExtractedText(scanResult.extractedText)}
                className="inline-flex items-center gap-1 font-semibold text-[#3B82F6] hover:text-[#60A5FA]"
              >
                <Edit3 className="h-3 w-3" />
                Edit as Text
              </button>
            )}
          </div>
          <p className="mt-1.5 whitespace-pre-wrap break-words font-mono text-[11px] text-[#94A3B8]">
            {scanResult.extractedText || 'No readable text was detected in the uploaded image.'}
          </p>
        </div>
      )}

      {/* Detected Indicators & Recommendations */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
            Detected Indicators
          </h3>
          {scanResult.detectedIndicators.length === 0 ? (
            <p className="mt-2.5 flex items-center gap-2 text-xs text-[#86EFAC]">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-[#22C55E]" />
              No strong phishing or malware indicators detected in completed checks.
            </p>
          ) : (
            <ul className="mt-2.5 space-y-2">
              {scanResult.detectedIndicators.map((ind, idx) => (
                <li
                  key={`${ind}-${idx}`}
                  className="rounded-md border border-[#263449] bg-[#111C30] p-2.5 text-xs"
                >
                  <p className="font-semibold text-[#F1F5F9]">{ind}</p>
                  {(localizedBundle?.explanations?.[idx] || scanResult.explanations?.[idx]) && (
                    <p className="mt-1 text-[11px] leading-relaxed text-[#94A3B8]">
                      {localizedBundle?.explanations?.[idx] || scanResult.explanations[idx]}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
            Recommended Next Steps
          </h3>
          <ul className="mt-2.5 list-disc space-y-1.5 pl-4 text-xs text-[#94A3B8]">
            {(localizedBundle?.recommendations?.length
              ? localizedBundle.recommendations
              : scanResult.recommendations
            ).map((rec, idx) => (
              <li key={`${rec}-${idx}`} className="leading-relaxed">
                {rec}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Expandable Technical Details */}
      <div className="rounded-lg border border-[#263449] bg-[#0B1120]">
        <button
          type="button"
          onClick={() => setShowTechnical((v) => !v)}
          aria-expanded={showTechnical}
          className="flex w-full items-center justify-between px-4 py-3 text-left text-xs font-semibold text-[#F1F5F9] transition-colors duration-150 hover:bg-[#172338]"
        >
          <span>Technical Analysis Details (Rules, ML &amp; Threat Intelligence)</span>
          {showTechnical ? (
            <ChevronUp className="h-4 w-4 text-[#94A3B8]" />
          ) : (
            <ChevronDown className="h-4 w-4 text-[#94A3B8]" />
          )}
        </button>

        {showTechnical && (
          <div className="space-y-3 border-t border-[#263449] bg-[#111C30] p-4">
            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-3.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="inline-flex items-center gap-1.5 font-semibold text-[#F1F5F9]">
                    <Cpu className="h-3.5 w-3.5 text-[#3B82F6]" />
                    Machine Learning Layer
                  </span>
                  <span className="font-mono text-[11px] text-[#94A3B8]">
                    {scanResult.mlAnalysis?.available ? 'Available' : 'Unavailable'}
                  </span>
                </div>
                {scanResult.mlAnalysis?.available ? (
                  <p className="mt-2 text-[#F1F5F9]">
                    Prediction: <strong>{scanResult.mlAnalysis.prediction}</strong>{' '}
                    {scanResult.mlAnalysis.confidence !== null && (
                      <span className="text-[#94A3B8]">
                        ({Math.round(scanResult.mlAnalysis.confidence * 100)}% confidence)
                      </span>
                    )}
                  </p>
                ) : (
                  <p className="mt-2 text-[#94A3B8]">
                    ML model unavailable for this scan; rule-based scoring remains active.
                  </p>
                )}
              </div>

              <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-3.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="inline-flex items-center gap-1.5 font-semibold text-[#F1F5F9]">
                    <Globe className="h-3.5 w-3.5 text-[#3B82F6]" />
                    Threat Intelligence
                  </span>
                  <StatusBadge label={scanResult.reputationStatus} />
                </div>
                <p className="mt-2 text-[#94A3B8]">
                  Provider:{' '}
                  <strong className="text-[#F1F5F9]">
                    {domainIntel?.provider_name || 'unconfigured'}
                  </strong>
                  {domainIntel?.note ? ` — ${domainIntel.note}` : ''}
                </p>
              </div>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <FindingCategorySection
                title="Phishing Indicators"
                icon={ShieldAlert}
                items={scanResult.phishingIndicators}
              />
              <FindingCategorySection
                title="Malware & Reputation"
                icon={Bug}
                items={scanResult.malwareIndicators}
                emptyLabel={
                  scanResult.reputationStatus === 'Check unavailable'
                    ? 'Check unavailable'
                    : 'Not detected'
                }
              />
              <FindingCategorySection
                title="Redirect Indicators"
                icon={ArrowRightLeft}
                items={scanResult.redirectIndicators}
              />
              <FindingCategorySection
                title="Download & File Signals"
                icon={FileWarning}
                items={scanResult.fileDownloadIndicators}
              />
            </div>

            {scanResult.urlResults.length > 0 && (
              <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-3.5 text-xs">
                <button
                  type="button"
                  onClick={() => setShowUrls((v) => !v)}
                  className="flex w-full items-center justify-between font-semibold text-[#F1F5F9]"
                >
                  <span>Inspected URLs ({scanResult.urlResults.length})</span>
                  {showUrls ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </button>
                {showUrls && (
                  <ul className="mt-2.5 space-y-2">
                    {scanResult.urlResults.map((u, idx) => (
                      <li
                        key={`${u.url}-${idx}`}
                        className="flex flex-wrap items-center justify-between gap-2 rounded border border-[#263449] bg-[#111C30] p-2"
                      >
                        <span className="break-all font-mono text-[11px] text-[#F1F5F9]">
                          {u.url}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[11px] text-[#94A3B8]">
                            {u.risk_score}/100
                          </span>
                          <StatusBadge label={u.risk_level} />
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      <p className="text-[11px] leading-relaxed text-[#94A3B8]">{scanResult.disclaimer}</p>
    </div>
  )
}
