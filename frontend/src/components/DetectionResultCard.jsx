import { useState } from 'react'
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
} from 'lucide-react'
import { downloadScanReport } from '../services/api.js'
import {
  EmptyState,
  LoadingState,
  RiskScoreDisplay,
  StatusBadge,
} from './ui/StatusPrimitives.jsx'
import TrackerFindingCard from './TrackerFindingCard.jsx'

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
    <div className="rounded-lg border border-slate-800/90 bg-[#090d16] p-3.5">
      <div className="flex items-center justify-between gap-2">
        <span className="inline-flex items-center gap-2 text-xs font-semibold text-slate-200">
          <Icon className="h-3.5 w-3.5 text-blue-400" />
          {title}
        </span>
        {items.length === 0 && <StatusBadge label={emptyLabel} />}
      </div>

      {items.length > 0 && (
        <div className="mt-2.5 space-y-2">
          {items.map((item, idx) => (
            <div
              key={`${item.rule_id}-${idx}`}
              className="rounded-md border border-slate-800 bg-[#0f1623] p-2.5 text-xs"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-slate-100">{item.rule_name}</span>
                <div className="flex items-center gap-1.5">
                  {item.score_contribution > 0 && (
                    <span className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-amber-300">
                      +{item.score_contribution} pts
                    </span>
                  )}
                  <StatusBadge label={item.detection_status} />
                </div>
              </div>
              {item.evidence && (
                <p className="mt-1 break-all font-mono text-[11px] text-slate-400">
                  {item.evidence}
                </p>
              )}
              <p className="mt-1 text-[11px] leading-relaxed text-slate-300">
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
 * Structured enterprise DetectionResultCard for URL, Message, and Image OCR scans.
 */
const LANG_OPTIONS = [
  { id: 'en', label: 'English' },
  { id: 'hi', label: 'हिंदी' },
  { id: 'hinglish', label: 'Hinglish' },
]

export default function DetectionResultCard({
  scanResult,
  isScanning,
  apiError,
  activeMode,
  onReviewExtractedText,
  onOpenThreatAnalysis,
}) {
  const [showDetailedBreakdown, setShowDetailedBreakdown] = useState(true)
  const [selectedLang, setSelectedLang] = useState('en')

  if (isScanning) {
    return (
      <LoadingState
        message={
          activeMode === 'url'
            ? 'Analyzing URL structure & security signals...'
            : 'Extracting text and inspecting detected URLs...'
        }
        subtext="Links are analyzed defensively and are never clicked or executed."
      />
    )
  }

  if (apiError) {
    return (
      <div
        role="alert"
        className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4"
      >
        <div className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
          <div>
            <h3 className="text-sm font-semibold text-rose-200">Scan Error</h3>
            <p className="mt-1 text-xs leading-relaxed text-rose-200/90">{apiError}</p>
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
            ? 'Submit a URL above to evaluate phishing, redirect, file-extension, and tracker signals.'
            : 'Paste a message or upload a screenshot above to extract and analyze embedded URLs.'
        }
      />
    )
  }

  const isUrlResult = scanResult.scanType === 'url'
  const isImageResult = scanResult.scanType === 'message-image'
  const hasScore = scanResult.riskScore !== null && scanResult.riskScore !== undefined
  const domainIntel = scanResult.domainIntelligence
  const localizedBundle =
    scanResult.multilingualExplanations?.[selectedLang] ||
    scanResult.multilingualExplanations?.en ||
    null

  return (
    <div className="space-y-4 rounded-xl border border-slate-800/90 bg-[#0f1623] p-5 shadow-lg shadow-black/20 sm:p-6">
      {/* Header metadata row */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/90 pb-3.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-[#090d16] px-2.5 py-1 text-xs font-medium text-slate-200">
            {isUrlResult ? (
              <Link2 className="h-3.5 w-3.5 text-blue-400" />
            ) : isImageResult ? (
              <ImageIcon className="h-3.5 w-3.5 text-blue-400" />
            ) : (
              <MessageSquareWarning className="h-3.5 w-3.5 text-blue-400" />
            )}
            {isUrlResult ? 'URL Scan' : isImageResult ? 'Image OCR Scan' : 'Message Scan'}
          </span>
          <StatusBadge label={scanResult.inspectionStatus} />
          <StatusBadge label={scanResult.reputationStatus} />
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
          {/* Instant Language Selector (no re-scan) */}
          <div
            role="group"
            aria-label="Explanation language"
            className="inline-flex items-center gap-1 rounded-md border border-slate-800 bg-[#090d16] p-0.5"
          >
            <Languages className="ml-1.5 h-3.5 w-3.5 text-slate-400" />
            {LANG_OPTIONS.map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setSelectedLang(opt.id)}
                className={`rounded px-2 py-0.5 text-[11px] font-medium transition-colors ${
                  selectedLang === opt.id
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {scanResult.scanId && (
            <div className="inline-flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => downloadScanReport(scanResult.scanId, 'pdf')}
                className="inline-flex items-center gap-1 rounded-md border border-blue-500/30 bg-blue-500/10 px-2 py-1 text-[11px] font-medium text-blue-300 hover:bg-blue-500/20"
              >
                <Download className="h-3 w-3" />
                PDF
              </button>
              <button
                type="button"
                onClick={() => downloadScanReport(scanResult.scanId, 'json')}
                className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-[#090d16] px-2 py-1 text-[11px] font-medium text-slate-300 hover:border-blue-500/40"
              >
                <Download className="h-3 w-3" />
                JSON
              </button>
            </div>
          )}

          {scanResult.scannedAt && (
            <span className="inline-flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5 text-slate-500" />
              {formatTimestamp(scanResult.scannedAt)}
            </span>
          )}
          {onOpenThreatAnalysis && hasScore && (
            <button
              type="button"
              onClick={onOpenThreatAnalysis}
              className="text-xs font-medium text-blue-400 hover:text-blue-300"
            >
              Open Threat Analysis →
            </button>
          )}
        </div>
      </div>

      {/* OCR Extracted Text Panel */}
      {isImageResult && (
        <div className="space-y-2.5 rounded-lg border border-slate-800 bg-[#090d16] p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              OCR Extracted Text
            </h3>
            <div className="flex items-center gap-2">
              {scanResult.ocrConfidence !== null && (
                <span className="rounded border border-slate-700 bg-[#131c2e] px-2 py-0.5 text-[11px] text-slate-300">
                  Confidence: {Math.round(scanResult.ocrConfidence * 100)}%
                </span>
              )}
              {scanResult.extractedText && onReviewExtractedText && (
                <button
                  type="button"
                  onClick={() => onReviewExtractedText(scanResult.extractedText)}
                  className="inline-flex items-center gap-1 rounded border border-blue-500/40 bg-blue-500/10 px-2.5 py-0.5 text-[11px] font-medium text-blue-300 hover:bg-blue-500/20"
                >
                  <Edit3 className="h-3 w-3" />
                  Edit &amp; Re-scan
                </button>
              )}
            </div>
          </div>

          {scanResult.lowOcrConfidenceWarning && (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              <span>{scanResult.lowOcrConfidenceWarning}</span>
            </div>
          )}

          <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-md border border-slate-800 bg-[#0f1623] p-3 font-mono text-xs text-slate-200">
            {scanResult.extractedText || '(No readable text detected in image)'}
          </pre>
        </div>
      )}

      {/* Score & Assessment Card */}
      <div className="rounded-lg border border-slate-800 bg-[#090d16] p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-[200px] flex-1">
            <RiskScoreDisplay
              score={scanResult.riskScore}
              level={scanResult.riskLevel}
              label={isUrlResult ? 'Combined Risk Score' : 'Overall URL-Based Risk Score'}
            />
            {scanResult.ruleScore !== null &&
              scanResult.ruleScore !== undefined &&
              scanResult.mlAnalysis?.score_contribution > 0 && (
                <p className="mt-1.5 text-[11px] text-slate-400">
                  Breakdown: Rule-based ({scanResult.ruleScore}) + ML contribution (+
                  {scanResult.mlAnalysis.score_contribution})
                </p>
              )}
          </div>
          <StatusBadge label={scanResult.riskLevel} size="md" />
        </div>

        <div className="mt-3 space-y-1 text-[11px] text-slate-400">
          {localizedBundle?.summary && (
            <p className="text-xs font-medium text-slate-200">{localizedBundle.summary}</p>
          )}
          {scanResult.inspectionNote && (
            <p>
              <strong className="text-slate-300">Analysis Mode:</strong>{' '}
              {scanResult.inspectionNote}
            </p>
          )}
          {scanResult.completedChecks?.length > 0 && (
            <p>
              <strong className="text-slate-300">Completed Checks:</strong>{' '}
              {scanResult.completedChecks.join(' • ')}
            </p>
          )}
          {scanResult.blockedDestinations?.length > 0 && (
            <p className="text-amber-300">
              <strong>Blocked for Safety:</strong>{' '}
              {scanResult.blockedDestinations.join(', ')}
            </p>
          )}
        </div>
      </div>

      {/* ML Analysis Section */}
      {scanResult.mlAnalysis && (
        <div className="rounded-lg border border-slate-800 bg-[#090d16] p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
              <Cpu className="h-3.5 w-3.5 text-blue-400" />
              ML Analysis
            </span>
            <StatusBadge
              label={
                scanResult.mlAnalysis.available
                  ? scanResult.mlAnalysis.prediction === 'Legitimate'
                    ? 'No strong indicators detected'
                    : scanResult.mlAnalysis.prediction
                  : 'Check unavailable'
              }
            />
          </div>

          <div className="mt-2.5 grid gap-2 text-xs sm:grid-cols-3">
            <div className="rounded border border-slate-800 bg-[#0f1623] p-2.5">
              <p className="text-[10px] uppercase text-slate-500">ML Prediction</p>
              <p className="mt-0.5 font-semibold text-slate-100">
                {scanResult.mlAnalysis.prediction}
              </p>
            </div>
            <div className="rounded border border-slate-800 bg-[#0f1623] p-2.5">
              <p className="text-[10px] uppercase text-slate-500">Calibrated Confidence</p>
              <p className="mt-0.5 font-mono font-semibold text-slate-100">
                {scanResult.mlAnalysis.calibrated &&
                scanResult.mlAnalysis.confidence !== null
                  ? `${Math.round(scanResult.mlAnalysis.confidence * 100)}%`
                  : 'Unavailable'}
              </p>
            </div>
            <div className="rounded border border-slate-800 bg-[#0f1623] p-2.5">
              <p className="text-[10px] uppercase text-slate-500">Model Version</p>
              <p className="mt-0.5 font-mono text-slate-200">
                {scanResult.mlAnalysis.model_version || 'Unavailable'}
              </p>
            </div>
          </div>

          {scanResult.mlAnalysis.error && (
            <p className="mt-2 text-[11px] text-amber-300">{scanResult.mlAnalysis.error}</p>
          )}
          <p className="mt-2 text-[11px] text-slate-400">
            {scanResult.mlAnalysis.disclaimer}
          </p>
        </div>
      )}

      {/* Individual URL results for Message & Image OCR */}
      {!isUrlResult && scanResult.urlResults.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-[#090d16] p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Detected URLs ({scanResult.urlResults.length})
          </h3>
          <ul className="mt-2.5 space-y-2">
            {scanResult.urlResults.map((item, idx) => (
              <li
                key={`${item.url}-${idx}`}
                className="rounded-md border border-slate-800 bg-[#0f1623] p-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="break-all font-mono text-xs text-slate-200">
                    {item.url}
                  </span>
                  <StatusBadge label={`${item.risk_level} (${item.risk_score}/100)`} />
                </div>
                {item.error && <p className="mt-1 text-xs text-rose-300">{item.error}</p>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Triggered Rules */}
      {hasScore && (
        <div className="rounded-lg border border-slate-800 bg-[#090d16] p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Triggered Rules &amp; Score Contributions
          </h3>
          {scanResult.detectedRules.length === 0 ? (
            <p className="mt-2 flex items-center gap-2 text-xs text-emerald-300">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              No strong malicious indicators detected in available checks.
            </p>
          ) : (
            <ul className="mt-2.5 space-y-2">
              {scanResult.detectedRules.map((rule, idx) => (
                <li
                  key={`${rule.rule_id}-${idx}`}
                  className="rounded-md border border-slate-800 bg-[#0f1623] p-3 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-slate-100">{rule.rule_name}</span>
                    <div className="flex items-center gap-1.5">
                      <span className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-amber-300">
                        +{rule.score_contribution} pts
                      </span>
                      <StatusBadge label={rule.detection_status} />
                    </div>
                  </div>
                  {rule.evidence && (
                    <p className="mt-1 break-all font-mono text-[11px] text-slate-400">
                      {rule.evidence}
                    </p>
                  )}
                  <p className="mt-1 text-[11px] leading-relaxed text-slate-300">
                    {localizedBundle?.explanations?.[idx] || rule.explanation}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Expandable Detailed Breakdown */}
      {hasScore && (
        <div className="rounded-lg border border-slate-800 bg-[#090d16] p-4">
          <button
            type="button"
            onClick={() => setShowDetailedBreakdown((prev) => !prev)}
            className="flex w-full items-center justify-between text-left text-xs font-semibold uppercase tracking-wider text-slate-300"
          >
            <span>Detailed Findings (Trackers, Phishing, Malware, Redirects, Domain &amp; Files)</span>
            {showDetailedBreakdown ? (
              <ChevronUp className="h-4 w-4 text-slate-400" />
            ) : (
              <ChevronDown className="h-4 w-4 text-slate-400" />
            )}
          </button>

          {showDetailedBreakdown && (
            <div className="mt-3 space-y-2.5">
              <FindingCategorySection
                title="Phishing Indicators"
                icon={ShieldAlert}
                items={scanResult.phishingIndicators}
              />
              <FindingCategorySection
                title="Malware Indicators"
                icon={Bug}
                items={scanResult.malwareIndicators}
                emptyLabel="Check unavailable"
              />
              <FindingCategorySection
                title="Redirect Indicators"
                icon={ArrowRightLeft}
                items={scanResult.redirectIndicators}
              />
              <FindingCategorySection
                title="File & Download Indicators"
                icon={FileWarning}
                items={scanResult.fileDownloadIndicators}
              />

              {/* Tracker Findings using TrackerFindingCard */}
              <div className="rounded-lg border border-slate-800/90 bg-[#090d16] p-3.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-200">
                    Website Tracker Findings (Informational)
                  </span>
                  {scanResult.trackerIndicators.length === 0 && (
                    <StatusBadge label="Not detected" />
                  )}
                </div>
                {scanResult.trackerIndicators.length > 0 && (
                  <div className="mt-2.5 space-y-2">
                    {scanResult.trackerIndicators.map((t, idx) => (
                      <TrackerFindingCard key={`${t.rule_id}-${idx}`} finding={t} />
                    ))}
                  </div>
                )}
              </div>

              {domainIntel && (
                <div className="rounded-lg border border-slate-800/90 bg-[#0f1623] p-3.5 text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-2 font-semibold text-slate-200">
                      <Globe className="h-3.5 w-3.5 text-blue-400" />
                      Domain Reputation &amp; Age
                    </span>
                    <StatusBadge label={domainIntel.reputation_status} />
                  </div>
                  <div className="mt-2 grid gap-1.5 text-[11px] text-slate-300 sm:grid-cols-2">
                    <p>
                      <span className="text-slate-500">Provider:</span>{' '}
                      {domainIntel.provider_name}
                    </p>
                    <p>
                      <span className="text-slate-500">Domain Age:</span>{' '}
                      {domainIntel.domain_age_status}
                    </p>
                    {domainIntel.checked_at && (
                      <p>
                        <span className="text-slate-500">Checked:</span>{' '}
                        {formatTimestamp(domainIntel.checked_at)}{' '}
                        <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
                          {domainIntel.cached ? 'Cached' : 'Fresh'}
                        </span>
                      </p>
                    )}
                  </div>
                  {domainIntel.provider_results?.length > 0 && (
                    <ul className="mt-2 space-y-1.5 border-t border-slate-800 pt-2">
                      {domainIntel.provider_results.map((pr, idx) => (
                        <li
                          key={`${pr.provider_name}-${idx}`}
                          className="flex flex-wrap items-center justify-between gap-2 text-[11px]"
                        >
                          <span className="text-slate-200">
                            {pr.provider_name} ({pr.threat_category})
                          </span>
                          <span className="text-slate-400">
                            {pr.lookup_status} • {pr.cached ? 'Cached' : 'Fresh'}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                  {domainIntel.note && (
                    <p className="mt-2 text-[11px] text-slate-400">{domainIntel.note}</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Recommendations & Limitations */}
      {(localizedBundle?.recommendations?.length > 0 || scanResult.recommendations.length > 0) && (
        <div className="rounded-lg border border-slate-800 bg-[#090d16] p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Recommendations
          </h3>
          <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-slate-300">
            {(localizedBundle?.recommendations?.length > 0
              ? localizedBundle.recommendations
              : scanResult.recommendations
            ).map((rec, idx) => (
              <li key={`${rec}-${idx}`}>{rec}</li>
            ))}
          </ul>
        </div>
      )}

      {scanResult.limitations?.length > 0 && (
        <p className="text-[11px] leading-relaxed text-slate-400">
          <strong className="text-slate-300">Limitations:</strong>{' '}
          {scanResult.limitations.join(' ')}
        </p>
      )}
    </div>
  )
}
