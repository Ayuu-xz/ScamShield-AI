import { useState } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Activity,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Link2,
  MessageSquareWarning,
  Image as ImageIcon,
  Clock,
  HelpCircle,
  Edit3,
  ChevronDown,
  ChevronUp,
  Globe,
  FileWarning,
  ArrowRightLeft,
  Eye,
  Bug,
} from 'lucide-react'

const LEVEL_STYLES = {
  Safe: {
    badge: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
    bar: 'bg-emerald-500',
    scoreText: 'text-emerald-400',
    Icon: ShieldCheck,
  },
  Suspicious: {
    badge: 'border-amber-500/40 bg-amber-500/15 text-amber-300',
    bar: 'bg-amber-500',
    scoreText: 'text-amber-400',
    Icon: ShieldAlert,
  },
  Dangerous: {
    badge: 'border-rose-500/40 bg-rose-500/15 text-rose-300',
    bar: 'bg-rose-500',
    scoreText: 'text-rose-400',
    Icon: ShieldX,
  },
  'No strong indicators detected': {
    badge: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
    bar: 'bg-emerald-500',
    scoreText: 'text-emerald-400',
    Icon: ShieldCheck,
  },
  'Inspection unavailable': {
    badge: 'border-slate-500/40 bg-slate-800/80 text-slate-200',
    bar: 'bg-slate-500',
    scoreText: 'text-slate-300',
    Icon: HelpCircle,
  },
  Unavailable: {
    badge: 'border-slate-600 bg-slate-800/80 text-slate-300',
    bar: 'bg-slate-600',
    scoreText: 'text-slate-400',
    Icon: HelpCircle,
  },
}

const STATUS_BADGE_STYLES = {
  Detected: 'border-rose-500/40 bg-rose-500/15 text-rose-300',
  Completed: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
  'Not detected': 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
  'Check unavailable': 'border-slate-600 bg-slate-800 text-slate-300',
  'Blocked for safety': 'border-amber-500/40 bg-amber-500/15 text-amber-300',
  Informational: 'border-blue-500/40 bg-blue-500/15 text-blue-300',
}

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

function CategoryFindingGroup({ title, icon: Icon, items, emptyLabel }) {
  return (
    <div className="rounded-lg border border-slate-800/80 bg-slate-900/70 p-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
          <Icon className="h-3.5 w-3.5 text-blue-400" />
          {title}
        </div>
        {items.length === 0 && (
          <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-300">
            {emptyLabel || 'Not detected'}
          </span>
        )}
      </div>

      {items.length > 0 && (
        <ul className="mt-2.5 space-y-2">
          {items.map((item, idx) => (
            <li
              key={`${item.rule_id}-${idx}`}
              className="rounded border border-slate-800 bg-slate-950/70 p-2.5 text-xs"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-slate-100">{item.rule_name}</span>
                <div className="flex items-center gap-1.5">
                  {item.score_contribution > 0 && (
                    <span className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-amber-300">
                      +{item.score_contribution} pts
                    </span>
                  )}
                  <span
                    className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                      STATUS_BADGE_STYLES[item.detection_status] ||
                      STATUS_BADGE_STYLES['Check unavailable']
                    }`}
                  >
                    {item.detection_status}
                  </span>
                </div>
              </div>
              {item.evidence && (
                <p className="mt-1 break-all font-mono text-[11px] text-slate-400">
                  Evidence: {item.evidence}
                </p>
              )}
              {(item.detection_source || item.tracker_domain) && (
                <p className="mt-0.5 text-[10px] text-slate-500">
                  Source: {item.detection_source || 'url'}
                  {item.tracker_domain ? ` • Domain: ${item.tracker_domain}` : ''}
                  {item.confidence ? ` • Confidence: ${item.confidence}` : ''}
                </p>
              )}
              <p className="mt-1 text-[11px] leading-relaxed text-slate-300">
                {item.explanation}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/**
 * Unified RiskResult component displaying structured findings from URL, Message, and Image OCR scanners.
 */
export default function RiskResultCard({
  scanResult,
  isScanning,
  apiError,
  activeMode,
  onReviewExtractedText,
}) {
  const [showBreakdown, setShowBreakdown] = useState(true)

  const renderContent = () => {
    if (isScanning) {
      return (
        <div
          role="status"
          aria-live="polite"
          className="flex flex-col items-center justify-center gap-3 py-10 text-center"
        >
          <Loader2 className="h-7 w-7 animate-spin text-blue-400" />
          <p className="text-sm font-medium text-slate-200">
            {activeMode === 'url'
              ? 'Inspecting URL text patterns...'
              : 'Extracting text and inspecting detected URLs...'}
          </p>
          <p className="text-xs text-slate-500">
            {activeMode === 'url'
              ? 'Analyzing domain, redirects, file extensions, and phishing rules without visiting the link.'
              : 'URLs are inspected strictly as text and are never visited.'}
          </p>
        </div>
      )
    }

    if (apiError) {
      return (
        <div
          role="alert"
          className="mt-5 rounded-xl border border-rose-500/40 bg-rose-500/10 p-4"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
            <div>
              <h3 className="text-sm font-semibold text-rose-200">
                Unable to Complete Scan
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-rose-200/90">
                {apiError}
              </p>
            </div>
          </div>
        </div>
      )
    }

    if (scanResult) {
      const style = LEVEL_STYLES[scanResult.riskLevel] || LEVEL_STYLES.Unavailable
      const LevelIcon = style.Icon
      const isUrlResult = scanResult.scanType === 'url'
      const isImageResult = scanResult.scanType === 'message-image'
      const hasScore = scanResult.riskScore !== null && scanResult.riskScore !== undefined
      const domainIntel = scanResult.domainIntelligence

      return (
        <div className="mt-5 space-y-5">
          {/* Metadata strip: Scan Type + Reputation Provider Status + Timestamp */}
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-slate-950/80 px-2.5 py-1 font-medium text-slate-200">
                {isUrlResult ? (
                  <Link2 className="h-3.5 w-3.5 text-blue-400" />
                ) : isImageResult ? (
                  <ImageIcon className="h-3.5 w-3.5 text-blue-400" />
                ) : (
                  <MessageSquareWarning className="h-3.5 w-3.5 text-blue-400" />
                )}
                Scan Type:{' '}
                {isUrlResult ? 'URL' : isImageResult ? 'Message (Image OCR)' : 'Message'}
              </span>

              <span
                className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-[11px] font-medium ${
                  STATUS_BADGE_STYLES[scanResult.inspectionStatus] ||
                  STATUS_BADGE_STYLES['Check unavailable']
                }`}
              >
                Website Inspection: {scanResult.inspectionStatus}
              </span>

              <span
                className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-[11px] font-medium ${
                  STATUS_BADGE_STYLES[scanResult.reputationStatus] ||
                  STATUS_BADGE_STYLES['Check unavailable']
                }`}
              >
                Reputation: {scanResult.reputationStatus}
              </span>
            </div>

            {scanResult.scannedAt && (
              <span className="inline-flex items-center gap-1.5 text-slate-400">
                <Clock className="h-3.5 w-3.5 text-slate-500" />
                {formatTimestamp(scanResult.scannedAt)}
              </span>
            )}
          </div>

          {/* OCR Extracted Text Review Panel */}
          {isImageResult && (
            <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  OCR Extracted Text
                </h3>
                <div className="flex items-center gap-2">
                  {scanResult.ocrConfidence !== null && (
                    <span className="rounded-md border border-slate-700 bg-slate-900 px-2 py-0.5 text-[11px] text-slate-300">
                      OCR Confidence: {Math.round(scanResult.ocrConfidence * 100)}%
                    </span>
                  )}
                  {scanResult.extractedText && onReviewExtractedText && (
                    <button
                      type="button"
                      onClick={() => onReviewExtractedText(scanResult.extractedText)}
                      className="inline-flex items-center gap-1 rounded-md border border-blue-500/40 bg-blue-500/10 px-2.5 py-0.5 text-[11px] font-medium text-blue-300 hover:bg-blue-500/20"
                    >
                      <Edit3 className="h-3 w-3" />
                      Edit &amp; Re-scan Text
                    </button>
                  )}
                </div>
              </div>

              {scanResult.lowOcrConfidenceWarning && (
                <div className="flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
                  <span>{scanResult.lowOcrConfidenceWarning}</span>
                </div>
              )}

              <pre className="max-h-44 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-slate-900/80 p-3 font-mono text-xs text-slate-200">
                {scanResult.extractedText || '(No readable text detected in image)'}
              </pre>
            </div>
          )}

          {/* Overall Score + Classification summary */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 sm:p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
                  {isUrlResult ? 'Risk Score' : 'Overall URL-Based Risk Score'}
                </p>
                {hasScore ? (
                  <div className="mt-1 flex items-baseline gap-1.5">
                    <span className={`text-3xl font-extrabold ${style.scoreText}`}>
                      {scanResult.riskScore}
                    </span>
                    <span className="text-sm text-slate-500">/ 100</span>
                  </div>
                ) : (
                  <p className="mt-1 text-sm font-semibold text-slate-300">
                    Assessment Unavailable
                  </p>
                )}
              </div>

              <span
                className={`inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-sm font-semibold ${style.badge}`}
              >
                <LevelIcon className="h-4 w-4" />
                {scanResult.riskLevel === 'Unavailable'
                  ? 'No URL Detected'
                  : scanResult.riskLevel}
              </span>
            </div>

            {hasScore && (
              <div
                role="progressbar"
                aria-valuenow={scanResult.riskScore}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label="Risk score"
                className="mt-4 h-2.5 w-full overflow-hidden rounded-full bg-slate-800"
              >
                <div
                  className={`h-full rounded-full transition-all duration-500 ease-out ${style.bar}`}
                  style={{ width: `${scanResult.riskScore}%` }}
                />
              </div>
            )}

            {scanResult.inspectionNote && (
              <p className="mt-2 text-[11px] text-slate-400">
                <strong className="text-slate-300">Inspection Scope:</strong>{' '}
                {scanResult.inspectionNote}
              </p>
            )}
            {scanResult.completedChecks?.length > 0 && (
              <p className="mt-1 text-[11px] text-slate-400">
                <strong className="text-slate-300">Completed Checks:</strong>{' '}
                {scanResult.completedChecks.join(' • ')}
              </p>
            )}
            {scanResult.blockedDestinations?.length > 0 && (
              <p className="mt-1 text-[11px] text-amber-300">
                <strong>Blocked for Safety:</strong>{' '}
                {scanResult.blockedDestinations.join(', ')}
              </p>
            )}
          </div>

          {/* Individual URL Scan Results (for Message & Image OCR modes) */}
          {!isUrlResult && scanResult.urlResults.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 sm:p-5">
              <h3 className="text-sm font-semibold text-white">
                Detected URLs ({scanResult.urlResults.length})
              </h3>
              <ul className="mt-3 space-y-3">
                {scanResult.urlResults.map((item, idx) => {
                  const itemStyle =
                    LEVEL_STYLES[item.risk_level] || LEVEL_STYLES.Unavailable
                  const ItemIcon = itemStyle.Icon
                  return (
                    <li
                      key={`${item.url}-${idx}`}
                      className="rounded-lg border border-slate-800/80 bg-slate-900/70 p-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="break-all font-mono text-xs text-slate-200">
                          {item.url}
                        </span>
                        <span
                          className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${itemStyle.badge}`}
                        >
                          <ItemIcon className="h-3 w-3" />
                          {item.risk_level} ({item.risk_score}/100)
                        </span>
                      </div>
                      {item.error && (
                        <p className="mt-1.5 text-xs text-rose-300">{item.error}</p>
                      )}
                      {item.detected_indicators?.length > 0 && (
                        <p className="mt-1.5 text-[11px] text-slate-400">
                          Indicators: {item.detected_indicators.join(' • ')}
                        </p>
                      )}
                    </li>
                  )
                })}
              </ul>
            </div>
          )}

          {/* Triggered Rules & Score Contributions */}
          {hasScore && (
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 sm:p-5">
              <h3 className="text-sm font-semibold text-white">
                Triggered Rules &amp; Score Contributions
              </h3>
              {scanResult.detectedRules.length === 0 ? (
                <p className="mt-2 flex items-center gap-2 text-xs text-emerald-300">
                  <CheckCircle2 className="h-4 w-4 shrink-0" />
                  Safe indicators not detected in URL text.
                </p>
              ) : (
                <ul className="mt-3 space-y-3">
                  {scanResult.detectedRules.map((rule, index) => (
                    <li
                      key={`${rule.rule_id}-${index}`}
                      className="rounded-lg border border-slate-800/80 bg-slate-900/70 p-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-xs font-semibold text-slate-100">
                          {rule.rule_name}
                        </p>
                        <div className="flex items-center gap-1.5">
                          <span className="rounded bg-amber-500/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-amber-300">
                            +{rule.score_contribution} pts
                          </span>
                          <span className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[10px] font-medium text-rose-300">
                            {rule.detection_status}
                          </span>
                        </div>
                      </div>
                      {rule.evidence && (
                        <p className="mt-1 break-all font-mono text-[11px] text-slate-400">
                          Evidence: {rule.evidence}
                        </p>
                      )}
                      <p className="mt-1 text-xs leading-relaxed text-slate-300">
                        {rule.explanation}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {/* Expandable Specialized Security Modules Breakdown */}
          {hasScore && (
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 sm:p-5">
              <button
                type="button"
                onClick={() => setShowBreakdown((prev) => !prev)}
                className="flex w-full items-center justify-between text-left"
              >
                <span className="text-sm font-semibold text-white">
                  Detailed Security Checks (Trackers, Phishing, Malware, Redirects, Domain &amp; Files)
                </span>
                {showBreakdown ? (
                  <ChevronUp className="h-4 w-4 text-slate-400" />
                ) : (
                  <ChevronDown className="h-4 w-4 text-slate-400" />
                )}
              </button>

              {showBreakdown && (
                <div className="mt-4 space-y-3">
                  <CategoryFindingGroup
                    title="Phishing Indicators"
                    icon={ShieldAlert}
                    items={scanResult.phishingIndicators}
                  />
                  <CategoryFindingGroup
                    title="Malware Indicators"
                    icon={Bug}
                    items={scanResult.malwareIndicators}
                    emptyLabel="Check unavailable"
                  />
                  <CategoryFindingGroup
                    title="Redirect & URL Chain Indicators"
                    icon={ArrowRightLeft}
                    items={scanResult.redirectIndicators}
                  />
                  <CategoryFindingGroup
                    title="Suspicious File & Download Indicators"
                    icon={FileWarning}
                    items={scanResult.fileDownloadIndicators}
                  />
                  <CategoryFindingGroup
                    title="Website Tracker Findings (Informational)"
                    icon={Eye}
                    items={scanResult.trackerIndicators}
                  />

                  {domainIntel && (
                    <div className="rounded-lg border border-slate-800/80 bg-slate-900/70 p-3 text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="inline-flex items-center gap-2 font-semibold text-slate-200">
                          <Globe className="h-3.5 w-3.5 text-blue-400" />
                          Domain Reputation &amp; Age Intelligence
                        </span>
                        <span
                          className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                            STATUS_BADGE_STYLES[domainIntel.reputation_status] ||
                            STATUS_BADGE_STYLES['Check unavailable']
                          }`}
                        >
                          {domainIntel.reputation_status}
                        </span>
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
                      </div>
                      {domainIntel.note && (
                        <p className="mt-1.5 text-[11px] text-slate-400">
                          {domainIntel.note}
                        </p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Recommendations */}
          {scanResult.recommendations.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 sm:p-5">
              <h3 className="text-sm font-semibold text-white">Recommendations</h3>
              <ul className="mt-2.5 list-disc space-y-1.5 pl-5 text-xs leading-relaxed text-slate-300">
                {scanResult.recommendations.map((rec, index) => (
                  <li key={`${rec}-${index}`}>{rec}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Limitations */}
          {scanResult.limitations?.length > 0 && (
            <div className="rounded-xl border border-slate-800/70 bg-slate-950/40 p-3.5 text-[11px] text-slate-400">
              <span className="font-semibold text-slate-300">Analysis Scope &amp; Limitations:</span>{' '}
              {scanResult.limitations.join(' ')}
            </div>
          )}
        </div>
      )
    }

    return (
      <div className="py-8 text-center">
        <p className="text-sm text-slate-300">
          {activeMode === 'url'
            ? 'Enter a URL above and click Scan URL to inspect it.'
            : 'Paste a message or upload a screenshot above to extract and scan any URLs inside it.'}
        </p>
        <p className="mt-2 text-xs text-slate-500">
          Results display a 0–100 risk score, classification badge, triggered rules with
          score contributions, tracker/phishing/malware/redirect/file checks, and guidance.
        </p>
      </div>
    )
  }

  return (
    <section id="results" className="mx-auto mt-8 max-w-4xl px-4 sm:px-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 sm:p-7">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-blue-400" />
            <h2 className="text-lg font-bold text-white">Risk Analysis Results</h2>
          </div>

          {/* Color-coded classification legend */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-medium">
            <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-emerald-300">
              <ShieldCheck className="h-3.5 w-3.5" />
              Safe (0–24)
            </span>
            <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-amber-300">
              <ShieldAlert className="h-3.5 w-3.5" />
              Suspicious (25–49)
            </span>
            <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-0.5 text-rose-300">
              <ShieldX className="h-3.5 w-3.5" />
              Dangerous (50–100)
            </span>
          </div>
        </div>

        {renderContent()}

        {/* Important non-guarantee disclaimer */}
        <p className="mt-5 border-t border-slate-800/80 pt-3 text-xs text-slate-500">
          {scanResult?.disclaimer ||
            'Note: A Safe classification indicates no known suspicious text patterns were detected; it never guarantees a link or message is 100% safe.'}
        </p>
      </div>
    </section>
  )
}
