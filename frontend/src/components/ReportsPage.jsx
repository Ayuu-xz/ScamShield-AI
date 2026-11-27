import { useCallback, useEffect, useState } from 'react'
import {
  FileText,
  Download,
  CheckCircle2,
  Cpu,
  Globe,
  AlertTriangle,
  Search,
  ShieldCheck,
} from 'lucide-react'
import {
  downloadScanReport,
  fetchHistory,
  fetchScanReport,
} from '../services/api.js'
import {
  EmptyState,
  LoadingState,
  RiskScoreDisplay,
  StatusBadge,
} from './ui/StatusPrimitives.jsx'

function formatDateTime(isoString) {
  if (!isoString) return ''
  try {
    return new Date(isoString).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'medium',
    })
  } catch {
    return isoString
  }
}

/**
 * Refined dark-mode Reports workspace for inspecting and exporting PDF/JSON reports.
 */
export default function ReportsPage({ selectedScanId, onSelectScanId, onNavigate, onToast }) {
  const [recentItems, setRecentItems] = useState([])
  const [searchId, setSearchId] = useState('')
  const [isListLoading, setIsListLoading] = useState(true)

  const [report, setReport] = useState(null)
  const [isReportLoading, setIsReportLoading] = useState(false)
  const [reportError, setReportError] = useState('')
  const [exportingFormat, setExportingFormat] = useState('')

  const loadList = useCallback(async () => {
    setIsListLoading(true)
    try {
      const data = await fetchHistory({ limit: 20, offset: 0, search: searchId })
      const items = data.items || []
      setRecentItems(items)
      if (!selectedScanId && items.length > 0) {
        onSelectScanId?.(items[0].id)
      }
    } catch {
      // Non-blocking list load
    } finally {
      setIsListLoading(false)
    }
  }, [searchId, selectedScanId, onSelectScanId])

  useEffect(() => {
    loadList()
  }, [loadList])

  useEffect(() => {
    if (!selectedScanId) {
      setReport(null)
      return
    }
    let cancelled = false
    setIsReportLoading(true)
    setReportError('')
    fetchScanReport(selectedScanId)
      .then((data) => {
        if (!cancelled) setReport(data)
      })
      .catch((err) => {
        if (!cancelled) setReportError(err.message || 'Unable to load scan report.')
      })
      .finally(() => {
        if (!cancelled) setIsReportLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [selectedScanId])

  const handleExport = async (format) => {
    if (!report) return
    setExportingFormat(format)
    try {
      await downloadScanReport(report.scan_id, format)
      onToast?.({
        type: 'success',
        message: `Downloaded ${format.toUpperCase()} report for Scan #${report.scan_id}.`,
      })
    } catch (err) {
      onToast?.({
        type: 'error',
        message: err.message || `Failed to export ${format.toUpperCase()}.`,
      })
    } finally {
      setExportingFormat('')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-[#F1F5F9] sm:text-xl">Security Scan Reports</h2>
        <p className="mt-0.5 text-xs text-[#94A3B8]">
          Inspect evidence breakdowns and export validated PDF or JSON audit reports
        </p>
      </div>

      <div className="grid gap-5 lg:grid-cols-12">
        {/* Left Report Selector */}
        <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-4 lg:col-span-4">
          <div className="relative">
            <Search className="pointer-events-none absolute top-2.5 left-3 h-3.5 w-3.5 text-[#94A3B8]" />
            <input
              type="text"
              value={searchId}
              onChange={(e) => setSearchId(e.target.value)}
              placeholder="Filter by Scan ID or URL..."
              aria-label="Filter reports"
              className="w-full rounded-lg border border-[#263449] bg-[#0B1120] py-1.5 pr-3 pl-8 text-xs text-[#F1F5F9] placeholder-[#64748B] focus:border-[#3B82F6] focus:outline-none"
            />
          </div>

          <div className="mt-3 max-h-[520px] space-y-1.5 overflow-y-auto">
            {isListLoading ? (
              <p className="py-6 text-center text-xs text-[#94A3B8]">Loading scans...</p>
            ) : recentItems.length === 0 ? (
              <p className="py-6 text-center text-xs text-[#94A3B8]">
                No completed scans available.
              </p>
            ) : (
              recentItems.map((item) => {
                const isSelected = item.id === selectedScanId
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => onSelectScanId?.(item.id)}
                    className={`w-full rounded-lg border p-3 text-left text-xs transition-colors duration-150 ${
                      isSelected
                        ? 'border-[#3B82F6] bg-[#172338]'
                        : 'border-[#263449] bg-[#0B1120] hover:border-[#3B82F6]/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono font-semibold text-[#F1F5F9]">
                        #{item.id} · {item.scan_type.toUpperCase()}
                      </span>
                      <StatusBadge label={item.risk_level} />
                    </div>
                    <p className="mt-1.5 truncate font-mono text-[11px] text-[#94A3B8]">
                      {item.input_text}
                    </p>
                  </button>
                )
              })
            )}
          </div>
        </div>

        {/* Right Detailed Report Document */}
        <div className="lg:col-span-8">
          {isReportLoading ? (
            <LoadingState message="Loading detailed scan report..." />
          ) : reportError ? (
            <div
              role="alert"
              className="flex items-center gap-2.5 rounded-[10px] border border-[#EF4444]/40 bg-[#1F1218] p-4 text-xs text-[#FCA5A5]"
            >
              <AlertTriangle className="h-4 w-4 shrink-0 text-[#EF4444]" />
              <span>{reportError}</span>
            </div>
          ) : !report ? (
            <EmptyState
              icon={FileText}
              title="No Scan Report Selected"
              description="Run a scan or select a completed scan from the list to view and export its full report."
              action={
                <button
                  type="button"
                  onClick={() => onNavigate('overview')}
                  className="rounded-lg bg-[#3B82F6] px-4 py-2 text-xs font-semibold text-white hover:bg-[#2563EB]"
                >
                  Run a Scan
                </button>
              }
            />
          ) : (
            <article className="space-y-5 rounded-[10px] border border-[#263449] bg-[#111C30] p-6">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#263449] pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-[#3B82F6]" />
                    <span className="text-xs font-bold uppercase tracking-wider text-[#93C5FD]">
                      ScamShield AI Security Report
                    </span>
                  </div>
                  <h3 className="mt-1 text-lg font-bold text-[#F1F5F9]">
                    Scan Report #{report.scan_id}
                  </h3>
                  <p className="mt-0.5 text-xs text-[#94A3B8]">
                    Generated for {report.scan_type.toUpperCase()} inspection ·{' '}
                    {formatDateTime(report.created_at)}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={exportingFormat === 'pdf'}
                    onClick={() => handleExport('pdf')}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-[#3B82F6] px-3.5 py-2 text-xs font-semibold text-white transition-colors duration-150 hover:bg-[#2563EB] disabled:opacity-60"
                  >
                    <Download className="h-3.5 w-3.5" />
                    {exportingFormat === 'pdf' ? 'Exporting...' : 'Export PDF'}
                  </button>
                  <button
                    type="button"
                    disabled={exportingFormat === 'json'}
                    onClick={() => handleExport('json')}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[#263449] bg-[#172338] px-3.5 py-2 text-xs font-semibold text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50 disabled:opacity-60"
                  >
                    <Download className="h-3.5 w-3.5" />
                    {exportingFormat === 'json' ? 'Exporting...' : 'Export JSON'}
                  </button>
                </div>
              </div>

              <div className="grid gap-4 rounded-lg border border-[#263449] bg-[#0B1120] p-4 sm:grid-cols-3 sm:items-center">
                <RiskScoreDisplay score={report.risk_score} level={report.risk_level} />
                <div className="space-y-1.5 sm:col-span-2">
                  <StatusBadge label={report.risk_level} size="md" />
                  <p className="text-xs leading-relaxed text-[#F1F5F9]">
                    {report.classification_summary}
                  </p>
                  <p className="text-[11px] text-[#94A3B8]">
                    Analysis Sources: {report.analysis_sources.join(' · ')}
                  </p>
                </div>
              </div>

              <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-3.5">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-[#94A3B8]">
                  Inspected Target / Privacy-Sanitized Excerpt
                </p>
                <p className="mt-1.5 break-all font-mono text-xs text-[#F1F5F9]">
                  {report.input_preview}
                </p>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-4 text-xs">
                  <div className="flex items-center gap-2 font-semibold uppercase tracking-wider text-[#F1F5F9]">
                    <Cpu className="h-4 w-4 text-[#3B82F6]" />
                    ML Prediction
                  </div>
                  {report.ml_analysis.available ? (
                    <div className="mt-2 space-y-1 text-[#94A3B8]">
                      <p>
                        Classification:{' '}
                        <strong className="text-[#F1F5F9]">
                          {report.ml_analysis.prediction}
                        </strong>
                      </p>
                      <p>
                        Confidence:{' '}
                        <span className="text-[#F1F5F9]">
                          {report.ml_analysis.confidence !== null
                            ? `${Math.round(report.ml_analysis.confidence * 100)}%`
                            : 'N/A'}
                        </span>
                      </p>
                    </div>
                  ) : (
                    <p className="mt-2 text-[#94A3B8]">
                      Unavailable — {report.ml_analysis.note}
                    </p>
                  )}
                </div>

                <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-4 text-xs">
                  <div className="flex items-center gap-2 font-semibold uppercase tracking-wider text-[#F1F5F9]">
                    <Globe className="h-4 w-4 text-[#3B82F6]" />
                    Threat Intelligence
                  </div>
                  <div className="mt-2 space-y-1 text-[#94A3B8]">
                    <p>
                      Status:{' '}
                      <strong className="text-[#F1F5F9]">
                        {report.threat_intelligence.reputation_status}
                      </strong>{' '}
                      ({report.threat_intelligence.provider_name})
                    </p>
                    {report.threat_intelligence.note && (
                      <p>{report.threat_intelligence.note}</p>
                    )}
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-4">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
                  Detected Indicators &amp; Rule Analysis (Rule Score:{' '}
                  {report.rule_analysis.rule_score}/100)
                </h4>
                {report.detected_indicators.length === 0 ? (
                  <p className="mt-2.5 flex items-center gap-2 text-xs text-[#86EFAC]">
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-[#22C55E]" />
                    No strong indicators recorded.
                  </p>
                ) : (
                  <ul className="mt-2.5 space-y-2">
                    {report.detected_indicators.map((ind, idx) => (
                      <li
                        key={`${ind}-${idx}`}
                        className="rounded-md border border-[#263449] bg-[#111C30] p-3 text-xs"
                      >
                        <p className="font-semibold text-[#F1F5F9]">{ind}</p>
                        {report.explanations[idx] && (
                          <p className="mt-1 text-[11px] text-[#94A3B8]">
                            {report.explanations[idx]}
                          </p>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {report.recommendations.length > 0 && (
                <div className="rounded-lg border border-[#263449] bg-[#0B1120] p-4">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
                    Recommended Next Steps
                  </h4>
                  <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-[#94A3B8]">
                    {report.recommendations.map((rec, idx) => (
                      <li key={`${rec}-${idx}`}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}

              <p className="border-t border-[#263449] pt-3 text-[11px] text-[#94A3B8]">
                {report.disclaimer} {report.privacy_notice}
              </p>
            </article>
          )}
        </div>
      </div>
    </div>
  )
}
