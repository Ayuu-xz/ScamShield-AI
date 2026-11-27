import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  History,
  Trash2,
  Eye,
  Loader2,
  AlertTriangle,
  Link2,
  MessageSquareWarning,
  Image as ImageIcon,
  ChevronLeft,
  ChevronRight,
  X,
  CheckCircle2,
  Search,
  ArrowUpDown,
  Download,
  FileText,
  Calendar,
  Cpu,
  Globe,
} from 'lucide-react'
import {
  clearAllHistory,
  deleteHistoryItem,
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

const PAGE_SIZE = 10

function truncateText(text, maxLength = 56) {
  if (!text || text.length <= maxLength) return text
  return `${text.slice(0, maxLength)}...`
}

function formatDateTime(isoString) {
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

/**
 * Enterprise Scan History data-table with search, filters, sorting, pagination,
 * delete confirmation, and Scan Details drawer.
 */
export default function ScanHistoryPage({ onNavigate }) {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [scanTypeFilter, setScanTypeFilter] = useState('')
  const [riskLevelFilter, setRiskLevelFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [sortBy, setSortBy] = useState('date_desc')

  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [deletingId, setDeletingId] = useState(null)
  const [confirmClearAll, setConfirmClearAll] = useState(false)
  const [isClearingAll, setIsClearingAll] = useState(false)
  const [exportingKey, setExportingKey] = useState('')

  const [selectedDetail, setSelectedDetail] = useState(null)
  const [isDetailLoading, setIsDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')

  const loadHistory = useCallback(async () => {
    setIsLoading(true)
    setError('')
    try {
      const data = await fetchHistory({
        limit: PAGE_SIZE,
        offset,
        scanType: scanTypeFilter,
        riskLevel: riskLevelFilter,
        search: searchQuery,
        dateFrom,
        dateTo,
        sortBy,
      })
      setItems(data.items || [])
      setTotal(data.total || 0)
    } catch (err) {
      setError(err.message || 'Failed to load scan history.')
    } finally {
      setIsLoading(false)
    }
  }, [offset, scanTypeFilter, riskLevelFilter, searchQuery, dateFrom, dateTo, sortBy])

  useEffect(() => {
    loadHistory()
  }, [loadHistory])

  const displayedItems = useMemo(() => items, [items])

  const handleFilterChange = (type, value) => {
    setOffset(0)
    if (type === 'scanType') setScanTypeFilter(value)
    if (type === 'riskLevel') setRiskLevelFilter(value)
    if (type === 'search') setSearchQuery(value)
    if (type === 'dateFrom') setDateFrom(value)
    if (type === 'dateTo') setDateTo(value)
    if (type === 'sortBy') setSortBy(value)
  }

  const handleViewDetail = async (scanId) => {
    setIsDetailLoading(true)
    setDetailError('')
    setSelectedDetail(null)
    try {
      const report = await fetchScanReport(scanId)
      setSelectedDetail(report)
    } catch (err) {
      setDetailError(err.message || 'Unable to load scan report.')
    } finally {
      setIsDetailLoading(false)
    }
  }

  const handleExportReport = async (scanId, format) => {
    const key = `${scanId}-${format}`
    setExportingKey(key)
    setError('')
    try {
      await downloadScanReport(scanId, format)
    } catch (err) {
      setError(err.message || `Failed to export ${format.toUpperCase()} report.`)
    } finally {
      setExportingKey('')
    }
  }

  const handleDeleteOne = async (scanId) => {
    setDeletingId(scanId)
    setError('')
    try {
      await deleteHistoryItem(scanId)
      if (selectedDetail?.id === scanId) setSelectedDetail(null)
      if (items.length === 1 && offset > 0) {
        setOffset(Math.max(0, offset - PAGE_SIZE))
      } else {
        await loadHistory()
      }
    } catch (err) {
      setError(err.message || 'Failed to delete scan record.')
    } finally {
      setDeletingId(null)
    }
  }

  const handleClearAll = async () => {
    setIsClearingAll(true)
    setError('')
    try {
      await clearAllHistory()
      setConfirmClearAll(false)
      setSelectedDetail(null)
      setOffset(0)
      await loadHistory()
    } catch (err) {
      setError(err.message || 'Failed to clear scan history.')
    } finally {
      setIsClearingAll(false)
    }
  }

  const startRange = total === 0 ? 0 : offset + 1
  const endRange = Math.min(total, offset + items.length)

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white sm:text-xl">Scan History</h2>
          <p className="text-xs text-slate-400">
            Completed URL, message, and OCR scans stored locally in SQLite
          </p>
        </div>

        {total > 0 && !confirmClearAll && (
          <button
            type="button"
            onClick={() => setConfirmClearAll(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-2 text-xs font-semibold text-rose-300 transition-colors hover:bg-rose-500/20"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Clear All
          </button>
        )}
      </div>

      {/* Confirmation dialog */}
      {confirmClearAll && (
        <div
          role="alertdialog"
          aria-label="Confirm clear all scan history"
          className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-rose-500/50 bg-rose-950/30 p-4"
        >
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
            <div>
              <p className="text-sm font-semibold text-rose-200">
                Delete all {total} scan history record{total === 1 ? '' : 's'}?
              </p>
              <p className="text-xs text-rose-200/80">This action cannot be undone.</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={isClearingAll}
              onClick={() => setConfirmClearAll(false)}
              className="rounded-lg border border-slate-700 bg-[#0f1623] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={isClearingAll}
              onClick={handleClearAll}
              className="inline-flex items-center gap-1.5 rounded-lg bg-rose-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-rose-500 disabled:opacity-60"
            >
              {isClearingAll && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Confirm Delete All
            </button>
          </div>
        </div>
      )}

      {/* Search, Filters, Date Range, and Sort Toolbar */}
      <div className="grid gap-3 rounded-xl border border-slate-800/90 bg-[#0f1623] p-4 sm:grid-cols-2 lg:grid-cols-6">
        <div className="relative lg:col-span-2">
          <Search className="pointer-events-none absolute top-2.5 left-3 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            placeholder="Search by Scan ID, URL, or text..."
            aria-label="Search scan history"
            className="w-full rounded-lg border border-slate-700/80 bg-[#090d16] py-1.5 pr-3 pl-8 text-xs text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <select
          aria-label="Filter by scan type"
          value={scanTypeFilter}
          onChange={(e) => handleFilterChange('scanType', e.target.value)}
          className="rounded-lg border border-slate-700/80 bg-[#090d16] px-3 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
        >
          <option value="">All Scan Types</option>
          <option value="url">URL</option>
          <option value="message">Message</option>
          <option value="message-image">Image OCR</option>
        </select>

        <select
          aria-label="Filter by risk level"
          value={riskLevelFilter}
          onChange={(e) => handleFilterChange('riskLevel', e.target.value)}
          className="rounded-lg border border-slate-700/80 bg-[#090d16] px-3 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
        >
          <option value="">All Classifications</option>
          <option value="Dangerous">Dangerous</option>
          <option value="Suspicious">Suspicious</option>
          <option value="Safe">Safe</option>
          <option value="No strong indicators detected">No strong indicators detected</option>
          <option value="Inspection unavailable">Inspection unavailable</option>
        </select>

        <div className="flex items-center gap-1.5">
          <Calendar className="h-3.5 w-3.5 shrink-0 text-slate-500" />
          <input
            type="date"
            aria-label="Filter from date"
            value={dateFrom}
            onChange={(e) => handleFilterChange('dateFrom', e.target.value)}
            title="From date"
            className="w-full rounded-lg border border-slate-700/80 bg-[#090d16] px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <input
            type="date"
            aria-label="Filter to date"
            value={dateTo}
            onChange={(e) => handleFilterChange('dateTo', e.target.value)}
            title="To date"
            className="w-full rounded-lg border border-slate-700/80 bg-[#090d16] px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
          />
          <ArrowUpDown className="h-3.5 w-3.5 shrink-0 text-slate-500" />
          <select
            aria-label="Sort scan history"
            value={sortBy}
            onChange={(e) => handleFilterChange('sortBy', e.target.value)}
            className="w-full rounded-lg border border-slate-700/80 bg-[#090d16] px-2.5 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
          >
            <option value="date_desc">Newest First</option>
            <option value="date_asc">Oldest First</option>
            <option value="score_desc">Highest Score</option>
            <option value="score_asc">Lowest Score</option>
          </select>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div
          role="alert"
          className="flex items-center gap-2.5 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3.5 text-xs text-rose-200"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Table / Empty / Loading */}
      {isLoading ? (
        <LoadingState message="Loading scan history..." />
      ) : displayedItems.length === 0 ? (
        <EmptyState
          icon={History}
          title="No scan records found"
          description="Run a URL or Message scan to populate your local SQLite scan history."
          action={
            onNavigate && (
              <button
                type="button"
                onClick={() => onNavigate('overview')}
                className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500"
              >
                Go to Scanner
              </button>
            )
          }
        />
      ) : (
        <>
          {/* Desktop Table */}
          <div className="hidden overflow-hidden rounded-xl border border-slate-800/90 bg-[#0f1623] md:block">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-[#0c121e] text-[11px] uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Submitted Input</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Classification</th>
                  <th className="px-4 py-3">Date &amp; Time</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {displayedItems.map((item) => (
                  <tr key={item.id} className="transition-colors hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono text-slate-400">#{item.id}</td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#090d16] px-2 py-0.5 text-[11px] font-medium text-slate-200">
                        {item.scan_type === 'url' ? (
                          <Link2 className="h-3 w-3 text-blue-400" />
                        ) : item.scan_type === 'message-image' ? (
                          <ImageIcon className="h-3 w-3 text-blue-400" />
                        ) : (
                          <MessageSquareWarning className="h-3 w-3 text-blue-400" />
                        )}
                        {item.scan_type === 'url'
                          ? 'URL'
                          : item.scan_type === 'message-image'
                            ? 'Image OCR'
                            : 'Message'}
                      </span>
                    </td>
                    <td className="max-w-xs px-4 py-3 font-mono text-slate-200">
                      {truncateText(item.input_text)}
                    </td>
                    <td className="px-4 py-3 font-mono font-semibold text-slate-200">
                      {item.risk_score}/100
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge label={item.risk_level} />
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {formatDateTime(item.created_at)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleViewDetail(item.id)}
                          className="inline-flex items-center gap-1 rounded-md border border-blue-500/30 bg-blue-500/10 px-2.5 py-1 text-[11px] font-medium text-blue-300 hover:bg-blue-500/20"
                        >
                          <Eye className="h-3 w-3" />
                          Details
                        </button>
                        <button
                          type="button"
                          disabled={deletingId === item.id}
                          onClick={() => handleDeleteOne(item.id)}
                          aria-label={`Delete scan ${item.id}`}
                          className="inline-flex items-center gap-1 rounded-md border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-[11px] font-medium text-rose-300 hover:bg-rose-500/20 disabled:opacity-50"
                        >
                          {deletingId === item.id ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Trash2 className="h-3 w-3" />
                          )}
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Mobile Cards */}
          <div className="space-y-3 md:hidden">
            {displayedItems.map((item) => (
              <article
                key={item.id}
                className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-4 text-xs"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-slate-400">
                    #{item.id} •{' '}
                    {item.scan_type === 'url'
                      ? 'URL'
                      : item.scan_type === 'message-image'
                        ? 'Image OCR'
                        : 'Message'}
                  </span>
                  <StatusBadge label={item.risk_level} />
                </div>
                <p className="mt-2 break-all font-mono text-slate-200">
                  {truncateText(item.input_text, 85)}
                </p>
                <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                  <span>Score: {item.risk_score}/100</span>
                  <span>{formatDateTime(item.created_at)}</span>
                </div>
                <div className="mt-3 flex items-center gap-2 border-t border-slate-800 pt-3">
                  <button
                    type="button"
                    onClick={() => handleViewDetail(item.id)}
                    className="inline-flex flex-1 items-center justify-center gap-1 rounded-md border border-blue-500/30 bg-blue-500/10 py-1.5 font-medium text-blue-300"
                  >
                    <Eye className="h-3.5 w-3.5" />
                    Details
                  </button>
                  <button
                    type="button"
                    disabled={deletingId === item.id}
                    onClick={() => handleDeleteOne(item.id)}
                    className="inline-flex items-center justify-center gap-1 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 font-medium text-rose-300 disabled:opacity-50"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete
                  </button>
                </div>
              </article>
            ))}
          </div>

          {/* Pagination */}
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
            <span>
              Showing {startRange}–{endRange} of {total}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-[#0f1623] px-3 py-1.5 font-medium text-slate-300 hover:border-blue-500/40 disabled:opacity-40"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                Previous
              </button>
              <button
                type="button"
                disabled={offset + PAGE_SIZE >= total}
                onClick={() => setOffset(offset + PAGE_SIZE)}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-[#0f1623] px-3 py-1.5 font-medium text-slate-300 hover:border-blue-500/40 disabled:opacity-40"
              >
                Next
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </>
      )}

      {/* Detailed Scan Report Drawer */}
      {(isDetailLoading || detailError || selectedDetail) && (
        <div className="rounded-xl border border-blue-500/30 bg-[#0f1623] p-5 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3.5">
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-blue-400" />
              <h3 className="text-sm font-bold text-white">
                Detailed Scan Report {selectedDetail ? `#${selectedDetail.scan_id}` : ''}
              </h3>
            </div>
            <div className="flex items-center gap-2">
              {selectedDetail && (
                <>
                  <button
                    type="button"
                    disabled={exportingKey === `${selectedDetail.scan_id}-pdf`}
                    onClick={() => handleExportReport(selectedDetail.scan_id, 'pdf')}
                    className="inline-flex items-center gap-1 rounded-lg border border-blue-500/40 bg-blue-500/10 px-3 py-1.5 text-xs font-semibold text-blue-300 hover:bg-blue-500/20 disabled:opacity-50"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Export PDF
                  </button>
                  <button
                    type="button"
                    disabled={exportingKey === `${selectedDetail.scan_id}-json`}
                    onClick={() => handleExportReport(selectedDetail.scan_id, 'json')}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-[#090d16] px-3 py-1.5 text-xs font-semibold text-slate-200 hover:border-blue-500/40 disabled:opacity-50"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Export JSON
                  </button>
                </>
              )}
              <button
                type="button"
                onClick={() => {
                  setSelectedDetail(null)
                  setDetailError('')
                }}
                aria-label="Close scan report"
                className="rounded-lg border border-slate-800 bg-[#090d16] p-1.5 text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          {isDetailLoading && <LoadingState message="Loading detailed scan report..." />}

          {detailError && (
            <div className="mt-4 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">
              {detailError}
            </div>
          )}

          {selectedDetail && (
            <div className="mt-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
                <span>
                  Scan Type:{' '}
                  <strong className="uppercase text-slate-200">{selectedDetail.scan_type}</strong>
                </span>
                <span>Sources: {selectedDetail.analysis_sources.join(' · ')}</span>
                <span>{formatDateTime(selectedDetail.created_at)}</span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5">
                <p className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                  Inspected Target / Privacy-Sanitized Excerpt
                </p>
                <p className="mt-1.5 break-all font-mono text-xs text-slate-200">
                  {selectedDetail.input_preview}
                </p>
              </div>

              <div className="flex flex-wrap items-start justify-between gap-4 rounded-lg border border-slate-800 bg-[#090d16] p-4">
                <div className="min-w-[200px] flex-1">
                  <RiskScoreDisplay
                    score={selectedDetail.risk_score}
                    level={selectedDetail.risk_level}
                  />
                  <p className="mt-2 text-xs text-slate-300">
                    {selectedDetail.classification_summary}
                  </p>
                </div>
                <StatusBadge label={selectedDetail.risk_level} size="md" />
              </div>

              {/* Rule, ML, and Threat Intel Breakdown */}
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5 text-xs">
                  <div className="flex items-center gap-2 font-semibold uppercase tracking-wider text-slate-300">
                    <Cpu className="h-3.5 w-3.5 text-blue-400" />
                    ML Prediction
                  </div>
                  {selectedDetail.ml_analysis.available ? (
                    <div className="mt-2 space-y-1 text-slate-300">
                      <p>
                        Prediction:{' '}
                        <strong className="text-white">
                          {selectedDetail.ml_analysis.prediction}
                        </strong>
                      </p>
                      <p>
                        Confidence:{' '}
                        {selectedDetail.ml_analysis.confidence !== null
                          ? `${Math.round(selectedDetail.ml_analysis.confidence * 100)}%`
                          : 'N/A'}
                      </p>
                    </div>
                  ) : (
                    <p className="mt-2 text-slate-400">
                      Unavailable — {selectedDetail.ml_analysis.note}
                    </p>
                  )}
                </div>

                <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5 text-xs">
                  <div className="flex items-center gap-2 font-semibold uppercase tracking-wider text-slate-300">
                    <Globe className="h-3.5 w-3.5 text-blue-400" />
                    Threat Intelligence
                  </div>
                  <div className="mt-2 space-y-1 text-slate-300">
                    <p>
                      Status:{' '}
                      <strong className="text-white">
                        {selectedDetail.threat_intelligence.reputation_status}
                      </strong>{' '}
                      ({selectedDetail.threat_intelligence.provider_name})
                    </p>
                    {selectedDetail.threat_intelligence.note && (
                      <p className="text-slate-400">{selectedDetail.threat_intelligence.note}</p>
                    )}
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Detected Indicators &amp; Rule Analysis (Rule Score:{' '}
                  {selectedDetail.rule_analysis.rule_score}/100)
                </h4>
                {selectedDetail.detected_indicators.length === 0 ? (
                  <p className="mt-2 flex items-center gap-2 text-xs text-emerald-300">
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                    No strong indicators recorded.
                  </p>
                ) : (
                  <ul className="mt-2.5 space-y-2">
                    {selectedDetail.detected_indicators.map((ind, idx) => (
                      <li
                        key={`${ind}-${idx}`}
                        className="rounded border border-slate-800 bg-[#0f1623] p-2.5 text-xs"
                      >
                        <p className="font-semibold text-slate-100">{ind}</p>
                        {selectedDetail.explanations[idx] && (
                          <p className="mt-1 text-[11px] text-slate-400">
                            {selectedDetail.explanations[idx]}
                          </p>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {selectedDetail.recommendations.length > 0 && (
                <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Recommended Next Steps
                  </h4>
                  <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-slate-300">
                    {selectedDetail.recommendations.map((rec, idx) => (
                      <li key={`${rec}-${idx}`}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}

              <p className="text-[11px] text-slate-500">
                {selectedDetail.disclaimer} {selectedDetail.privacy_notice}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
