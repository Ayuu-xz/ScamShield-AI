import { useCallback, useEffect, useState } from 'react'
import {
  History,
  Trash2,
  FileText,
  Loader2,
  AlertTriangle,
  Link2,
  MessageSquareWarning,
  Image as ImageIcon,
  ChevronLeft,
  ChevronRight,
  Search,
  ArrowUpDown,
  Calendar,
  Download,
} from 'lucide-react'
import {
  clearAllHistory,
  deleteHistoryItem,
  downloadScanReport,
  fetchHistory,
} from '../services/api.js'
import { EmptyState, LoadingState, StatusBadge } from './ui/StatusPrimitives.jsx'

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
 * Refined dark-mode Scan History data-table with search, date/type/classification filters,
 * sorting, pagination, delete confirmation, and Open Report action.
 */
export default function ScanHistoryPage({ onNavigate, onOpenReport, onToast }) {
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

  const handleFilterChange = (type, value) => {
    setOffset(0)
    if (type === 'scanType') setScanTypeFilter(value)
    if (type === 'riskLevel') setRiskLevelFilter(value)
    if (type === 'search') setSearchQuery(value)
    if (type === 'dateFrom') setDateFrom(value)
    if (type === 'dateTo') setDateTo(value)
    if (type === 'sortBy') setSortBy(value)
  }

  const handleDeleteOne = async (scanId) => {
    setDeletingId(scanId)
    setError('')
    try {
      await deleteHistoryItem(scanId)
      onToast?.({ type: 'success', message: `Deleted scan record #${scanId}.` })
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
      setOffset(0)
      onToast?.({ type: 'success', message: 'Cleared all scan history records.' })
      await loadHistory()
    } catch (err) {
      setError(err.message || 'Failed to clear scan history.')
    } finally {
      setIsClearingAll(false)
    }
  }

  const handleQuickExport = async (scanId, format) => {
    try {
      await downloadScanReport(scanId, format)
      onToast?.({
        type: 'success',
        message: `Exported ${format.toUpperCase()} report for Scan #${scanId}.`,
      })
    } catch (err) {
      onToast?.({
        type: 'error',
        message: err.message || 'Report export failed.',
      })
    }
  }

  const startRange = total === 0 ? 0 : offset + 1
  const endRange = Math.min(total, offset + items.length)

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-[#F1F5F9] sm:text-xl">Scan History</h2>
          <p className="text-xs text-[#94A3B8]">
            Completed URL, message, and OCR scans stored locally in SQLite
          </p>
        </div>

        {total > 0 && !confirmClearAll && (
          <button
            type="button"
            onClick={() => setConfirmClearAll(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#EF4444]/35 bg-[#EF4444]/12 px-3.5 py-2 text-xs font-semibold text-[#FCA5A5] transition-colors duration-150 hover:bg-[#EF4444]/20"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Clear All
          </button>
        )}
      </div>

      {confirmClearAll && (
        <div
          role="alertdialog"
          aria-label="Confirm clear all scan history"
          className="flex flex-wrap items-center justify-between gap-3 rounded-[10px] border border-[#EF4444]/40 bg-[#1F1218] p-4"
        >
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-[#EF4444]" />
            <div>
              <p className="text-sm font-semibold text-[#FCA5A5]">
                Delete all {total} scan history record{total === 1 ? '' : 's'}?
              </p>
              <p className="text-xs text-[#FCA5A5]/80">
                Deleted records are also removed from analytics and reports. This cannot be undone.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={isClearingAll}
              onClick={() => setConfirmClearAll(false)}
              className="rounded-lg border border-[#263449] bg-[#111C30] px-3 py-1.5 text-xs font-medium text-[#F1F5F9] hover:bg-[#172338]"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={isClearingAll}
              onClick={handleClearAll}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#EF4444] px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-[#DC2626] disabled:opacity-60"
            >
              {isClearingAll && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Confirm Delete All
            </button>
          </div>
        </div>
      )}

      {/* Search, Filters, Date Range, and Sort */}
      <div className="grid gap-3 rounded-[10px] border border-[#263449] bg-[#111C30] p-4 sm:grid-cols-2 lg:grid-cols-6">
        <div className="relative lg:col-span-2">
          <Search className="pointer-events-none absolute top-2.5 left-3 h-3.5 w-3.5 text-[#94A3B8]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            placeholder="Search by Scan ID, URL, or text..."
            aria-label="Search scan history"
            className="w-full rounded-lg border border-[#263449] bg-[#0B1120] py-1.5 pr-3 pl-8 text-xs text-[#F1F5F9] placeholder-[#64748B] focus:border-[#3B82F6] focus:outline-none"
          />
        </div>

        <select
          aria-label="Filter by scan type"
          value={scanTypeFilter}
          onChange={(e) => handleFilterChange('scanType', e.target.value)}
          className="rounded-lg border border-[#263449] bg-[#0B1120] px-3 py-1.5 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
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
          className="rounded-lg border border-[#263449] bg-[#0B1120] px-3 py-1.5 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
        >
          <option value="">All Classifications</option>
          <option value="Dangerous">Dangerous</option>
          <option value="Suspicious">Suspicious</option>
          <option value="Safe">Safe</option>
          <option value="No strong indicators detected">No strong indicators detected</option>
          <option value="Inspection unavailable">Inspection unavailable</option>
        </select>

        <div className="flex items-center gap-1.5">
          <Calendar className="h-3.5 w-3.5 shrink-0 text-[#94A3B8]" />
          <input
            type="date"
            aria-label="Filter from date"
            value={dateFrom}
            onChange={(e) => handleFilterChange('dateFrom', e.target.value)}
            className="w-full rounded-lg border border-[#263449] bg-[#0B1120] px-2 py-1.5 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <input
            type="date"
            aria-label="Filter to date"
            value={dateTo}
            onChange={(e) => handleFilterChange('dateTo', e.target.value)}
            className="w-full rounded-lg border border-[#263449] bg-[#0B1120] px-2 py-1.5 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
          />
          <ArrowUpDown className="h-3.5 w-3.5 shrink-0 text-[#94A3B8]" />
          <select
            aria-label="Sort scan history"
            value={sortBy}
            onChange={(e) => handleFilterChange('sortBy', e.target.value)}
            className="w-full rounded-lg border border-[#263449] bg-[#0B1120] px-2 py-1.5 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
          >
            <option value="date_desc">Newest First</option>
            <option value="date_asc">Oldest First</option>
            <option value="score_desc">Highest Score</option>
            <option value="score_asc">Lowest Score</option>
          </select>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="flex items-center gap-2.5 rounded-[10px] border border-[#EF4444]/40 bg-[#1F1218] p-3.5 text-xs text-[#FCA5A5]"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 text-[#EF4444]" />
          <span>{error}</span>
        </div>
      )}

      {isLoading ? (
        <LoadingState message="Loading scan history..." />
      ) : items.length === 0 ? (
        <EmptyState
          icon={History}
          title="No scan records found"
          description="Run a URL or Message scan to populate your local SQLite scan history."
          action={
            onNavigate && (
              <button
                type="button"
                onClick={() => onNavigate('overview')}
                className="rounded-lg bg-[#3B82F6] px-4 py-2 text-xs font-semibold text-white hover:bg-[#2563EB]"
              >
                Go to Scanner
              </button>
            )
          }
        />
      ) : (
        <>
          {/* Desktop Data Table */}
          <div className="hidden overflow-hidden rounded-[10px] border border-[#263449] bg-[#111C30] md:block">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-[#263449] bg-[#0F172A] text-[11px] font-semibold uppercase tracking-wider text-[#94A3B8]">
                  <tr>
                    <th className="px-4 py-3">ID</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Inspected Input</th>
                    <th className="px-4 py-3">Score</th>
                    <th className="px-4 py-3">Classification</th>
                    <th className="px-4 py-3">Scanned At</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#263449]/70">
                  {items.map((item) => (
                    <tr
                      key={item.id}
                      className="transition-colors duration-150 hover:bg-[#172338]/70"
                    >
                      <td className="px-4 py-3 font-mono text-[#94A3B8]">#{item.id}</td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center gap-1.5 font-medium text-[#F1F5F9]">
                          {item.scan_type === 'url' ? (
                            <Link2 className="h-3.5 w-3.5 text-[#3B82F6]" />
                          ) : item.scan_type === 'message-image' ? (
                            <ImageIcon className="h-3.5 w-3.5 text-[#3B82F6]" />
                          ) : (
                            <MessageSquareWarning className="h-3.5 w-3.5 text-[#3B82F6]" />
                          )}
                          {item.scan_type === 'url'
                            ? 'URL'
                            : item.scan_type === 'message-image'
                              ? 'Image OCR'
                              : 'Message'}
                        </span>
                      </td>
                      <td className="max-w-xs px-4 py-3 font-mono text-[#F1F5F9]">
                        {truncateText(item.input_text)}
                      </td>
                      <td className="px-4 py-3 font-mono font-semibold text-[#F1F5F9]">
                        {item.risk_score}/100
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge label={item.risk_level} />
                      </td>
                      <td className="px-4 py-3 text-[#94A3B8]">
                        {formatDateTime(item.created_at)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => onOpenReport?.(item.id)}
                            className="inline-flex items-center gap-1 rounded-md border border-[#3B82F6]/35 bg-[#3B82F6]/12 px-2.5 py-1 text-[11px] font-semibold text-[#93C5FD] transition-colors duration-150 hover:bg-[#3B82F6]/20"
                          >
                            <FileText className="h-3 w-3" />
                            Open Report
                          </button>
                          <button
                            type="button"
                            onClick={() => handleQuickExport(item.id, 'pdf')}
                            title="Download PDF Report"
                            aria-label={`Export PDF for scan ${item.id}`}
                            className="inline-flex items-center rounded-md border border-[#263449] bg-[#172338] p-1.5 text-[#94A3B8] transition-colors duration-150 hover:text-[#F1F5F9]"
                          >
                            <Download className="h-3 w-3" />
                          </button>
                          <button
                            type="button"
                            disabled={deletingId === item.id}
                            onClick={() => handleDeleteOne(item.id)}
                            aria-label={`Delete scan ${item.id}`}
                            className="inline-flex items-center gap-1 rounded-md border border-[#EF4444]/35 bg-[#EF4444]/12 px-2.5 py-1 text-[11px] font-semibold text-[#FCA5A5] transition-colors duration-150 hover:bg-[#EF4444]/20 disabled:opacity-50"
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
          </div>

          {/* Mobile Cards */}
          <div className="space-y-3 md:hidden">
            {items.map((item) => (
              <article
                key={item.id}
                className="rounded-[10px] border border-[#263449] bg-[#111C30] p-4 text-xs"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[#94A3B8]">
                    #{item.id} •{' '}
                    {item.scan_type === 'url'
                      ? 'URL'
                      : item.scan_type === 'message-image'
                        ? 'Image OCR'
                        : 'Message'}
                  </span>
                  <StatusBadge label={item.risk_level} />
                </div>
                <p className="mt-2 break-all font-mono text-[#F1F5F9]">
                  {truncateText(item.input_text, 85)}
                </p>
                <div className="mt-2 flex items-center justify-between text-[11px] text-[#94A3B8]">
                  <span>Score: {item.risk_score}/100</span>
                  <span>{formatDateTime(item.created_at)}</span>
                </div>
                <div className="mt-3 flex items-center gap-2 border-t border-[#263449] pt-3">
                  <button
                    type="button"
                    onClick={() => onOpenReport?.(item.id)}
                    className="inline-flex flex-1 items-center justify-center gap-1 rounded-md border border-[#3B82F6]/35 bg-[#3B82F6]/12 py-1.5 font-semibold text-[#93C5FD]"
                  >
                    <FileText className="h-3.5 w-3.5" />
                    Open Report
                  </button>
                  <button
                    type="button"
                    disabled={deletingId === item.id}
                    onClick={() => handleDeleteOne(item.id)}
                    className="inline-flex items-center justify-center gap-1 rounded-md border border-[#EF4444]/35 bg-[#EF4444]/12 px-3 py-1.5 font-semibold text-[#FCA5A5] disabled:opacity-50"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete
                  </button>
                </div>
              </article>
            ))}
          </div>

          {/* Pagination */}
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-[#94A3B8]">
            <span>
              Showing {startRange}–{endRange} of {total}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                className="inline-flex items-center gap-1 rounded-lg border border-[#263449] bg-[#111C30] px-3 py-1.5 font-medium text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50 disabled:opacity-40"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                Previous
              </button>
              <button
                type="button"
                disabled={offset + PAGE_SIZE >= total}
                onClick={() => setOffset(offset + PAGE_SIZE)}
                className="inline-flex items-center gap-1 rounded-lg border border-[#263449] bg-[#111C30] px-3 py-1.5 font-medium text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50 disabled:opacity-40"
              >
                Next
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
