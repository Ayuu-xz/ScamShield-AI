import { useEffect, useState } from 'react'
import { History, ShieldAlert, ArrowRight, Link2, MessageSquareWarning } from 'lucide-react'
import ScannerPanel from './ScannerPanel.jsx'
import DetectionResultCard from './DetectionResultCard.jsx'
import { StatusBadge } from './ui/StatusPrimitives.jsx'
import { fetchHistory } from '../services/api.js'

/**
 * Scanner-first dark-mode Overview dashboard with compact recent scans and session summary.
 */
export default function OverviewPage({
  scannerProps,
  scanResult,
  isScanning,
  apiError,
  defaultLanguage,
  defaultExpandTechnical,
  onReviewExtractedText,
  onNavigate,
  onOpenReport,
  onToast,
}) {
  const [recentScans, setRecentScans] = useState([])
  const [recentTotal, setRecentTotal] = useState(0)

  useEffect(() => {
    let cancelled = false
    fetchHistory({ limit: 5, offset: 0 })
      .then((data) => {
        if (!cancelled) {
          setRecentScans(data.items || [])
          setRecentTotal(data.total || 0)
        }
      })
      .catch(() => {
        // Keep overview non-blocking if history fetch fails
      })
    return () => {
      cancelled = true
    }
  }, [scanResult])

  const flaggedCount = recentScans.filter(
    (s) => s.risk_level === 'Dangerous' || s.risk_level === 'Suspicious',
  ).length

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold tracking-tight text-[#F1F5F9] sm:text-xl">
            URL &amp; Message Threat Scanner
          </h2>
          <p className="mt-0.5 text-xs text-[#94A3B8]">
            Inspect suspicious links, messages, and screenshots with defensive read-only analysis.
          </p>
        </div>

        <button
          type="button"
          onClick={() => onNavigate('help')}
          className="text-xs font-semibold text-[#3B82F6] transition-colors duration-150 hover:text-[#60A5FA]"
        >
          Scoring &amp; Safety Guide →
        </button>
      </div>

      {/* Primary Scanner */}
      <ScannerPanel {...scannerProps} showModeTabs />

      {/* Active Result */}
      <DetectionResultCard
        scanResult={scanResult}
        isScanning={isScanning}
        apiError={apiError}
        activeMode={scannerProps.activeMode}
        defaultLanguage={defaultLanguage}
        defaultExpandTechnical={defaultExpandTechnical}
        onReviewExtractedText={onReviewExtractedText}
        onOpenReport={onOpenReport}
        onToast={onToast}
      />

      {/* Compact Recent Scans & Session Summary */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-[#263449] pb-3">
            <div className="flex items-center gap-2">
              <History className="h-4 w-4 text-[#3B82F6]" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
                Recent Scans ({recentTotal})
              </h3>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('history')}
              className="inline-flex items-center gap-1 text-xs font-semibold text-[#3B82F6] transition-colors duration-150 hover:text-[#60A5FA]"
            >
              View All
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>

          {recentScans.length === 0 ? (
            <p className="py-6 text-center text-xs text-[#94A3B8]">
              No saved scans yet. Completed URL and message scans appear here automatically.
            </p>
          ) : (
            <ul className="divide-y divide-[#263449]/70">
              {recentScans.map((item) => (
                <li
                  key={item.id}
                  className="flex items-center justify-between gap-3 py-2.5 text-xs"
                >
                  <button
                    type="button"
                    onClick={() => onOpenReport(item.id)}
                    className="flex min-w-0 flex-1 items-center gap-2 text-left transition-colors duration-150 hover:text-[#3B82F6]"
                  >
                    {item.scan_type === 'url' ? (
                      <Link2 className="h-3.5 w-3.5 shrink-0 text-[#94A3B8]" />
                    ) : (
                      <MessageSquareWarning className="h-3.5 w-3.5 shrink-0 text-[#94A3B8]" />
                    )}
                    <span className="truncate font-mono text-[#F1F5F9]">
                      {item.input_text}
                    </span>
                  </button>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className="font-mono text-[11px] text-[#94A3B8]">
                      {item.risk_score}/100
                    </span>
                    <StatusBadge label={item.risk_level} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="space-y-4 rounded-[10px] border border-[#263449] bg-[#111C30] p-4">
          <div className="flex items-center gap-2 border-b border-[#263449] pb-3">
            <ShieldAlert className="h-4 w-4 text-[#3B82F6]" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
              Session Overview
            </h3>
          </div>

          <div className="grid grid-cols-2 gap-2.5 text-center">
            <div className="rounded-lg border border-[#263449] bg-[#172338] p-3">
              <p className="text-xl font-bold text-[#F1F5F9]">{recentTotal}</p>
              <p className="text-[11px] text-[#94A3B8]">Saved Scans</p>
            </div>
            <div className="rounded-lg border border-[#263449] bg-[#172338] p-3">
              <p className="text-xl font-bold text-[#F59E0B]">{flaggedCount}</p>
              <p className="text-[11px] text-[#94A3B8]">Flagged (Recent 5)</p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => onNavigate('analytics')}
            className="w-full rounded-lg border border-[#263449] bg-[#172338] py-2 text-xs font-semibold text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50 hover:bg-[#1E2E48]"
          >
            Open Full Analytics →
          </button>
        </div>
      </div>
    </div>
  )
}
