import { useEffect, useState } from 'react'
import { History, ShieldAlert, ArrowRight, Link2, MessageSquareWarning } from 'lucide-react'
import ScannerPanel from './ScannerPanel.jsx'
import DetectionResultCard from './DetectionResultCard.jsx'
import { StatusBadge } from './ui/StatusPrimitives.jsx'
import { fetchHistory } from '../services/api.js'

/**
 * Scanner-first Overview dashboard with compact recent scans and concise threat summary.
 */
export default function OverviewPage({
  scannerProps,
  scanResult,
  isScanning,
  apiError,
  onReviewExtractedText,
  onNavigate,
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
      {/* Compact Welcome Strip */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold tracking-tight text-white sm:text-xl">
            URL &amp; Message Threat Scanner
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Inspect suspicious links, messages, and screenshots with defensive read-only analysis.
          </p>
        </div>

        <button
          type="button"
          onClick={() => onNavigate('help')}
          className="text-xs font-medium text-blue-400 transition-colors hover:text-blue-300"
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
        onReviewExtractedText={onReviewExtractedText}
        onOpenThreatAnalysis={() => onNavigate('threat-analysis')}
      />

      {/* Compact Recent Scans & Threat Overview Grid */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <History className="h-4 w-4 text-blue-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Recent Scans ({recentTotal})
              </h3>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('history')}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 hover:text-blue-300"
            >
              View All
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>

          {recentScans.length === 0 ? (
            <p className="py-6 text-center text-xs text-slate-500">
              No saved scans yet. Completed URL and message scans appear here automatically.
            </p>
          ) : (
            <ul className="divide-y divide-slate-800/70">
              {recentScans.map((item) => (
                <li
                  key={item.id}
                  className="flex items-center justify-between gap-3 py-2.5 text-xs"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    {item.scan_type === 'url' ? (
                      <Link2 className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                    ) : (
                      <MessageSquareWarning className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                    )}
                    <span className="truncate font-mono text-slate-200">
                      {item.input_text}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className="font-mono text-[11px] text-slate-400">
                      {item.risk_score}/100
                    </span>
                    <StatusBadge label={item.risk_level} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Small Threat Overview + 2 Short Tips */}
        <div className="space-y-4 rounded-xl border border-slate-800/90 bg-[#0f1623] p-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <ShieldAlert className="h-4 w-4 text-blue-400" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
              Session Overview
            </h3>
          </div>

          <div className="grid grid-cols-2 gap-2.5 text-center">
            <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3">
              <p className="text-xl font-bold text-white">{recentTotal}</p>
              <p className="text-[11px] text-slate-400">Saved Scans</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3">
              <p className="text-xl font-bold text-amber-400">{flaggedCount}</p>
              <p className="text-[11px] text-slate-400">Flagged (Recent 5)</p>
            </div>
          </div>

          <div className="space-y-2 border-t border-slate-800 pt-3 text-[11px] text-slate-400">
            <p>
              • Never click suspicious links or share OTPs/passwords with unverified senders.
            </p>
            <p>
              • A low score never guarantees safety; verify domains via official channels.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
