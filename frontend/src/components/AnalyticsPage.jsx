import { useCallback, useEffect, useState } from 'react'
import {
  BarChart3,
  RefreshCw,
  ShieldAlert,
  Link2,
  MessageSquareWarning,
  Cpu,
  Globe,
  AlertTriangle,
  Calendar,
  TrendingUp,
} from 'lucide-react'
import { fetchAnalytics } from '../services/api.js'
import { EmptyState, LoadingState } from './ui/StatusPrimitives.jsx'

/**
 * Refined dark-mode Analytics Dashboard computed strictly from real SQLite scan records.
 */
export default function AnalyticsPage({ onNavigate }) {
  const [analytics, setAnalytics] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  const [scanType, setScanType] = useState('')
  const [riskLevel, setRiskLevel] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [trendMode, setTrendMode] = useState('daily')

  const loadAnalytics = useCallback(async () => {
    setIsLoading(true)
    setError('')
    try {
      const data = await fetchAnalytics({ scanType, riskLevel, dateFrom, dateTo })
      setAnalytics(data)
    } catch (err) {
      setError(err.message || 'Failed to load scan analytics.')
    } finally {
      setIsLoading(false)
    }
  }, [scanType, riskLevel, dateFrom, dateTo])

  useEffect(() => {
    loadAnalytics()
  }, [loadAnalytics])

  const trends =
    trendMode === 'weekly'
      ? analytics?.weekly_trends || []
      : analytics?.daily_trends || []
  const maxTrendTotal = Math.max(1, ...trends.map((t) => t.total))

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-[#F1F5F9] sm:text-xl">
            Analytics &amp; Threat Telemetry
          </h2>
          <p className="mt-0.5 text-xs text-[#94A3B8]">
            Real-time metrics computed directly from stored SQLite scan records
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onNavigate('history')}
            className="rounded-lg border border-[#263449] bg-[#111C30] px-3 py-1.5 text-xs font-medium text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50"
          >
            Open Scan History →
          </button>
          <button
            type="button"
            onClick={loadAnalytics}
            disabled={isLoading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#3B82F6]/35 bg-[#3B82F6]/12 px-3 py-1.5 text-xs font-semibold text-[#93C5FD] transition-colors duration-150 hover:bg-[#3B82F6]/20 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="grid gap-3 rounded-[10px] border border-[#263449] bg-[#111C30] p-4 sm:grid-cols-2 lg:grid-cols-4">
        <select
          aria-label="Analytics filter by scan type"
          value={scanType}
          onChange={(e) => setScanType(e.target.value)}
          className="rounded-lg border border-[#263449] bg-[#0B1120] px-3 py-1.5 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
        >
          <option value="">All Scan Types</option>
          <option value="url">URL</option>
          <option value="message">Message</option>
          <option value="message-image">Image OCR</option>
        </select>

        <select
          aria-label="Analytics filter by classification"
          value={riskLevel}
          onChange={(e) => setRiskLevel(e.target.value)}
          className="rounded-lg border border-[#263449] bg-[#0B1120] px-3 py-1.5 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
        >
          <option value="">All Classifications</option>
          <option value="Dangerous">Dangerous</option>
          <option value="Suspicious">Suspicious</option>
          <option value="Safe">Safe</option>
          <option value="No strong indicators detected">No strong indicators detected</option>
          <option value="Inspection unavailable">Inspection unavailable</option>
        </select>

        <div className="flex items-center gap-2">
          <Calendar className="h-3.5 w-3.5 shrink-0 text-[#94A3B8]" />
          <input
            type="date"
            aria-label="Analytics start date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            className="w-full rounded-lg border border-[#263449] bg-[#0B1120] px-2.5 py-1.5 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <Calendar className="h-3.5 w-3.5 shrink-0 text-[#94A3B8]" />
          <input
            type="date"
            aria-label="Analytics end date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            className="w-full rounded-lg border border-[#263449] bg-[#0B1120] px-2.5 py-1.5 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
          />
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
        <LoadingState message="Calculating analytics from stored scan records..." />
      ) : !analytics || !analytics.has_data ? (
        <EmptyState
          icon={BarChart3}
          title="No historical scan data available"
          description="Run URL, Message, or Screenshot scans—or adjust your active filters—to view real analytics."
          action={
            <button
              type="button"
              onClick={() => onNavigate('overview')}
              className="rounded-lg bg-[#3B82F6] px-4 py-2 text-xs font-semibold text-white hover:bg-[#2563EB]"
            >
              Go to Scanner
            </button>
          }
        />
      ) : (
        <>
          {/* KPI Cards */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-4">
              <div className="flex items-center justify-between text-xs font-medium text-[#94A3B8]">
                <span>Total Scans</span>
                <BarChart3 className="h-4 w-4 text-[#3B82F6]" />
              </div>
              <p className="mt-2 text-2xl font-bold text-[#F1F5F9]">{analytics.total_scans}</p>
              <p className="mt-1 text-[11px] text-[#94A3B8]">
                Avg Risk Score: {analytics.average_risk_score ?? 0}/100
              </p>
            </div>

            <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-4">
              <div className="flex items-center justify-between text-xs font-medium text-[#94A3B8]">
                <span>URL Scans</span>
                <Link2 className="h-4 w-4 text-[#3B82F6]" />
              </div>
              <p className="mt-2 text-2xl font-bold text-[#F1F5F9]">{analytics.url_scans}</p>
              <p className="mt-1 text-[11px] text-[#94A3B8]">
                {Math.round((analytics.url_scans / analytics.total_scans) * 100)}% of total volume
              </p>
            </div>

            <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-4">
              <div className="flex items-center justify-between text-xs font-medium text-[#94A3B8]">
                <span>Message &amp; OCR Scans</span>
                <MessageSquareWarning className="h-4 w-4 text-[#3B82F6]" />
              </div>
              <p className="mt-2 text-2xl font-bold text-[#F1F5F9]">{analytics.message_scans}</p>
              <p className="mt-1 text-[11px] text-[#94A3B8]">
                Includes {analytics.message_image_scans} screenshot OCR scan(s)
              </p>
            </div>

            <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-4">
              <div className="flex items-center justify-between text-xs font-medium text-[#94A3B8]">
                <span>Flagged Rate</span>
                <ShieldAlert className="h-4 w-4 text-[#F59E0B]" />
              </div>
              <p className="mt-2 text-2xl font-bold text-[#F59E0B]">{analytics.high_risk_rate}%</p>
              <p className="mt-1 text-[11px] text-[#94A3B8]">
                {analytics.classifications.dangerous} Dangerous · {analytics.classifications.suspicious} Suspicious
              </p>
            </div>
          </div>

          {/* Classification & Risk Distribution */}
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
                Classification Breakdown
              </h3>
              <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
                {[
                  {
                    label: 'Dangerous',
                    count: analytics.classifications.dangerous,
                    color: 'text-[#FCA5A5] border-[#EF4444]/35 bg-[#EF4444]/12',
                  },
                  {
                    label: 'Suspicious',
                    count: analytics.classifications.suspicious,
                    color: 'text-[#FCD34D] border-[#F59E0B]/35 bg-[#F59E0B]/12',
                  },
                  {
                    label: 'Safe',
                    count: analytics.classifications.safe,
                    color: 'text-[#86EFAC] border-[#22C55E]/35 bg-[#22C55E]/12',
                  },
                  {
                    label: 'No Strong Indicators',
                    count: analytics.classifications.no_strong_indicators,
                    color: 'text-[#93C5FD] border-[#3B82F6]/35 bg-[#3B82F6]/12',
                  },
                  {
                    label: 'Inspection Unavailable',
                    count: analytics.classifications.inspection_unavailable,
                    color: 'text-[#94A3B8] border-[#263449] bg-[#172338]',
                  },
                ].map((item) => (
                  <div key={item.label} className={`rounded-lg border p-3 ${item.color}`}>
                    <p className="text-xl font-bold">{item.count}</p>
                    <p className="mt-0.5 text-[11px] font-medium">{item.label}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
                Risk Score Distribution
              </h3>
              <div className="mt-4 space-y-3">
                {analytics.risk_distribution.map((bucket) => (
                  <div key={bucket.label} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium text-[#F1F5F9]">{bucket.label}</span>
                      <span className="font-mono text-[#94A3B8]">
                        {bucket.count} ({bucket.percentage}%)
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-[#172338]">
                      <div
                        className={`h-full rounded-full transition-all duration-200 ${
                          bucket.min_score >= 75
                            ? 'bg-[#EF4444]'
                            : bucket.min_score >= 50
                              ? 'bg-[#F97316]'
                              : bucket.min_score >= 25
                                ? 'bg-[#F59E0B]'
                                : 'bg-[#22C55E]'
                        }`}
                        style={{
                          width: `${Math.max(bucket.count > 0 ? 4 : 0, bucket.percentage)}%`,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Daily & Weekly Trends */}
          <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-[#3B82F6]" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
                  Scan Trends ({trendMode === 'weekly' ? 'Weekly' : 'Daily'})
                </h3>
              </div>

              <div className="flex items-center gap-4">
                <div className="hidden items-center gap-3 text-[11px] text-[#94A3B8] sm:flex">
                  <span className="inline-flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-[#22C55E]" /> Safe
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-[#F59E0B]" /> Suspicious
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-[#EF4444]" /> Dangerous
                  </span>
                </div>

                <div className="inline-flex rounded-lg border border-[#263449] bg-[#0B1120] p-0.5 text-xs">
                  <button
                    type="button"
                    onClick={() => setTrendMode('daily')}
                    className={`rounded-md px-3 py-1 font-medium transition-colors duration-150 ${
                      trendMode === 'daily'
                        ? 'bg-[#3B82F6] text-white'
                        : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                    }`}
                  >
                    Daily
                  </button>
                  <button
                    type="button"
                    onClick={() => setTrendMode('weekly')}
                    className={`rounded-md px-3 py-1 font-medium transition-colors duration-150 ${
                      trendMode === 'weekly'
                        ? 'bg-[#3B82F6] text-white'
                        : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                    }`}
                  >
                    Weekly
                  </button>
                </div>
              </div>
            </div>

            {trends.length === 0 ? (
              <p className="py-6 text-center text-xs text-[#94A3B8]">
                No trend buckets available for the selected filters.
              </p>
            ) : (
              <div className="mt-5 flex items-end gap-2 overflow-x-auto pb-2">
                {trends.map((point) => {
                  const totalHeight = Math.max(12, Math.round((point.total / maxTrendTotal) * 120))
                  return (
                    <div
                      key={point.period}
                      className="flex min-w-[56px] flex-1 flex-col items-center gap-1.5"
                      title={`${point.period}: ${point.total} total (${point.safe} safe, ${point.suspicious} suspicious, ${point.dangerous} dangerous)`}
                    >
                      <span className="font-mono text-[10px] text-[#94A3B8]">{point.total}</span>
                      <div
                        className="flex w-8 flex-col-reverse overflow-hidden rounded-t bg-[#172338]"
                        style={{ height: `${totalHeight}px` }}
                      >
                        {point.safe > 0 && (
                          <div
                            className="w-full bg-[#22C55E]"
                            style={{ height: `${(point.safe / point.total) * 100}%` }}
                          />
                        )}
                        {point.suspicious > 0 && (
                          <div
                            className="w-full bg-[#F59E0B]"
                            style={{ height: `${(point.suspicious / point.total) * 100}%` }}
                          />
                        )}
                        {point.dangerous > 0 && (
                          <div
                            className="w-full bg-[#EF4444]"
                            style={{ height: `${(point.dangerous / point.total) * 100}%` }}
                          />
                        )}
                      </div>
                      <span className="truncate font-mono text-[10px] text-[#94A3B8]">
                        {point.period.slice(-5)}
                      </span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Top Indicators + ML & Threat Intel Telemetry */}
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5 lg:col-span-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
                Most Frequently Detected Indicators
              </h3>
              {analytics.top_indicators.length === 0 ? (
                <p className="py-6 text-xs text-[#94A3B8]">
                  No threat indicators have been recorded in the matching scans.
                </p>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-[#263449] text-[11px] uppercase text-[#94A3B8]">
                      <tr>
                        <th className="py-2 pr-4">Indicator</th>
                        <th className="py-2 text-right">Detections</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#263449]/70">
                      {analytics.top_indicators.map((item) => (
                        <tr key={item.indicator}>
                          <td className="py-2 pr-4 font-medium text-[#F1F5F9]">
                            {item.indicator}
                          </td>
                          <td className="py-2 text-right font-mono font-semibold text-[#3B82F6]">
                            {item.count}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="space-y-4">
              <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-4">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
                  <Cpu className="h-4 w-4 text-[#3B82F6]" />
                  ML Usage Statistics
                </div>
                {analytics.ml_stats.recorded_scans === 0 ? (
                  <p className="mt-2 text-xs text-[#94A3B8]">
                    No ML telemetry recorded on stored scans yet.
                  </p>
                ) : (
                  <dl className="mt-3 space-y-1.5 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-[#94A3B8]">Recorded Scans</dt>
                      <dd className="font-mono font-semibold text-[#F1F5F9]">
                        {analytics.ml_stats.recorded_scans}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-[#94A3B8]">ML Available</dt>
                      <dd className="font-mono font-semibold text-[#86EFAC]">
                        {analytics.ml_stats.available_scans}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-[#94A3B8]">ML Flagged</dt>
                      <dd className="font-mono font-semibold text-[#FCD34D]">
                        {analytics.ml_stats.flagged_predictions}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-[#94A3B8]">Avg Confidence</dt>
                      <dd className="font-mono font-semibold text-[#F1F5F9]">
                        {analytics.ml_stats.average_confidence !== null
                          ? `${Math.round(analytics.ml_stats.average_confidence * 100)}%`
                          : 'Unavailable'}
                      </dd>
                    </div>
                  </dl>
                )}
              </div>

              <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-4">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#F1F5F9]">
                  <Globe className="h-4 w-4 text-[#3B82F6]" />
                  Threat Intel Matches
                </div>
                {analytics.threat_intel_stats.recorded_scans === 0 ? (
                  <p className="mt-2 text-xs text-[#94A3B8]">
                    No threat intelligence telemetry recorded yet.
                  </p>
                ) : (
                  <dl className="mt-3 space-y-1.5 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-[#94A3B8]">Malicious Matches</dt>
                      <dd className="font-mono font-semibold text-[#FCA5A5]">
                        {analytics.threat_intel_stats.malicious_matches}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-[#94A3B8]">Clean Checks</dt>
                      <dd className="font-mono font-semibold text-[#86EFAC]">
                        {analytics.threat_intel_stats.clean_checks}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-[#94A3B8]">Unavailable</dt>
                      <dd className="font-mono font-semibold text-[#94A3B8]">
                        {analytics.threat_intel_stats.unavailable_checks}
                      </dd>
                    </div>
                  </dl>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
