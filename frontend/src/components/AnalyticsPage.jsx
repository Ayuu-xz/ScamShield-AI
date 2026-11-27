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
 * Enterprise Analytics & Reporting Dashboard powered strictly by real SQLite scan records.
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
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white sm:text-xl">
            Analytics &amp; Threat Telemetry
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Real-time metrics computed directly from stored SQLite scan records
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onNavigate('history')}
            className="rounded-lg border border-slate-700 bg-[#0f1623] px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-blue-500/40 hover:text-white"
          >
            Open Scan History →
          </button>
          <button
            type="button"
            onClick={loadAnalytics}
            disabled={isLoading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-1.5 text-xs font-semibold text-blue-300 hover:bg-blue-500/20 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="grid gap-3 rounded-xl border border-slate-800/90 bg-[#0f1623] p-4 sm:grid-cols-2 lg:grid-cols-4">
        <select
          aria-label="Analytics filter by scan type"
          value={scanType}
          onChange={(e) => setScanType(e.target.value)}
          className="rounded-lg border border-slate-700/80 bg-[#090d16] px-3 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
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
          className="rounded-lg border border-slate-700/80 bg-[#090d16] px-3 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
        >
          <option value="">All Classifications</option>
          <option value="Dangerous">Dangerous</option>
          <option value="Suspicious">Suspicious</option>
          <option value="Safe">Safe</option>
          <option value="No strong indicators detected">No strong indicators detected</option>
          <option value="Inspection unavailable">Inspection unavailable</option>
        </select>

        <div className="flex items-center gap-2">
          <Calendar className="h-3.5 w-3.5 shrink-0 text-slate-500" />
          <input
            type="date"
            aria-label="Analytics start date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            className="w-full rounded-lg border border-slate-700/80 bg-[#090d16] px-2.5 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <Calendar className="h-3.5 w-3.5 shrink-0 text-slate-500" />
          <input
            type="date"
            aria-label="Analytics end date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            className="w-full rounded-lg border border-slate-700/80 bg-[#090d16] px-2.5 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Error */}
      {error && (
        <div
          role="alert"
          className="flex items-center gap-2.5 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3.5 text-xs text-rose-200"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Loading / Empty / Data */}
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
              className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500"
            >
              Go to Scanner
            </button>
          }
        />
      ) : (
        <>
          {/* KPI Cards */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Total Scans</span>
                <BarChart3 className="h-4 w-4 text-blue-400" />
              </div>
              <p className="mt-2 text-2xl font-bold text-white">{analytics.total_scans}</p>
              <p className="mt-1 text-[11px] text-slate-400">
                Avg Risk Score: {analytics.average_risk_score ?? 0}/100
              </p>
            </div>

            <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>URL Scans</span>
                <Link2 className="h-4 w-4 text-sky-400" />
              </div>
              <p className="mt-2 text-2xl font-bold text-white">{analytics.url_scans}</p>
              <p className="mt-1 text-[11px] text-slate-400">
                {Math.round((analytics.url_scans / analytics.total_scans) * 100)}% of total volume
              </p>
            </div>

            <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Message &amp; OCR Scans</span>
                <MessageSquareWarning className="h-4 w-4 text-indigo-400" />
              </div>
              <p className="mt-2 text-2xl font-bold text-white">{analytics.message_scans}</p>
              <p className="mt-1 text-[11px] text-slate-400">
                Includes {analytics.message_image_scans} screenshot OCR scan(s)
              </p>
            </div>

            <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Flagged Rate</span>
                <ShieldAlert className="h-4 w-4 text-amber-400" />
              </div>
              <p className="mt-2 text-2xl font-bold text-amber-400">{analytics.high_risk_rate}%</p>
              <p className="mt-1 text-[11px] text-slate-400">
                {analytics.classifications.dangerous} Dangerous · {analytics.classifications.suspicious} Suspicious
              </p>
            </div>
          </div>

          {/* Classification & Risk Distribution */}
          <div className="grid gap-4 lg:grid-cols-2">
            {/* Classification Breakdown */}
            <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Classification Breakdown
              </h3>
              <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
                {[
                  {
                    label: 'Dangerous',
                    count: analytics.classifications.dangerous,
                    color: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
                  },
                  {
                    label: 'Suspicious',
                    count: analytics.classifications.suspicious,
                    color: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
                  },
                  {
                    label: 'Safe',
                    count: analytics.classifications.safe,
                    color: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
                  },
                  {
                    label: 'No Strong Indicators',
                    count: analytics.classifications.no_strong_indicators,
                    color: 'text-sky-300 border-sky-500/30 bg-sky-500/10',
                  },
                  {
                    label: 'Inspection Unavailable',
                    count: analytics.classifications.inspection_unavailable,
                    color: 'text-slate-300 border-slate-700 bg-slate-800/40',
                  },
                ].map((item) => (
                  <div
                    key={item.label}
                    className={`rounded-lg border p-3 ${item.color}`}
                  >
                    <p className="text-xl font-bold">{item.count}</p>
                    <p className="mt-0.5 text-[11px] opacity-90">{item.label}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Risk Score Distribution */}
            <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Risk Score Distribution
              </h3>
              <div className="mt-4 space-y-3">
                {analytics.risk_distribution.map((bucket) => (
                  <div key={bucket.label} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-300">{bucket.label}</span>
                      <span className="font-mono text-slate-400">
                        {bucket.count} ({bucket.percentage}%)
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                      <div
                        className={`h-full rounded-full transition-all ${
                          bucket.min_score >= 75
                            ? 'bg-rose-500'
                            : bucket.min_score >= 50
                              ? 'bg-orange-500'
                              : bucket.min_score >= 25
                                ? 'bg-amber-400'
                                : 'bg-emerald-500'
                        }`}
                        style={{ width: `${Math.max(bucket.count > 0 ? 4 : 0, bucket.percentage)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Daily & Weekly Trends */}
          <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-blue-400" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                  Scan Trends ({trendMode === 'weekly' ? 'Weekly' : 'Daily'})
                </h3>
              </div>

              <div className="inline-flex rounded-lg border border-slate-800 bg-[#090d16] p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setTrendMode('daily')}
                  className={`rounded-md px-3 py-1 font-medium transition-colors ${
                    trendMode === 'daily'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Daily
                </button>
                <button
                  type="button"
                  onClick={() => setTrendMode('weekly')}
                  className={`rounded-md px-3 py-1 font-medium transition-colors ${
                    trendMode === 'weekly'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Weekly
                </button>
              </div>
            </div>

            {trends.length === 0 ? (
              <p className="py-6 text-center text-xs text-slate-500">
                No trend buckets available for the selected filters.
              </p>
            ) : (
              <div className="mt-5 flex items-end gap-2 overflow-x-auto pb-2">
                {trends.map((point) => {
                  const totalHeight = Math.max(10, Math.round((point.total / maxTrendTotal) * 120))
                  return (
                    <div
                      key={point.period}
                      className="flex min-w-[56px] flex-1 flex-col items-center gap-1.5"
                      title={`${point.period}: ${point.total} total (${point.safe} safe, ${point.suspicious} suspicious, ${point.dangerous} dangerous)`}
                    >
                      <span className="font-mono text-[10px] text-slate-400">{point.total}</span>
                      <div
                        className="flex w-8 flex-col-reverse overflow-hidden rounded-t bg-slate-800"
                        style={{ height: `${totalHeight}px` }}
                      >
                        {point.safe > 0 && (
                          <div
                            className="w-full bg-emerald-500/80"
                            style={{ height: `${(point.safe / point.total) * 100}%` }}
                          />
                        )}
                        {point.suspicious > 0 && (
                          <div
                            className="w-full bg-amber-400/90"
                            style={{ height: `${(point.suspicious / point.total) * 100}%` }}
                          />
                        )}
                        {point.dangerous > 0 && (
                          <div
                            className="w-full bg-rose-500"
                            style={{ height: `${(point.dangerous / point.total) * 100}%` }}
                          />
                        )}
                      </div>
                      <span className="truncate font-mono text-[10px] text-slate-500">
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
            <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5 lg:col-span-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Most Frequently Detected Indicators
              </h3>
              {analytics.top_indicators.length === 0 ? (
                <p className="py-6 text-xs text-slate-500">
                  No threat indicators have been recorded in the matching scans.
                </p>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-[11px] uppercase text-slate-400">
                      <tr>
                        <th className="py-2 pr-4">Indicator</th>
                        <th className="py-2 text-right">Detections</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {analytics.top_indicators.map((item) => (
                        <tr key={item.indicator}>
                          <td className="py-2 pr-4 font-medium text-slate-200">{item.indicator}</td>
                          <td className="py-2 text-right font-mono text-blue-300">{item.count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="space-y-4">
              {/* ML Telemetry */}
              <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-4">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-200">
                  <Cpu className="h-4 w-4 text-blue-400" />
                  ML Usage Statistics
                </div>
                {analytics.ml_stats.recorded_scans === 0 ? (
                  <p className="mt-2 text-xs text-slate-500">
                    No ML telemetry recorded on stored scans yet.
                  </p>
                ) : (
                  <dl className="mt-3 space-y-1.5 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-slate-400">Recorded Scans</dt>
                      <dd className="font-mono text-slate-200">{analytics.ml_stats.recorded_scans}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-slate-400">ML Available</dt>
                      <dd className="font-mono text-emerald-300">{analytics.ml_stats.available_scans}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-slate-400">ML Flagged</dt>
                      <dd className="font-mono text-amber-300">{analytics.ml_stats.flagged_predictions}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-slate-400">Avg Confidence</dt>
                      <dd className="font-mono text-slate-200">
                        {analytics.ml_stats.average_confidence !== null
                          ? `${Math.round(analytics.ml_stats.average_confidence * 100)}%`
                          : 'Unavailable'}
                      </dd>
                    </div>
                  </dl>
                )}
              </div>

              {/* Threat Intel Telemetry */}
              <div className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-4">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-200">
                  <Globe className="h-4 w-4 text-blue-400" />
                  Threat Intel Matches
                </div>
                {analytics.threat_intel_stats.recorded_scans === 0 ? (
                  <p className="mt-2 text-xs text-slate-500">
                    No threat intelligence telemetry recorded yet.
                  </p>
                ) : (
                  <dl className="mt-3 space-y-1.5 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-slate-400">Malicious Matches</dt>
                      <dd className="font-mono text-rose-300">
                        {analytics.threat_intel_stats.malicious_matches}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-slate-400">Clean Checks</dt>
                      <dd className="font-mono text-emerald-300">
                        {analytics.threat_intel_stats.clean_checks}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-slate-400">Unavailable</dt>
                      <dd className="font-mono text-slate-400">
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
