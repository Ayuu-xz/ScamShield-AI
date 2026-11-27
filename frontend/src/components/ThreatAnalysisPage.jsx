import {
  ShieldAlert,
  Bug,
  Eye,
  ArrowRightLeft,
  Globe,
  Search,
} from 'lucide-react'
import { EmptyState, StatusBadge } from './ui/StatusPrimitives.jsx'
import TrackerFindingCard from './TrackerFindingCard.jsx'

function ThreatCategoryPanel({ title, icon: Icon, items, emptyStatus = 'Not detected' }) {
  return (
    <section className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-blue-400" />
          <h3 className="text-sm font-semibold text-white">{title}</h3>
        </div>
        {items.length === 0 && <StatusBadge label={emptyStatus} />}
      </div>

      {items.length === 0 ? (
        <p className="mt-3 text-xs text-slate-400">
          {emptyStatus === 'Check unavailable'
            ? 'External threat-intelligence lookup was unavailable or not configured.'
            : 'No indicators detected in this category for the current scan.'}
        </p>
      ) : (
        <ul className="mt-3 space-y-2.5">
          {items.map((item, idx) => (
            <li
              key={`${item.rule_id}-${idx}`}
              className="rounded-lg border border-slate-800 bg-[#090d16] p-3 text-xs"
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
                <p className="mt-1.5 break-all font-mono text-[11px] text-slate-400">
                  {item.evidence}
                </p>
              )}
              <p className="mt-1.5 text-[11px] leading-relaxed text-slate-300">
                {item.explanation}
              </p>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

/**
 * Dedicated Threat Analysis page organizing Phishing, Malware, Trackers,
 * Redirects, and Domain Intelligence from the active scan.
 */
export default function ThreatAnalysisPage({ scanResult, onNavigate }) {
  if (!scanResult) {
    return (
      <EmptyState
        icon={Search}
        title="No Active Scan Selected"
        description="Run a URL or Message scan first to inspect detailed phishing, malware, tracker, redirect, and domain intelligence findings."
        action={
          <button
            type="button"
            onClick={() => onNavigate('url-scanner')}
            className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500"
          >
            Open URL Scanner
          </button>
        }
      />
    )
  }

  const domainIntel = scanResult.domainIntelligence

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800/90 bg-[#0f1623] p-4">
        <div>
          <h2 className="text-base font-bold text-white sm:text-lg">
            Detailed Threat Analysis
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">{scanResult.inspectionNote}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge label={scanResult.inspectionStatus} />
          <StatusBadge label={scanResult.riskLevel} size="md" />
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <ThreatCategoryPanel
          title="Phishing Indicators"
          icon={ShieldAlert}
          items={scanResult.phishingIndicators}
        />

        <ThreatCategoryPanel
          title="Malware Indicators"
          icon={Bug}
          items={scanResult.malwareIndicators}
          emptyStatus="Check unavailable"
        />

        <ThreatCategoryPanel
          title="Redirect Analysis"
          icon={ArrowRightLeft}
          items={scanResult.redirectIndicators}
        />

        {/* Domain Intelligence */}
        <section className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-400" />
              <h3 className="text-sm font-semibold text-white">Domain Intelligence</h3>
            </div>
            <StatusBadge label={domainIntel?.reputation_status || 'Check unavailable'} />
          </div>

          <dl className="mt-3 space-y-2 text-xs">
            <div className="flex justify-between gap-2">
              <dt className="text-slate-400">Provider</dt>
              <dd className="font-mono text-slate-200">
                {domainIntel?.provider_name || 'unconfigured'}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-400">Reputation Status</dt>
              <dd className="text-slate-200">
                {domainIntel?.reputation_status || 'Check unavailable'}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-slate-400">Domain Age</dt>
              <dd className="text-slate-200">
                {domainIntel?.domain_age_status || 'Check unavailable'}
              </dd>
            </div>
            {domainIntel?.checked_at && (
              <div className="flex justify-between gap-2">
                <dt className="text-slate-400">Lookup Time</dt>
                <dd className="text-slate-200">
                  {new Date(domainIntel.checked_at).toLocaleString()} (
                  {domainIntel.cached ? 'Cached' : 'Fresh'})
                </dd>
              </div>
            )}
          </dl>
          {domainIntel?.provider_results?.length > 0 && (
            <ul className="mt-3 space-y-1.5 border-t border-slate-800 pt-2.5 text-[11px]">
              {domainIntel.provider_results.map((pr, idx) => (
                <li
                  key={`${pr.provider_name}-${idx}`}
                  className="flex flex-wrap items-center justify-between gap-2"
                >
                  <span className="font-medium text-slate-200">
                    {pr.provider_name} — {pr.threat_category}
                  </span>
                  <span className="text-slate-400">
                    {pr.lookup_status} ({pr.cached ? 'Cached' : 'Fresh'})
                  </span>
                </li>
              ))}
            </ul>
          )}
          {domainIntel?.note && (
            <p className="mt-3 text-[11px] text-slate-400">{domainIntel.note}</p>
          )}
        </section>
      </div>

      {/* Website Trackers */}
      <section className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Eye className="h-4 w-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-white">
              Website Trackers (Informational)
            </h3>
          </div>
          {scanResult.trackerIndicators.length === 0 && <StatusBadge label="Not detected" />}
        </div>

        {scanResult.trackerIndicators.length === 0 ? (
          <p className="mt-3 text-xs text-slate-400">
            No tracker indicators detected in the available URL or page inspection data.
          </p>
        ) : (
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            {scanResult.trackerIndicators.map((t, idx) => (
              <TrackerFindingCard key={`${t.rule_id}-${idx}`} finding={t} />
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
