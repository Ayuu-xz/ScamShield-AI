import { Eye } from 'lucide-react'
import { StatusBadge } from './ui/StatusPrimitives.jsx'

/**
 * Reusable card for displaying a single website/URL tracker finding.
 */
export default function TrackerFindingCard({ finding }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="inline-flex items-center gap-1.5 font-semibold text-slate-100">
          <Eye className="h-3.5 w-3.5 text-blue-400" />
          {finding.rule_name}
        </span>
        <StatusBadge label={finding.detection_status || 'Informational'} />
      </div>

      {finding.evidence && (
        <p className="mt-1.5 break-all font-mono text-[11px] text-slate-400">
          {finding.evidence}
        </p>
      )}

      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-slate-500">
        <span>Source: {finding.detection_source || 'url'}</span>
        {finding.tracker_domain && <span>Domain: {finding.tracker_domain}</span>}
        {finding.confidence && <span>Confidence: {finding.confidence}</span>}
      </div>

      <p className="mt-1.5 text-[11px] leading-relaxed text-slate-300">
        {finding.explanation}
      </p>
    </div>
  )
}
