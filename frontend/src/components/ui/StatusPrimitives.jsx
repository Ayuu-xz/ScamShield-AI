import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  HelpCircle,
  Info,
  Lock,
  Loader2,
} from 'lucide-react'

const BADGE_STYLES = {
  Dangerous: 'border-rose-500/35 bg-rose-500/10 text-rose-300',
  Suspicious: 'border-amber-500/35 bg-amber-500/10 text-amber-300',
  'No strong indicators detected': 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300',
  Safe: 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300',
  'Not detected': 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300',
  Completed: 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300',
  Detected: 'border-rose-500/35 bg-rose-500/10 text-rose-300',
  Informational: 'border-blue-500/35 bg-blue-500/10 text-blue-300',
  'Blocked for safety': 'border-amber-500/35 bg-amber-500/10 text-amber-300',
  'Inspection unavailable': 'border-slate-600/80 bg-slate-800/80 text-slate-300',
  'Check unavailable': 'border-slate-600/80 bg-slate-800/80 text-slate-300',
  Unavailable: 'border-slate-600/80 bg-slate-800/80 text-slate-300',
}

const SCORE_COLORS = {
  Dangerous: { text: 'text-rose-400', bar: 'bg-rose-500' },
  Suspicious: { text: 'text-amber-400', bar: 'bg-amber-500' },
  'No strong indicators detected': { text: 'text-emerald-400', bar: 'bg-emerald-500' },
  Safe: { text: 'text-emerald-400', bar: 'bg-emerald-500' },
  'Inspection unavailable': { text: 'text-slate-300', bar: 'bg-slate-500' },
  Unavailable: { text: 'text-slate-400', bar: 'bg-slate-600' },
}

/**
 * Consistent restrained status badge across all pages.
 */
export function StatusBadge({ label, size = 'sm' }) {
  const style = BADGE_STYLES[label] || BADGE_STYLES['Check unavailable']
  const sizeClass =
    size === 'md' ? 'px-3 py-1 text-xs font-semibold' : 'px-2 py-0.5 text-[11px] font-medium'

  let Icon = HelpCircle
  if (label === 'Dangerous' || label === 'Detected') Icon = ShieldX
  else if (label === 'Suspicious' || label === 'Blocked for safety') Icon = ShieldAlert
  else if (
    label === 'No strong indicators detected' ||
    label === 'Safe' ||
    label === 'Not detected' ||
    label === 'Completed'
  ) {
    Icon = ShieldCheck
  } else if (label === 'Informational') {
    Icon = Info
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border ${sizeClass} ${style}`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" />
      <span>{label === 'Unavailable' ? 'No URL Detected' : label}</span>
    </span>
  )
}

/**
 * Clean 0-100 risk score display with restrained progress bar.
 */
export function RiskScoreDisplay({ score, level, label = 'Risk Score' }) {
  const hasScore = score !== null && score !== undefined
  const palette = SCORE_COLORS[level] || SCORE_COLORS['Inspection unavailable']

  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
        {label}
      </p>
      {hasScore ? (
        <>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className={`text-3xl font-bold tracking-tight ${palette.text}`}>
              {score}
            </span>
            <span className="text-xs text-slate-500">/ 100</span>
          </div>
          <div
            role="progressbar"
            aria-valuenow={score}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={label}
            className="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-800"
          >
            <div
              className={`h-full rounded-full transition-all duration-300 ${palette.bar}`}
              style={{ width: `${score}%` }}
            />
          </div>
        </>
      ) : (
        <p className="mt-1 text-sm font-semibold text-slate-300">
          Assessment Unavailable
        </p>
      )}
    </div>
  )
}

/**
 * Reusable enterprise empty state.
 */
export function EmptyState({ icon: Icon = Lock, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-slate-800/90 bg-[#0f1623] px-6 py-12 text-center">
      <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-slate-800 bg-[#131c2e] text-slate-400">
        <Icon className="h-5 w-5" />
      </div>
      <h3 className="mt-3 text-sm font-semibold text-slate-200">{title}</h3>
      {description && (
        <p className="mt-1 max-w-md text-xs leading-relaxed text-slate-400">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

/**
 * Clean loading skeleton and spinner state.
 */
export function LoadingState({ message = 'Loading...', subtext }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-6"
    >
      <div className="flex items-center gap-3">
        <Loader2 className="h-5 w-5 animate-spin text-blue-400" />
        <div>
          <p className="text-sm font-medium text-slate-200">{message}</p>
          {subtext && <p className="text-xs text-slate-400">{subtext}</p>}
        </div>
      </div>
      <div className="mt-4 space-y-2.5">
        <div className="h-3 w-3/4 animate-pulse rounded bg-slate-800" />
        <div className="h-3 w-1/2 animate-pulse rounded bg-slate-800" />
      </div>
    </div>
  )
}
