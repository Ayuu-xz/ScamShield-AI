import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  HelpCircle,
  Info,
  Lock,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  X,
} from 'lucide-react'

const BADGE_STYLES = {
  Dangerous: 'border-[#EF4444]/35 bg-[#EF4444]/12 text-[#FCA5A5]',
  Suspicious: 'border-[#F59E0B]/35 bg-[#F59E0B]/12 text-[#FCD34D]',
  'No strong indicators detected': 'border-[#22C55E]/35 bg-[#22C55E]/12 text-[#86EFAC]',
  Safe: 'border-[#22C55E]/35 bg-[#22C55E]/12 text-[#86EFAC]',
  'Not detected': 'border-[#22C55E]/35 bg-[#22C55E]/12 text-[#86EFAC]',
  Completed: 'border-[#22C55E]/35 bg-[#22C55E]/12 text-[#86EFAC]',
  Detected: 'border-[#EF4444]/35 bg-[#EF4444]/12 text-[#FCA5A5]',
  Informational: 'border-[#3B82F6]/35 bg-[#3B82F6]/12 text-[#93C5FD]',
  'Blocked for safety': 'border-[#F59E0B]/35 bg-[#F59E0B]/12 text-[#FCD34D]',
  'Inspection unavailable': 'border-[#263449] bg-[#172338] text-[#94A3B8]',
  'Check unavailable': 'border-[#263449] bg-[#172338] text-[#94A3B8]',
  Unavailable: 'border-[#263449] bg-[#172338] text-[#94A3B8]',
}

const SCORE_COLORS = {
  Dangerous: { text: 'text-[#EF4444]', bar: 'bg-[#EF4444]' },
  Suspicious: { text: 'text-[#F59E0B]', bar: 'bg-[#F59E0B]' },
  'No strong indicators detected': { text: 'text-[#22C55E]', bar: 'bg-[#22C55E]' },
  Safe: { text: 'text-[#22C55E]', bar: 'bg-[#22C55E]' },
  'Inspection unavailable': { text: 'text-[#94A3B8]', bar: 'bg-[#64748B]' },
  Unavailable: { text: 'text-[#94A3B8]', bar: 'bg-[#64748B]' },
}

/**
 * Consistent dark-mode status badge with icon and text label.
 */
export function StatusBadge({ label, size = 'sm' }) {
  const style = BADGE_STYLES[label] || BADGE_STYLES['Check unavailable']
  const sizeClass =
    size === 'md'
      ? 'px-3 py-1 text-xs font-semibold'
      : 'px-2.5 py-0.5 text-[11px] font-medium'

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
      <p className="text-[11px] font-semibold uppercase tracking-wider text-[#94A3B8]">
        {label}
      </p>
      {hasScore ? (
        <>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className={`text-3xl font-bold tracking-tight ${palette.text}`}>
              {score}
            </span>
            <span className="text-xs font-medium text-[#94A3B8]">/ 100</span>
          </div>
          <div
            role="progressbar"
            aria-valuenow={score}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={label}
            className="mt-2.5 h-2 w-full overflow-hidden rounded-full bg-[#172338]"
          >
            <div
              className={`h-full rounded-full transition-all duration-200 ${palette.bar}`}
              style={{ width: `${score}%` }}
            />
          </div>
        </>
      ) : (
        <p className="mt-1 text-sm font-semibold text-[#F1F5F9]">
          Assessment Unavailable
        </p>
      )}
    </div>
  )
}

/**
 * Reusable dark-mode empty state.
 */
export function EmptyState({ icon: Icon = Lock, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-[10px] border border-[#263449] bg-[#111C30] px-6 py-10 text-center">
      <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#263449] bg-[#172338] text-[#94A3B8]">
        <Icon className="h-5 w-5" />
      </div>
      <h3 className="mt-3 text-sm font-semibold text-[#F1F5F9]">{title}</h3>
      {description && (
        <p className="mt-1 max-w-md text-xs leading-relaxed text-[#94A3B8]">
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
      className="rounded-[10px] border border-[#263449] bg-[#111C30] p-6"
    >
      <div className="flex items-center gap-3">
        <Loader2 className="h-5 w-5 animate-spin text-[#3B82F6]" />
        <div>
          <p className="text-sm font-medium text-[#F1F5F9]">{message}</p>
          {subtext && <p className="text-xs text-[#94A3B8]">{subtext}</p>}
        </div>
      </div>
      <div className="mt-4 space-y-2.5">
        <div className="h-3 w-3/4 animate-pulse rounded bg-[#172338]" />
        <div className="h-3 w-1/2 animate-pulse rounded bg-[#172338]" />
      </div>
    </div>
  )
}

/**
 * Accessible dark-mode toast notification banner.
 */
export function ToastBanner({ toast, onDismiss }) {
  if (!toast) return null
  const isError = toast.type === 'error'
  return (
    <div
      role="status"
      aria-live="polite"
      className={`fixed right-4 bottom-4 z-50 flex max-w-sm items-center gap-2.5 rounded-lg border px-4 py-3 text-xs font-medium shadow-lg ${
        isError
          ? 'border-[#EF4444]/40 bg-[#1F1218] text-[#FCA5A5]'
          : 'border-[#263449] bg-[#172338] text-[#F1F5F9]'
      }`}
    >
      {isError ? (
        <AlertTriangle className="h-4 w-4 shrink-0 text-[#EF4444]" />
      ) : (
        <CheckCircle2 className="h-4 w-4 shrink-0 text-[#22C55E]" />
      )}
      <span className="flex-1">{toast.message}</span>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss notification"
        className="rounded p-0.5 text-[#94A3B8] transition-colors duration-150 hover:text-[#F1F5F9]"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}
