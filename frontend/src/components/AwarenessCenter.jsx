import {
  FileWarning,
  Gift,
  Briefcase,
  PackageX,
  KeyRound,
  Link2,
  ShieldAlert,
  CheckSquare,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import {
  BEFORE_YOU_CLICK_TIPS,
  SCAM_CATEGORIES,
  SCAM_IDENTIFICATION_CHECKLIST,
  getRelevantAwarenessCards,
} from '../data/awarenessContent.js'

const ICON_MAP = {
  FileWarning,
  Gift,
  Briefcase,
  PackageX,
  KeyRound,
  Link2,
}

/**
 * Reusable educational card for a single scam category.
 */
function AwarenessCard({ category, isHighlighted }) {
  const Icon = ICON_MAP[category.iconName] || ShieldAlert

  return (
    <article
      className={`flex flex-col rounded-2xl border p-5 transition ${
        isHighlighted
          ? 'border-blue-500/60 bg-blue-950/30 shadow-lg shadow-blue-950/30'
          : 'border-slate-800 bg-slate-900/60 hover:border-blue-500/40'
      }`}
    >
      <div className="mb-3 flex items-start justify-between gap-2">
        <div className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-blue-600/15 text-blue-400">
          <Icon className="h-5 w-5" />
        </div>

        {isHighlighted && (
          <span className="inline-flex items-center gap-1 rounded-full border border-blue-400/40 bg-blue-500/15 px-2.5 py-0.5 text-[11px] font-medium text-blue-300">
            <Sparkles className="h-3 w-3" />
            Relevant to Scan
          </span>
        )}
      </div>

      <h3 className="text-base font-bold text-white">{category.title}</h3>
      <p className="mt-1.5 text-xs leading-relaxed text-slate-300">
        {category.explanation}
      </p>

      <div className="mt-4 space-y-3 border-t border-slate-800/80 pt-3 text-xs">
        <div>
          <p className="font-semibold text-amber-300">Common Warning Signs</p>
          <ul className="mt-1.5 list-disc space-y-1 pl-4 text-slate-400">
            {category.warningSigns.map((sign) => (
              <li key={sign}>{sign}</li>
            ))}
          </ul>
        </div>

        <div>
          <p className="font-semibold text-emerald-300">How to Stay Safe</p>
          <ul className="mt-1.5 list-disc space-y-1 pl-4 text-slate-300">
            {category.preventionTips.map((tip) => (
              <li key={tip}>{tip}</li>
            ))}
          </ul>
        </div>
      </div>
    </article>
  )
}

/**
 * Safety Tips & Scam Awareness Center connected to live scan results.
 */
export default function AwarenessCenter({ scanResult }) {
  const relevantCards = getRelevantAwarenessCards(scanResult)
  const relevantIds = new Set(relevantCards.map((c) => c.id))

  return (
    <section id="about" className="mx-auto mt-14 max-w-6xl space-y-12 px-4 sm:px-6">
      {/* 1. Stay Alert. Stay Safe. */}
      <div>
        <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-blue-400">
              Scam Awareness Center
            </p>
            <h2 className="mt-1 text-2xl font-extrabold tracking-tight text-white sm:text-3xl">
              Stay Alert. Stay Safe.
            </h2>
            <p className="mt-1.5 max-w-2xl text-xs leading-relaxed text-slate-400 sm:text-sm">
              Educational guidance on common phishing and scam patterns. A single
              warning sign does not prove fraud, but recognizing these tactics helps
              you pause and verify safely.
            </p>
          </div>
        </div>

        {/* Result-integrated guidance banner when indicators were detected */}
        {relevantCards.length > 0 && (
          <div
            aria-live="polite"
            className="mb-6 rounded-2xl border border-blue-500/40 bg-blue-500/10 p-4 sm:p-5"
          >
            <div className="flex items-start gap-3">
              <Sparkles className="mt-0.5 h-5 w-5 shrink-0 text-blue-400" />
              <div>
                <h3 className="text-sm font-semibold text-blue-200">
                  Guidance Related to Your Latest Scan
                </h3>
                <p className="mt-1 text-xs leading-relaxed text-slate-300">
                  Based on the indicators detected in your scan, review the highlighted{' '}
                  {relevantCards.map((c) => c.title).join(', ')} guide
                  {relevantCards.length > 1 ? 's' : ''} below.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* 6 Scam Category Cards */}
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {SCAM_CATEGORIES.map((category) => (
            <AwarenessCard
              key={category.id}
              category={category}
              isHighlighted={relevantIds.has(category.id)}
            />
          ))}
        </div>
      </div>

      {/* 2. How to Identify a Scam Checklist */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 sm:p-7">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-amber-500/15 text-amber-400">
            <CheckSquare className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">How to Identify a Scam</h2>
            <p className="text-xs text-slate-400">
              Quick checklist of common warning signs to watch for
            </p>
          </div>
        </div>

        <ul className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {SCAM_IDENTIFICATION_CHECKLIST.map((item) => (
            <li
              key={item}
              className="flex items-start gap-2.5 rounded-xl border border-slate-800/80 bg-slate-950/70 p-3.5 text-xs text-slate-200"
            >
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* 3. Before You Click, Think Twice. */}
      <div id="safety-tips" className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 sm:p-7">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-400">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">
              Before You Click, Think Twice.
            </h2>
            <p className="text-xs text-slate-400">
              Practical habits to protect your accounts, money, and personal data
            </p>
          </div>
        </div>

        <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {BEFORE_YOU_CLICK_TIPS.map((tip) => (
            <div
              key={tip.title}
              className="rounded-xl border border-slate-800/80 bg-slate-950/70 p-4 transition hover:border-blue-500/40"
            >
              <h3 className="text-sm font-semibold text-white">{tip.title}</h3>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-400">
                {tip.detail}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
