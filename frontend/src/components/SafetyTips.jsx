import {
  Lightbulb,
  KeyRound,
  ClockAlert,
  GlobeLock,
  ShieldCheck,
  AlertOctagon,
} from 'lucide-react'

const COMMON_INDICATORS = [
  'Urgent account suspension or KYC expiry threats',
  'Look-alike domains, raw IP links, or URL shorteners',
  'Requests for OTPs, PINs, passwords, or registration fees',
  'Unexpected lottery prizes, cash rewards, or parcel fees',
]

const SAFETY_TIPS = [
  {
    icon: GlobeLock,
    title: 'Inspect the Real Domain',
    description:
      'Phishing links often mimic trusted brands using extra subdomains, hyphens, or look-alike characters (e.g., paypa1 vs paypal).',
  },
  {
    icon: ClockAlert,
    title: 'Watch for Artificial Urgency',
    description:
      'Scam messages frequently pressure you with "account suspended" or "act within 2 hours" to stop you from verifying calmly.',
  },
  {
    icon: KeyRound,
    title: 'Never Share OTPs or Passwords',
    description:
      'Legitimate banks and services will never ask for your one-time passcode, PIN, or full password through a link or text message.',
  },
  {
    icon: ShieldCheck,
    title: 'Verify via Official Channels',
    description:
      'Instead of clicking a link in an unexpected SMS or email, open a new tab and type the official website address yourself.',
  },
]

/**
 * Awareness & About section educating users on common phishing & scam tactics.
 */
export default function SafetyTips() {
  return (
    <section id="about" className="mx-auto mt-12 max-w-6xl px-4 sm:px-6">
      {/* Common scam indicators banner */}
      <div className="mb-8 rounded-2xl border border-slate-800 bg-slate-900/50 p-5 sm:p-6">
        <div className="flex items-start gap-3">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 text-amber-400">
            <AlertOctagon className="h-4 w-4" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">
              About ScamShield AI &amp; Common Scam Indicators
            </h2>
            <p className="mt-1 text-xs leading-relaxed text-slate-400">
              ScamShield AI inspects links and messages strictly as plain text without
              visiting URLs or executing content. Watch out for these frequent red flags:
            </p>
            <ul className="mt-3 grid gap-2 text-xs text-slate-300 sm:grid-cols-2">
              {COMMON_INDICATORS.map((item) => (
                <li key={item} className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-blue-400" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      <div id="safety-tips" className="mb-6 flex items-center gap-2.5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-500/15 text-blue-400">
          <Lightbulb className="h-4 w-4" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">Safe Online Behaviour Tips</h2>
          <p className="text-xs text-slate-400">
            Practical habits to spot phishing and social-engineering attempts
          </p>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {SAFETY_TIPS.map((tip) => {
          const Icon = tip.icon
          return (
            <article
              key={tip.title}
              className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 transition hover:border-blue-500/40"
            >
              <div className="mb-3 inline-flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600/15 text-blue-400">
                <Icon className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-semibold text-white">{tip.title}</h3>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-400">
                {tip.description}
              </p>
            </article>
          )
        })}
      </div>
    </section>
  )
}
