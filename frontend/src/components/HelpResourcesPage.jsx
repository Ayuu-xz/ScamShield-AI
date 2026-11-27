import {
  BookOpen,
  ShieldAlert,
  Eye,
  Bug,
  ShieldCheck,
  Gauge,
} from 'lucide-react'
import {
  BEFORE_YOU_CLICK_TIPS,
  SCAM_CATEGORIES,
  SCAM_IDENTIFICATION_CHECKLIST,
} from '../data/awarenessContent.js'

/**
 * Help & Resources page housing detailed scoring explanations and safety guidance
 * relocated off the main scanner-first dashboard.
 */
export default function HelpResourcesPage() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white sm:text-xl">Help &amp; Resources</h2>
        <p className="mt-0.5 text-xs text-slate-400">
          Documentation on risk scoring, phishing indicators, website trackers, malware checks, and safe browsing.
        </p>
      </div>

      {/* 5 Core Educational Sections */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Gauge className="h-4 w-4 text-blue-400" />
            Understanding Risk Scores
          </div>
          <ul className="mt-3 space-y-2 text-xs text-slate-300">
            <li>
              <strong className="text-emerald-300">0–24 (No strong indicators detected):</strong>{' '}
              Available checks found no strong evidence, but safety is never guaranteed.
            </li>
            <li>
              <strong className="text-amber-300">25–49 (Suspicious):</strong> Meaningful
              suspicious signals detected; verify independently before proceeding.
            </li>
            <li>
              <strong className="text-rose-300">50–100 (Dangerous):</strong> Strong phishing,
              credential-harvesting, or reputation evidence detected.
            </li>
            <li className="text-slate-400">
              <strong>Inspection unavailable:</strong> Shown when only URL text was analyzed or
              active inspection could not be completed safely.
            </li>
          </ul>
        </section>

        <section className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <ShieldAlert className="h-4 w-4 text-blue-400" />
            Identifying Phishing
          </div>
          <ul className="mt-3 list-disc space-y-1.5 pl-4 text-xs text-slate-300">
            {SCAM_IDENTIFICATION_CHECKLIST.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        <section className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Eye className="h-4 w-4 text-blue-400" />
            Understanding Website Trackers
          </div>
          <p className="mt-2.5 text-xs leading-relaxed text-slate-300">
            Analytics and advertising trackers (such as Google Analytics, Google Tag Manager,
            and Meta Pixel) are used by many legitimate websites to measure traffic. Tracker
            findings are strictly <strong className="text-blue-300">Informational</strong> and
            never add malicious phishing risk points on their own.
          </p>
        </section>

        <section className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Bug className="h-4 w-4 text-blue-400" />
            Understanding Malware Indicators
          </div>
          <p className="mt-2.5 text-xs leading-relaxed text-slate-300">
            ScamShield AI never downloads or executes files. Executable extensions in URLs
            (such as <code className="text-slate-200">.exe</code> or{' '}
            <code className="text-slate-200">.apk</code>) are flagged as risk signals, not
            confirmed malware. Confirmed malware status requires a configured external
            threat-intelligence provider; otherwise, the check reports{' '}
            <strong className="text-slate-200">Check unavailable</strong>.
          </p>
        </section>
      </div>

      {/* Safe Browsing Practices */}
      <section className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
        <div className="flex items-center gap-2 text-sm font-semibold text-white">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          Safe Browsing Practices
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {BEFORE_YOU_CLICK_TIPS.map((tip) => (
            <div
              key={tip.title}
              className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5 text-xs"
            >
              <p className="font-semibold text-slate-100">{tip.title}</p>
              <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
                {tip.detail}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Common Scam Categories Reference */}
      <section className="rounded-xl border border-slate-800/90 bg-[#0f1623] p-5">
        <div className="flex items-center gap-2 text-sm font-semibold text-white">
          <BookOpen className="h-4 w-4 text-blue-400" />
          Common Scam Categories Reference
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {SCAM_CATEGORIES.map((cat) => (
            <article
              key={cat.id}
              className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5 text-xs"
            >
              <h3 className="font-semibold text-slate-100">{cat.title}</h3>
              <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
                {cat.explanation}
              </p>
              <p className="mt-2 text-[11px] font-medium text-emerald-300">
                Tip: {cat.preventionTips[0]}
              </p>
            </article>
          ))}
        </div>
      </section>
    </div>
  )
}
