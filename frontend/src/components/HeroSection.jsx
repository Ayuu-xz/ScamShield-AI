import { Lock, ShieldAlert, EyeOff } from 'lucide-react'

/**
 * Hero section introducing ScamShield AI and its text-only inspection approach.
 */
export default function HeroSection() {
  return (
    <section id="top" className="relative overflow-hidden pt-10 pb-8 sm:pt-14 sm:pb-10">
      {/* Subtle radial glow */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-24 left-1/2 h-72 w-[42rem] -translate-x-1/2 rounded-full bg-blue-600/15 blur-3xl"
      />

      <div className="relative mx-auto max-w-4xl px-4 text-center sm:px-6">
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-blue-500/30 bg-blue-500/10 px-3.5 py-1 text-xs font-medium text-blue-300">
          <ShieldAlert className="h-3.5 w-3.5" />
          Cybersecurity Hackathon Prototype
        </div>

        <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-5xl">
          Detect Phishing Links &amp;{' '}
          <span className="bg-gradient-to-r from-blue-400 to-cyan-300 bg-clip-text text-transparent">
            Scam Messages
          </span>{' '}
          Before You Click
        </h1>

        <p className="mx-auto mt-4 max-w-2xl text-sm leading-relaxed text-slate-300 sm:text-base">
          Paste any suspicious URL, SMS, or email message below to get a 0–100 risk score,
          clear classification (<span className="text-emerald-400 font-medium">Safe</span>,{' '}
          <span className="text-amber-400 font-medium">Suspicious</span>, or{' '}
          <span className="text-rose-400 font-medium">Dangerous</span>), plain-English
          explanations, and practical safety advice.
        </p>

        {/* Key safety guarantees */}
        <div className="mt-6 flex flex-wrap items-center justify-center gap-3 text-xs text-slate-400">
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-1.5">
            <EyeOff className="h-3.5 w-3.5 text-blue-400" />
            URLs are analyzed strictly as text (never visited)
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-1.5">
            <Lock className="h-3.5 w-3.5 text-blue-400" />
            Privacy-first local inspection
          </span>
        </div>
      </div>
    </section>
  )
}
