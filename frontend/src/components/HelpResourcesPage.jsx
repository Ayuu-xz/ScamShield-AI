import { useState } from 'react'
import {
  ShieldAlert,
  Eye,
  Bug,
  ShieldCheck,
  Gauge,
  HelpCircle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import {
  BEFORE_YOU_CLICK_TIPS,
  SCAM_IDENTIFICATION_CHECKLIST,
} from '../data/awarenessContent.js'

const FAQS = [
  {
    q: 'Does ScamShield AI open or visit the links I submit?',
    a: 'No. Submitted URLs are analyzed strictly as text by default. Even if you enable Isolated Read-Only Website Inspection, private/local/metadata IPs are blocked and page JavaScript is never executed.',
  },
  {
    q: 'Why does a normal message with a suspicious link still get flagged?',
    a: 'Message Scanner uses URL-first analysis: it extracts links from the message and scores them with the exact same URL engine as the URL Scanner. Ordinary conversational text never inflates URL scores.',
  },
  {
    q: 'What does "Inspection unavailable" mean?',
    a: 'It means only URL text was checked or an external check could not run. ScamShield AI never marks an unverified target as Safe.',
  },
  {
    q: 'How are my passwords or tokens protected in Scan History?',
    a: 'Sensitive query parameters (such as token, password, session, cookie, or otp) and inline credentials are automatically redacted before saving to SQLite or exporting reports.',
  },
]

/**
 * Refined dark-mode Help & Awareness page separated from the primary scanner workspace.
 */
export default function HelpResourcesPage() {
  const [openFaq, setOpenFaq] = useState(0)

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-[#F1F5F9] sm:text-xl">Help &amp; Resources</h2>
        <p className="mt-0.5 text-xs text-[#94A3B8]">
          Classification definitions, frequently asked questions, and safe browsing guidance
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#F1F5F9]">
            <Gauge className="h-4 w-4 text-[#3B82F6]" />
            Understanding Risk Classifications
          </div>
          <ul className="mt-3 space-y-2 text-xs text-[#94A3B8]">
            <li>
              <strong className="text-[#86EFAC]">0–24 (No strong indicators detected):</strong>{' '}
              Available checks found no strong evidence, but safety is never guaranteed.
            </li>
            <li>
              <strong className="text-[#FCD34D]">25–49 (Suspicious):</strong> Meaningful
              suspicious signals detected; verify independently before proceeding.
            </li>
            <li>
              <strong className="text-[#FCA5A5]">50–100 (Dangerous):</strong> Strong phishing,
              credential-harvesting, or reputation evidence detected.
            </li>
            <li>
              <strong className="text-[#F1F5F9]">Inspection unavailable:</strong> Shown when only
              URL text was analyzed or external inspection could not complete safely.
            </li>
          </ul>
        </section>

        <section className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#F1F5F9]">
            <ShieldAlert className="h-4 w-4 text-[#3B82F6]" />
            Identifying Phishing Attempts
          </div>
          <ul className="mt-3 list-disc space-y-1.5 pl-4 text-xs text-[#94A3B8]">
            {SCAM_IDENTIFICATION_CHECKLIST.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        <section className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#F1F5F9]">
            <Eye className="h-4 w-4 text-[#3B82F6]" />
            Website Trackers vs. Threats
          </div>
          <p className="mt-2.5 text-xs leading-relaxed text-[#94A3B8]">
            Analytics and advertising trackers (such as Google Analytics or Meta Pixel) are
            used by many legitimate websites. Tracker findings are{' '}
            <strong className="text-[#93C5FD]">Informational</strong> and never add malicious
            phishing risk points on their own.
          </p>
        </section>

        <section className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#F1F5F9]">
            <Bug className="h-4 w-4 text-[#3B82F6]" />
            Malware &amp; File Indicators
          </div>
          <p className="mt-2.5 text-xs leading-relaxed text-[#94A3B8]">
            ScamShield AI never downloads or executes files. Executable extensions in URLs (such
            as <code className="text-[#F1F5F9]">.exe</code> or{' '}
            <code className="text-[#F1F5F9]">.apk</code>) are flagged as risk signals. Confirmed
            malware status requires an active threat-intelligence match.
          </p>
        </section>
      </div>

      {/* Frequently Asked Questions */}
      <section className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
        <div className="flex items-center gap-2 text-sm font-semibold text-[#F1F5F9]">
          <HelpCircle className="h-4 w-4 text-[#3B82F6]" />
          Frequently Asked Questions
        </div>
        <div className="mt-3 divide-y divide-[#263449]/70">
          {FAQS.map((faq, idx) => {
            const isOpen = openFaq === idx
            return (
              <div key={faq.q} className="py-2.5">
                <button
                  type="button"
                  onClick={() => setOpenFaq(isOpen ? -1 : idx)}
                  aria-expanded={isOpen}
                  className="flex w-full items-center justify-between gap-2 text-left text-xs font-semibold text-[#F1F5F9] transition-colors duration-150 hover:text-[#3B82F6]"
                >
                  <span>{faq.q}</span>
                  {isOpen ? (
                    <ChevronUp className="h-4 w-4 shrink-0 text-[#94A3B8]" />
                  ) : (
                    <ChevronDown className="h-4 w-4 shrink-0 text-[#94A3B8]" />
                  )}
                </button>
                {isOpen && (
                  <p className="mt-1.5 text-xs leading-relaxed text-[#94A3B8]">{faq.a}</p>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* Safe Browsing Practices */}
      <section className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
        <div className="flex items-center gap-2 text-sm font-semibold text-[#F1F5F9]">
          <ShieldCheck className="h-4 w-4 text-[#22C55E]" />
          Safe Browsing Practices
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {BEFORE_YOU_CLICK_TIPS.map((tip) => (
            <div
              key={tip.title}
              className="rounded-lg border border-[#263449] bg-[#0B1120] p-3.5 text-xs"
            >
              <p className="font-semibold text-[#F1F5F9]">{tip.title}</p>
              <p className="mt-1 text-[11px] leading-relaxed text-[#94A3B8]">{tip.detail}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
