import {
  ShieldCheck,
  Link2,
  MessageSquareWarning,
  Cpu,
  FileText,
  Lock,
  ArrowRight,
  CheckCircle2,
  Image as ImageIcon,
  Chrome,
} from 'lucide-react'

/**
 * Refined dark-mode SaaS Landing Page for ScamShield AI.
 */
export default function LandingPage({ onStartScanning, onNavigateConsole }) {
  return (
    <div className="min-h-screen bg-[#0B1120] text-[#F1F5F9]">
      {/* Top Navigation */}
      <header className="sticky top-0 z-30 border-b border-[#263449] bg-[#0B1120]/95 backdrop-blur-xs">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#3B82F6]/30 bg-[#3B82F6]/15">
              <ShieldCheck className="h-4 w-4 text-[#3B82F6]" />
            </div>
            <span className="text-base font-bold tracking-tight text-[#F1F5F9]">
              ScamShield <span className="text-[#3B82F6]">AI</span>
            </span>
          </div>

          <nav
            aria-label="Landing navigation"
            className="hidden items-center gap-6 text-sm font-medium text-[#94A3B8] md:flex"
          >
            <a
              href="#features"
              className="transition-colors duration-150 hover:text-[#F1F5F9]"
            >
              Features
            </a>
            <a
              href="#how-it-works"
              className="transition-colors duration-150 hover:text-[#F1F5F9]"
            >
              How It Works
            </a>
            <a
              href="#security"
              className="transition-colors duration-150 hover:text-[#F1F5F9]"
            >
              Privacy &amp; Security
            </a>
          </nav>

          <button
            type="button"
            onClick={onStartScanning}
            className="inline-flex items-center gap-1.5 rounded-lg bg-[#3B82F6] px-4 py-2 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#2563EB]"
          >
            Start Scanning
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <section className="border-b border-[#263449] bg-[#0F172A]">
        <div className="mx-auto max-w-6xl px-4 py-14 sm:px-6 lg:py-20">
          <div className="max-w-3xl">
            <p className="inline-flex items-center gap-2 rounded-md border border-[#3B82F6]/30 bg-[#3B82F6]/12 px-3 py-1 text-xs font-semibold text-[#93C5FD]">
              <Lock className="h-3.5 w-3.5" />
              Defensive Read-Only Threat Inspection
            </p>
            <h1 className="mt-5 text-3xl font-bold tracking-tight text-[#F1F5F9] sm:text-4xl lg:text-[42px] lg:leading-[1.15]">
              Detect Online Scams Before They Reach You.
            </h1>
            <p className="mt-4 max-w-2xl text-sm leading-relaxed text-[#94A3B8] sm:text-base">
              ScamShield AI inspects suspicious links, SMS and chat messages, and uploaded
              screenshots using deterministic security rules, machine learning, and optional
              threat intelligence—without ever opening or executing dangerous URLs.
            </p>

            <div className="mt-7 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={onStartScanning}
                className="inline-flex items-center gap-2 rounded-lg bg-[#3B82F6] px-5 py-2.5 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#2563EB]"
              >
                Start Scanning
                <ArrowRight className="h-4 w-4" />
              </button>
              <a
                href="#how-it-works"
                className="inline-flex items-center gap-2 rounded-lg border border-[#263449] bg-[#111C30] px-5 py-2.5 text-sm font-semibold text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50 hover:bg-[#172338]"
              >
                Learn More
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Overview */}
      <section id="features" className="mx-auto max-w-6xl px-4 py-12 sm:px-6">
        <div className="max-w-2xl">
          <h2 className="text-xl font-bold tracking-tight text-[#F1F5F9] sm:text-2xl">
            Built for Fast, Transparent Threat Verification
          </h2>
          <p className="mt-1.5 text-xs text-[#94A3B8] sm:text-sm">
            Every scan produces an explainable 0–100 risk score, clear evidence, and actionable next steps.
          </p>
        </div>

        <div className="mt-7 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            {
              icon: Link2,
              title: 'URL Risk Analysis',
              desc: 'Detects look-alike domains, IP hosts, URL shorteners, suspicious redirects, and credential patterns.',
            },
            {
              icon: MessageSquareWarning,
              title: 'URL-First Message & OCR',
              desc: 'Extracts links from pasted messages or screenshots without inflating scores on ordinary text.',
            },
            {
              icon: Cpu,
              title: 'ML & Threat Intel',
              desc: 'Combines calibrated scikit-learn classifiers with optional Google Safe Browsing and URLhaus lookups.',
            },
            {
              icon: FileText,
              title: 'Reports & Analytics',
              desc: 'Exports validated PDF and JSON reports and tracks real scan trends in your local database.',
            },
          ].map((item) => {
            const Icon = item.icon
            return (
              <div
                key={item.title}
                className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5 transition-colors duration-150 hover:border-[#3B82F6]/40"
              >
                <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#263449] bg-[#172338] text-[#3B82F6]">
                  <Icon className="h-4 w-4" />
                </div>
                <h3 className="mt-4 text-sm font-semibold text-[#F1F5F9]">{item.title}</h3>
                <p className="mt-1.5 text-xs leading-relaxed text-[#94A3B8]">{item.desc}</p>
              </div>
            )
          })}
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="border-y border-[#263449] bg-[#0F172A]">
        <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6">
          <h2 className="text-xl font-bold tracking-tight text-[#F1F5F9] sm:text-2xl">
            How It Works
          </h2>
          <div className="mt-7 grid gap-5 md:grid-cols-3">
            {[
              {
                step: '01',
                title: 'Submit a Link, Message, or Image',
                desc: 'Paste a URL, forward a suspicious SMS/email, or upload a screenshot directly in the console or Chrome extension.',
              },
              {
                step: '02',
                title: 'Multi-Layer Defensive Inspection',
                desc: 'Our engine evaluates structural URL rules, ML phishing classifiers, and optional threat-intelligence feeds safely.',
              },
              {
                step: '03',
                title: 'Review Explanations & Export Reports',
                desc: 'Get plain-language guidance in English, Hindi, or Hinglish, and download PDF or JSON audit reports.',
              },
            ].map((item) => (
              <div
                key={item.step}
                className="rounded-[10px] border border-[#263449] bg-[#111C30] p-5"
              >
                <span className="font-mono text-xs font-bold text-[#3B82F6]">
                  STEP {item.step}
                </span>
                <h3 className="mt-2 text-sm font-semibold text-[#F1F5F9]">{item.title}</h3>
                <p className="mt-1.5 text-xs leading-relaxed text-[#94A3B8]">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Capabilities & Privacy */}
      <section id="security" className="mx-auto max-w-6xl px-4 py-12 sm:px-6">
        <div className="grid gap-5 lg:grid-cols-2">
          <div className="rounded-[10px] border border-[#263449] bg-[#111C30] p-6">
            <h3 className="text-sm font-bold text-[#F1F5F9]">
              Supported Scanning Capabilities
            </h3>
            <ul className="mt-4 space-y-3 text-xs text-[#94A3B8]">
              <li className="flex items-start gap-2.5">
                <Link2 className="mt-0.5 h-4 w-4 shrink-0 text-[#3B82F6]" />
                <span>
                  <strong className="text-[#F1F5F9]">Direct URLs:</strong> HTTP/HTTPS links analyzed as text with optional SSRF-guarded inspection.
                </span>
              </li>
              <li className="flex items-start gap-2.5">
                <MessageSquareWarning className="mt-0.5 h-4 w-4 shrink-0 text-[#3B82F6]" />
                <span>
                  <strong className="text-[#F1F5F9]">Text Messages:</strong> SMS, WhatsApp, and email snippets with automatic URL extraction.
                </span>
              </li>
              <li className="flex items-start gap-2.5">
                <ImageIcon className="mt-0.5 h-4 w-4 shrink-0 text-[#3B82F6]" />
                <span>
                  <strong className="text-[#F1F5F9]">Screenshots (OCR):</strong> Local RapidOCR extraction for PNG, JPG, and WEBP uploads.
                </span>
              </li>
              <li className="flex items-start gap-2.5">
                <Chrome className="mt-0.5 h-4 w-4 shrink-0 text-[#3B82F6]" />
                <span>
                  <strong className="text-[#F1F5F9]">Browser Extension:</strong> On-demand active-tab URL scanning via Chrome Manifest V3.
                </span>
              </li>
            </ul>
          </div>

          <div className="rounded-[10px] border border-[#263449] bg-[#172338] p-6">
            <div className="flex items-center gap-2 text-sm font-bold text-[#F1F5F9]">
              <Lock className="h-4 w-4 text-[#3B82F6]" />
              Privacy &amp; Security Guarantees
            </div>
            <ul className="mt-4 space-y-2.5 text-xs text-[#94A3B8]">
              <li className="flex items-start gap-2">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#22C55E]" />
                <span>Submitted URLs are never visited, clicked, or executed as a user session.</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#22C55E]" />
                <span>Passwords, auth tokens, cookies, and sensitive parameters are redacted before storage.</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#22C55E]" />
                <span>Unavailable checks are explicitly labeled—never falsely marked as Safe.</span>
              </li>
            </ul>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#263449] bg-[#0F172A]">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-6 text-xs text-[#94A3B8] sm:px-6">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-[#3B82F6]" />
            <span className="font-semibold text-[#F1F5F9]">ScamShield AI</span>
            <span>— Defensive Phishing &amp; Scam Protection</span>
          </div>

          <div className="flex flex-wrap items-center gap-5">
            <button
              type="button"
              onClick={() => onNavigateConsole('url-scanner')}
              className="transition-colors duration-150 hover:text-[#F1F5F9]"
            >
              URL Scanner
            </button>
            <button
              type="button"
              onClick={() => onNavigateConsole('message-scanner')}
              className="transition-colors duration-150 hover:text-[#F1F5F9]"
            >
              Message Scanner
            </button>
            <button
              type="button"
              onClick={() => onNavigateConsole('analytics')}
              className="transition-colors duration-150 hover:text-[#F1F5F9]"
            >
              Analytics
            </button>
            <button
              type="button"
              onClick={() => onNavigateConsole('reports')}
              className="transition-colors duration-150 hover:text-[#F1F5F9]"
            >
              Reports
            </button>
            <button
              type="button"
              onClick={() => onNavigateConsole('help')}
              className="transition-colors duration-150 hover:text-[#F1F5F9]"
            >
              Help
            </button>
          </div>
        </div>
      </footer>
    </div>
  )
}
