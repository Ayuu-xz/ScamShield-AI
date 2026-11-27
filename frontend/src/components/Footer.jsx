import { ShieldCheck } from 'lucide-react'

/**
 * Application footer with project information and security disclaimer.
 */
export default function Footer({ apiBaseUrl }) {
  return (
    <footer className="mt-16 border-t border-slate-800/80 bg-slate-950/80 py-8">
      <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-4 px-4 text-xs text-slate-400 sm:flex-row sm:items-center sm:px-6">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-blue-400" />
          <span>
            <strong className="text-slate-200">ScamShield AI</strong> — Phishing Link &amp;
            Scam Message Checker
          </span>
        </div>

        <div className="flex flex-col gap-1 sm:text-right">
          <p>
            URLs are analyzed strictly as text and are never visited, crawled, or executed.
          </p>
          <p className="text-slate-500">
            Backend endpoint: <code className="text-slate-400">{apiBaseUrl}</code>
          </p>
        </div>
      </div>
    </footer>
  )
}
