import { Settings, Cpu, Globe, ShieldCheck, RotateCcw } from 'lucide-react'

/**
 * Refined dark-mode Settings page for language, scan preferences, and configuration status.
 */
export default function SettingsPage({
  preferences,
  onUpdatePreferences,
  onResetPreferences,
  healthState,
  apiBaseUrl,
}) {
  const isConnected = healthState?.status === 'connected'

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-[#F1F5F9] sm:text-xl">Settings</h2>
          <p className="mt-0.5 text-xs text-[#94A3B8]">
            Configure explanation language, scanner defaults, and inspect system status
          </p>
        </div>

        <button
          type="button"
          onClick={onResetPreferences}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[#263449] bg-[#111C30] px-3 py-1.5 text-xs font-medium text-[#F1F5F9] transition-colors duration-150 hover:border-[#3B82F6]/50"
        >
          <RotateCcw className="h-3.5 w-3.5" />
          Reset Defaults
        </button>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <section className="space-y-5 rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
          <div className="flex items-center gap-2 border-b border-[#263449] pb-3 text-sm font-semibold text-[#F1F5F9]">
            <Settings className="h-4 w-4 text-[#3B82F6]" />
            Application Preferences
          </div>

          <div>
            <label
              htmlFor="default-language-select"
              className="block text-xs font-semibold text-[#F1F5F9]"
            >
              Default Explanation Language
            </label>
            <p className="mt-0.5 text-[11px] text-[#94A3B8]">
              Used automatically on new scan results (you can still switch per result).
            </p>
            <select
              id="default-language-select"
              value={preferences.defaultLanguage}
              onChange={(e) =>
                onUpdatePreferences({ defaultLanguage: e.target.value })
              }
              className="mt-2 w-full rounded-lg border border-[#263449] bg-[#0B1120] px-3 py-2 text-xs text-[#F1F5F9] focus:border-[#3B82F6] focus:outline-none"
            >
              <option value="en">English</option>
              <option value="hi">हिंदी (Hindi)</option>
              <option value="hinglish">Hinglish</option>
            </select>
          </div>

          <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-[#263449] bg-[#0B1120] p-3.5 text-xs">
            <input
              type="checkbox"
              checked={preferences.defaultInspectWebsite}
              onChange={(e) =>
                onUpdatePreferences({ defaultInspectWebsite: e.target.checked })
              }
              className="mt-0.5 h-4 w-4 rounded border-[#263449] bg-[#172338] text-[#3B82F6] focus:ring-[#3B82F6]"
            />
            <span>
              <span className="block font-semibold text-[#F1F5F9]">
                Enable Isolated Website Inspection by Default
              </span>
              <span className="mt-0.5 block text-[11px] text-[#94A3B8]">
                Uses SSRF-guarded read-only inspection for HTML scripts and forms.
              </span>
            </span>
          </label>

          <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-[#263449] bg-[#0B1120] p-3.5 text-xs">
            <input
              type="checkbox"
              checked={preferences.defaultExpandTechnical}
              onChange={(e) =>
                onUpdatePreferences({ defaultExpandTechnical: e.target.checked })
              }
              className="mt-0.5 h-4 w-4 rounded border-[#263449] bg-[#172338] text-[#3B82F6] focus:ring-[#3B82F6]"
            />
            <span>
              <span className="block font-semibold text-[#F1F5F9]">
                Expand Technical Details Automatically
              </span>
              <span className="mt-0.5 block text-[11px] text-[#94A3B8]">
                Show Rule, ML, and Threat Intelligence breakdowns expanded by default.
              </span>
            </span>
          </label>
        </section>

        <section className="space-y-4 rounded-[10px] border border-[#263449] bg-[#111C30] p-5">
          <div className="flex items-center gap-2 border-b border-[#263449] pb-3 text-sm font-semibold text-[#F1F5F9]">
            <ShieldCheck className="h-4 w-4 text-[#3B82F6]" />
            Configuration &amp; Workspace Status
          </div>

          <dl className="divide-y divide-[#263449]/70 text-xs">
            <div className="flex items-center justify-between py-2.5">
              <dt className="text-[#94A3B8]">Backend API Endpoint</dt>
              <dd className="font-mono text-[#F1F5F9]">{apiBaseUrl}</dd>
            </div>
            <div className="flex items-center justify-between py-2.5">
              <dt className="text-[#94A3B8]">Connection Status</dt>
              <dd
                className={`font-semibold ${
                  isConnected ? 'text-[#22C55E]' : 'text-[#EF4444]'
                }`}
              >
                {isConnected ? 'Connected' : 'Offline / Checking'}
              </dd>
            </div>
            <div className="flex items-center justify-between py-2.5">
              <dt className="text-[#94A3B8]">Service Version</dt>
              <dd className="font-mono text-[#F1F5F9]">
                {healthState?.data?.version || 'Unavailable'}
              </dd>
            </div>
            <div className="flex items-center justify-between py-2.5">
              <dt className="inline-flex items-center gap-1.5 text-[#94A3B8]">
                <Cpu className="h-3.5 w-3.5 text-[#3B82F6]" />
                ML &amp; OCR Engines
              </dt>
              <dd className="text-[#F1F5F9]">Server-managed (scikit-learn + RapidOCR)</dd>
            </div>
            <div className="flex items-center justify-between py-2.5">
              <dt className="inline-flex items-center gap-1.5 text-[#94A3B8]">
                <Globe className="h-3.5 w-3.5 text-[#3B82F6]" />
                Threat Intelligence Keys
              </dt>
              <dd className="text-[#94A3B8]">Configured via backend .env</dd>
            </div>
          </dl>

          <p className="rounded-lg border border-[#263449] bg-[#0B1120] p-3 text-[11px] leading-relaxed text-[#94A3B8]">
            Account authentication is not enabled in this local single-workspace console. All
            scan history and reports are stored locally in SQLite with sensitive tokens redacted.
          </p>
        </section>
      </div>
    </div>
  )
}
