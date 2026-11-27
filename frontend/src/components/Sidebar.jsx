import {
  LayoutDashboard,
  Link2,
  MessageSquareWarning,
  History,
  BarChart3,
  ShieldAlert,
  BookOpen,
  ShieldCheck,
  X,
} from 'lucide-react'

export const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'url-scanner', label: 'URL Scanner', icon: Link2 },
  { id: 'message-scanner', label: 'Message Scanner', icon: MessageSquareWarning },
  { id: 'history', label: 'Scan History', icon: History },
  { id: 'analytics', label: 'Analytics & Reports', icon: BarChart3 },
  { id: 'threat-analysis', label: 'Threat Analysis', icon: ShieldAlert },
  { id: 'help', label: 'Help & Resources', icon: BookOpen },
]

/**
 * Compact enterprise left sidebar (desktop static, mobile slide-over drawer).
 */
export default function Sidebar({
  activePage,
  onNavigate,
  mobileOpen,
  onCloseMobile,
}) {
  const renderLinks = () => (
    <nav aria-label="Primary navigation" className="space-y-1 px-3 py-4">
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon
        const isActive = activePage === item.id
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => {
              onNavigate(item.id)
              onCloseMobile?.()
            }}
            className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-xs font-medium transition-colors duration-150 ${
              isActive
                ? 'bg-blue-600/15 text-blue-400 ring-1 ring-blue-500/30'
                : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
            }`}
          >
            <Icon className="h-4 w-4 shrink-0" />
            <span>{item.label}</span>
          </button>
        )
      })}
    </nav>
  )

  return (
    <>
      {/* Desktop sidebar */}
      <aside className="hidden w-60 shrink-0 flex-col border-r border-slate-800/90 bg-[#0c121e] lg:flex">
        <div className="flex h-14 items-center gap-2.5 border-b border-slate-800/90 px-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600/20 ring-1 ring-blue-500/40">
            <ShieldCheck className="h-4 w-4 text-blue-400" />
          </div>
          <div>
            <span className="text-sm font-bold tracking-tight text-white">
              ScamShield <span className="text-blue-400">AI</span>
            </span>
            <p className="text-[10px] text-slate-400">Security Inspection Console</p>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">{renderLinks()}</div>

        <div className="border-t border-slate-800/90 p-4 text-[11px] text-slate-500">
          <p className="font-medium text-slate-400">Defensive Read-Only Engine</p>
          <p className="mt-0.5">URLs are never executed or clicked as a user.</p>
        </div>
      </aside>

      {/* Mobile slide-over drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-xs"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <aside className="relative z-10 flex w-64 flex-col border-r border-slate-800 bg-[#0c121e]">
            <div className="flex h-14 items-center justify-between border-b border-slate-800 px-4">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-blue-400" />
                <span className="text-sm font-bold text-white">ScamShield AI</span>
              </div>
              <button
                type="button"
                onClick={onCloseMobile}
                aria-label="Close navigation menu"
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto">{renderLinks()}</div>
          </aside>
        </div>
      )}
    </>
  )
}
