import {
  LayoutDashboard,
  Link2,
  MessageSquareWarning,
  History,
  BarChart3,
  FileText,
  Settings,
  HelpCircle,
  ShieldCheck,
  X,
} from 'lucide-react'

export const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'url-scanner', label: 'URL Scanner', icon: Link2 },
  { id: 'message-scanner', label: 'Message Scanner', icon: MessageSquareWarning },
  { id: 'history', label: 'Scan History', icon: History },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'help', label: 'Help', icon: HelpCircle },
]

/**
 * Compact dark-mode (#0F172A) SaaS sidebar with responsive mobile drawer.
 */
export default function Sidebar({
  activePage,
  onNavigate,
  onGoHome,
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
            className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-xs font-medium transition-colors duration-150 ${
              isActive
                ? 'bg-[#3B82F6]/15 text-[#F1F5F9] ring-1 ring-[#3B82F6]/40'
                : 'text-[#94A3B8] hover:bg-[#172338] hover:text-[#F1F5F9]'
            }`}
          >
            <Icon className={`h-4 w-4 shrink-0 ${isActive ? 'text-[#3B82F6]' : ''}`} />
            <span>{item.label}</span>
          </button>
        )
      })}
    </nav>
  )

  return (
    <>
      {/* Desktop sidebar */}
      <aside className="hidden w-60 shrink-0 flex-col border-r border-[#263449] bg-[#0F172A] lg:flex">
        <button
          type="button"
          onClick={onGoHome}
          className="flex h-14 w-full items-center gap-2.5 border-b border-[#263449] px-4 text-left transition-colors duration-150 hover:bg-[#172338]/70"
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#3B82F6]/30 bg-[#3B82F6]/15">
            <ShieldCheck className="h-4 w-4 text-[#3B82F6]" />
          </div>
          <div>
            <span className="text-sm font-bold tracking-tight text-[#F1F5F9]">
              ScamShield <span className="text-[#3B82F6]">AI</span>
            </span>
            <p className="text-[10px] text-[#94A3B8]">Security Console</p>
          </div>
        </button>

        <div className="flex-1 overflow-y-auto">{renderLinks()}</div>

        <div className="border-t border-[#263449] p-4 text-[11px] text-[#94A3B8]">
          <p className="font-medium text-[#F1F5F9]">Defensive Read-Only Engine</p>
          <p className="mt-0.5 leading-relaxed">
            URLs are analyzed safely without executing or opening links.
          </p>
        </div>
      </aside>

      {/* Mobile slide-over drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            className="fixed inset-0 bg-[#0B1120]/80 backdrop-blur-xs"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <aside className="relative z-10 flex w-64 flex-col border-r border-[#263449] bg-[#0F172A] shadow-xl">
            <div className="flex h-14 items-center justify-between border-b border-[#263449] px-4">
              <button
                type="button"
                onClick={() => {
                  onGoHome()
                  onCloseMobile?.()
                }}
                className="flex items-center gap-2"
              >
                <ShieldCheck className="h-4 w-4 text-[#3B82F6]" />
                <span className="text-sm font-bold text-[#F1F5F9]">ScamShield AI</span>
              </button>
              <button
                type="button"
                onClick={onCloseMobile}
                aria-label="Close navigation menu"
                className="rounded-lg p-1 text-[#94A3B8] transition-colors duration-150 hover:bg-[#172338] hover:text-[#F1F5F9]"
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
