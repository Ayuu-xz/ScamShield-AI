import { Menu, RefreshCw, Wifi, WifiOff, Loader2 } from 'lucide-react'
import { NAV_ITEMS } from './Sidebar.jsx'

/**
 * Compact SaaS top bar with mobile menu trigger, active page title, and live API health status.
 */
export default function TopHeader({
  activePage,
  healthState,
  onRefreshHealth,
  onOpenMobileMenu,
}) {
  const currentItem = NAV_ITEMS.find((item) => item.id === activePage) || NAV_ITEMS[0]
  const { status, data, error } = healthState

  const renderApiStatus = () => {
    if (status === 'loading') {
      return (
        <span className="inline-flex items-center gap-1.5 rounded-md border border-blue-500/30 bg-blue-500/10 px-2.5 py-1 text-[11px] font-medium text-blue-300">
          <Loader2 className="h-3 w-3 animate-spin" />
          <span className="hidden sm:inline">Checking API...</span>
        </span>
      )
    }

    if (status === 'connected') {
      return (
        <span
          title={`Service: ${data?.service || 'API'} v${data?.version || ''}`}
          className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-[11px] font-medium text-emerald-300"
        >
          <Wifi className="h-3 w-3" />
          <span className="hidden sm:inline">API Connected</span>
        </span>
      )
    }

    return (
      <span
        title={error || 'Backend unreachable'}
        className="inline-flex items-center gap-1.5 rounded-md border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-[11px] font-medium text-rose-300"
      >
        <WifiOff className="h-3 w-3" />
        <span className="hidden sm:inline">API Offline</span>
      </span>
    )
  }

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-slate-800/90 bg-[#090d16]/95 px-4 backdrop-blur-sm sm:px-6">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation menu"
          className="rounded-lg border border-slate-800 bg-[#0f1623] p-1.5 text-slate-300 hover:border-blue-500/40 hover:text-white lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </button>
        <div>
          <h1 className="text-sm font-semibold text-white sm:text-base">
            {currentItem.label}
          </h1>
        </div>
      </div>

      <div className="flex items-center gap-2">
        {renderApiStatus()}
        <button
          type="button"
          onClick={onRefreshHealth}
          aria-label="Refresh backend health status"
          title="Re-check backend connection"
          className="rounded-lg border border-slate-800 bg-[#0f1623] p-1.5 text-slate-400 transition-colors hover:border-blue-500/40 hover:text-blue-300"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${status === 'loading' ? 'animate-spin' : ''}`} />
        </button>
      </div>
    </header>
  )
}
