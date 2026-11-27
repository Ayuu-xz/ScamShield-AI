import { Menu, RefreshCw, Wifi, WifiOff, Loader2, Home } from 'lucide-react'
import { NAV_ITEMS } from './Sidebar.jsx'

/**
 * Clean dark-mode top header with breadcrumb, product home link, and live API status.
 */
export default function TopHeader({
  activePage,
  healthState,
  onRefreshHealth,
  onOpenMobileMenu,
  onGoHome,
}) {
  const currentItem = NAV_ITEMS.find((item) => item.id === activePage) || NAV_ITEMS[0]
  const { status, data, error } = healthState

  const renderApiStatus = () => {
    if (status === 'loading') {
      return (
        <span className="inline-flex items-center gap-1.5 rounded-md border border-[#3B82F6]/35 bg-[#3B82F6]/12 px-2.5 py-1 text-[11px] font-medium text-[#93C5FD]">
          <Loader2 className="h-3 w-3 animate-spin" />
          <span className="hidden sm:inline">Checking API...</span>
        </span>
      )
    }

    if (status === 'connected') {
      return (
        <span
          title={`Service: ${data?.service || 'API'} v${data?.version || ''}`}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#22C55E]/35 bg-[#22C55E]/12 px-2.5 py-1 text-[11px] font-medium text-[#86EFAC]"
        >
          <Wifi className="h-3 w-3" />
          <span className="hidden sm:inline">API Connected</span>
        </span>
      )
    }

    return (
      <span
        title={error || 'Backend unreachable'}
        className="inline-flex items-center gap-1.5 rounded-md border border-[#EF4444]/35 bg-[#EF4444]/12 px-2.5 py-1 text-[11px] font-medium text-[#FCA5A5]"
      >
        <WifiOff className="h-3 w-3" />
        <span className="hidden sm:inline">API Offline</span>
      </span>
    )
  }

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-[#263449] bg-[#0B1120]/95 px-4 backdrop-blur-xs sm:px-6">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation menu"
          className="rounded-lg border border-[#263449] bg-[#111C30] p-1.5 text-[#94A3B8] transition-colors duration-150 hover:border-[#3B82F6]/50 hover:text-[#F1F5F9] lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </button>

        <div className="flex items-center gap-2 text-sm">
          <button
            type="button"
            onClick={onGoHome}
            className="hidden items-center gap-1 text-xs font-medium text-[#94A3B8] transition-colors duration-150 hover:text-[#F1F5F9] sm:inline-flex"
          >
            <Home className="h-3.5 w-3.5" />
            Home
          </button>
          <span className="hidden text-[#263449] sm:inline">/</span>
          <h1 className="font-semibold text-[#F1F5F9]">{currentItem.label}</h1>
        </div>
      </div>

      <div className="flex items-center gap-2">
        {renderApiStatus()}
        <button
          type="button"
          onClick={onRefreshHealth}
          aria-label="Refresh backend health status"
          title="Re-check backend connection"
          className="rounded-lg border border-[#263449] bg-[#111C30] p-1.5 text-[#94A3B8] transition-colors duration-150 hover:border-[#3B82F6]/50 hover:text-[#F1F5F9]"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${status === 'loading' ? 'animate-spin' : ''}`} />
        </button>
      </div>
    </header>
  )
}
