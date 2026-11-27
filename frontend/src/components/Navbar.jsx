import { ShieldCheck, RefreshCw, Wifi, WifiOff, Loader2, History } from 'lucide-react'

/**
 * Top navigation bar with ScamShield AI branding, navigation links
 * (Home, Scan History, About), and live backend health status.
 */
export default function Navbar({
  healthState,
  onRefreshHealth,
  activePage = 'home',
  onNavigate,
}) {
  const { status, data, error } = healthState

  const renderStatusBadge = () => {
    if (status === 'loading') {
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-xs font-medium text-blue-300">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          <span className="hidden sm:inline">Checking API...</span>
        </span>
      )
    }

    if (status === 'connected') {
      return (
        <span
          title={`Service: ${data?.service || 'API'} v${data?.version || ''}`}
          className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300"
        >
          <Wifi className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">API Connected</span>
        </span>
      )
    }

    return (
      <span
        title={error || 'Backend unreachable'}
        className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/30 bg-rose-500/10 px-3 py-1 text-xs font-medium text-rose-300"
      >
        <WifiOff className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">API Offline</span>
      </span>
    )
  }

  return (
    <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#060d1f]/90 backdrop-blur-md">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-3 px-4 py-3.5 sm:px-6">
        {/* Brand logo */}
        <button
          type="button"
          onClick={() => onNavigate?.('home', '#top')}
          className="flex items-center gap-2.5 text-left"
        >
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600/20 ring-1 ring-blue-500/40">
            <ShieldCheck className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <span className="text-lg font-bold tracking-tight text-white">
              ScamShield <span className="text-blue-400">AI</span>
            </span>
            <p className="hidden text-[11px] text-slate-400 sm:block">
              Phishing Link &amp; Scam Message Checker
            </p>
          </div>
        </button>

        {/* Navigation links + Backend health indicator */}
        <div className="flex items-center gap-3 sm:gap-5">
          <nav
            aria-label="Primary navigation"
            className="flex items-center gap-3 text-xs sm:gap-5 sm:text-sm"
          >
            <button
              type="button"
              onClick={() => onNavigate?.('home', '#top')}
              className={`font-medium transition hover:text-blue-400 ${
                activePage === 'home' ? 'text-blue-400' : 'text-slate-300'
              }`}
            >
              Home
            </button>
            <button
              type="button"
              onClick={() => onNavigate?.('history')}
              className={`inline-flex items-center gap-1.5 font-medium transition hover:text-blue-400 ${
                activePage === 'history' ? 'text-blue-400' : 'text-slate-300'
              }`}
            >
              <History className="h-3.5 w-3.5" />
              Scan History
            </button>
            <button
              type="button"
              onClick={() => onNavigate?.('home', '#about')}
              className="font-medium text-slate-300 transition hover:text-blue-400"
            >
              About
            </button>
          </nav>

          <div className="flex items-center gap-2">
            {renderStatusBadge()}
            <button
              type="button"
              onClick={onRefreshHealth}
              aria-label="Refresh backend health status"
              title="Re-check backend connection"
              className="rounded-lg border border-slate-800 bg-slate-900/80 p-1.5 text-slate-400 transition hover:border-blue-500/40 hover:text-blue-300"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${status === 'loading' ? 'animate-spin' : ''}`}
              />
            </button>
          </div>
        </div>
      </div>
    </header>
  )
}
