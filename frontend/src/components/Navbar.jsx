import { ShieldCheck, Radar } from 'lucide-react'

function Navbar() {
  return (
    <header className="border-b border-cyan-900/30 bg-slate-950/70 backdrop-blur">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 lg:px-8">
        <div className="flex items-center gap-3">
          <div className="rounded-lg border border-cyan-400/30 bg-cyan-500/10 p-2">
            <ShieldCheck className="h-5 w-5 text-cyan-300" />
          </div>
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-cyan-300">Phishing AI Platform</p>
            <p className="text-xs text-slate-400">Threat Intelligence Dashboard</p>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-full border border-cyan-900/30 bg-slate-900/70 px-3 py-1 text-xs text-slate-300">
          <Radar className="h-4 w-4 text-cyan-400" />
          Live Monitoring
        </div>
      </div>
    </header>
  )
}

export default Navbar
