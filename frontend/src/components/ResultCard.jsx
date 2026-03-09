import { AlertTriangle, BadgeCheck, ShieldAlert } from 'lucide-react'

const statusMap = {
  safe: {
    label: 'Safe',
    icon: BadgeCheck,
    color: 'text-emerald-300',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
  },
  suspicious: {
    label: 'Suspicious',
    icon: AlertTriangle,
    color: 'text-amber-300',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
  },
  phishing: {
    label: 'Phishing',
    icon: ShieldAlert,
    color: 'text-red-300',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
  },
}

function ResultCard({ result, loading }) {
  if (loading) {
    return (
      <div className="rounded-2xl border border-cyan-900/40 bg-slate-950/60 p-5">
        <div className="h-5 w-48 rounded bg-slate-700/70" />
        <div className="mt-3 h-4 w-full rounded bg-slate-800/80" />
        <div className="mt-2 h-4 w-5/6 rounded bg-slate-800/80" />
      </div>
    )
  }

  if (!result) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-5 text-sm text-slate-400">
        Run a scan to view threat intelligence and model explanation.
      </div>
    )
  }

  const status = statusMap[result.prediction] || statusMap.suspicious
  const Icon = status.icon

  return (
    <div className={`rounded-2xl border ${status.border} ${status.bg} p-5`}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Icon className={`h-5 w-5 ${status.color}`} />
          <p className={`text-lg font-semibold ${status.color}`}>{status.label}</p>
        </div>
        <p className="text-sm text-slate-300">Risk: {result.risk_level}</p>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        <div className="rounded-xl border border-slate-700/70 bg-slate-900/60 p-3">
          <p className="text-xs uppercase tracking-wide text-slate-400">Confidence</p>
          <p className="mt-1 text-xl font-semibold text-cyan-200">{Math.round((result.confidence || 0) * 100)}%</p>
        </div>
        <div className="rounded-xl border border-slate-700/70 bg-slate-900/60 p-3">
          <p className="text-xs uppercase tracking-wide text-slate-400">URL</p>
          <p className="mt-1 truncate text-sm text-slate-200">{result.url}</p>
        </div>
      </div>

      <div className="mt-4 rounded-xl border border-slate-700/70 bg-slate-900/60 p-3">
        <p className="text-xs uppercase tracking-wide text-slate-400">AI Explanation</p>
        <p className="mt-2 text-sm leading-6 text-slate-200">{result.explanation}</p>
      </div>

      <div className="mt-4 rounded-xl border border-slate-700/70 bg-slate-900/60 p-3">
        <p className="text-xs uppercase tracking-wide text-slate-400">Triggered Signals</p>
        <ul className="mt-2 space-y-1 text-sm text-slate-300">
          {(result.triggered_flags || ['No critical rule-based flags triggered']).map((flag) => (
            <li key={flag}>- {flag}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}

export default ResultCard
