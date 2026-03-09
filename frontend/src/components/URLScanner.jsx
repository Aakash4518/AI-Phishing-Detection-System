import { useState } from 'react'
import { Search, LoaderCircle } from 'lucide-react'

function URLScanner({ onScan, loading }) {
  const [url, setUrl] = useState('')

  const submit = (event) => {
    event.preventDefault()
    if (!url.trim()) return
    onScan(url.trim())
  }

  return (
    <form onSubmit={submit} className="rounded-2xl border border-cyan-900/40 bg-slate-950/60 p-5 shadow-glow">
      <p className="text-sm font-semibold text-cyan-300">URL Threat Scanner</p>
      <p className="mt-1 text-xs text-slate-400">Paste suspicious links for AI-powered phishing analysis.</p>
      <div className="mt-4 flex flex-col gap-3 sm:flex-row">
        <input
          type="text"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          placeholder="https://example.com"
          className="w-full rounded-xl border border-slate-700 bg-slate-900/70 px-4 py-3 text-sm outline-none ring-cyan-500/30 placeholder:text-slate-500 focus:ring"
        />
        <button
          type="submit"
          disabled={loading}
          className="flex items-center justify-center gap-2 rounded-xl bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-cyan-700"
        >
          {loading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
          {loading ? 'Scanning...' : 'Scan URL'}
        </button>
      </div>
    </form>
  )
}

export default URLScanner
