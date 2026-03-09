import { useMemo, useState } from 'react'
import axios from 'axios'
import Navbar from './components/Navbar'
import URLScanner from './components/URLScanner'
import ResultCard from './components/ResultCard'
import ScamAdvisory from './components/ScamAdvisory'
import Chatbot from './components/Chatbot'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:5000'

function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const metrics = useMemo(() => {
    if (!result) return null
    return {
      risk: result.risk_level,
      confidence: Math.round((result.confidence || 0) * 100),
      status: result.prediction,
    }
  }, [result])

  const handleScan = async (url) => {
    setLoading(true)
    setError('')
    try {
      const response = await axios.post(`${API_BASE}/scan-url`, { url })
      setResult(response.data)
    } catch (scanError) {
      setError(scanError.response?.data?.error || 'Scan failed. Please retry.')
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen grid-bg">
      <Navbar />
      <main className="mx-auto max-w-7xl px-4 py-6 lg:px-8">
        <div className="mb-6 grid gap-4 lg:grid-cols-3">
          <div className="rounded-2xl border border-cyan-900/40 bg-slate-950/60 p-4 shadow-glow">
            <p className="text-xs uppercase tracking-wide text-cyan-400">Detection Engine</p>
            <p className="mt-2 text-sm text-slate-300">ML + Explainable AI + Domain Intelligence</p>
          </div>
          <div className="rounded-2xl border border-cyan-900/40 bg-slate-950/60 p-4 shadow-glow">
            <p className="text-xs uppercase tracking-wide text-cyan-400">Current Risk</p>
            <p className="mt-2 text-2xl font-semibold">{metrics ? metrics.risk : 'Not Scanned'}</p>
          </div>
          <div className="rounded-2xl border border-cyan-900/40 bg-slate-950/60 p-4 shadow-glow">
            <p className="text-xs uppercase tracking-wide text-cyan-400">Confidence</p>
            <p className="mt-2 text-2xl font-semibold">{metrics ? `${metrics.confidence}%` : '--'}</p>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          <div className="space-y-6 lg:col-span-2">
            <URLScanner onScan={handleScan} loading={loading} />
            {error && (
              <div className="rounded-xl border border-red-500/40 bg-red-950/40 p-3 text-sm text-red-300">{error}</div>
            )}
            <ResultCard result={result} loading={loading} />
            <Chatbot apiBase={API_BASE} />
          </div>

          <div>
            <ScamAdvisory />
          </div>
        </div>
      </main>
    </div>
  )
}

export default App
