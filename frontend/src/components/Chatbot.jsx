import { useState } from 'react'
import axios from 'axios'
import { Bot, SendHorizonal } from 'lucide-react'

function Chatbot({ apiBase }) {
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)
  const [history, setHistory] = useState([
    { role: 'bot', text: 'I can analyze suspicious URLs and phishing messages in real time.' },
  ])

  const sendMessage = async (event) => {
    event.preventDefault()
    const text = message.trim()
    if (!text) return

    setHistory((prev) => [...prev, { role: 'user', text }])
    setMessage('')
    setLoading(true)

    try {
      const response = await axios.post(`${apiBase}/chatbot`, { message: text })
      setHistory((prev) => [...prev, { role: 'bot', text: response.data.reply }])
    } catch {
      setHistory((prev) => [...prev, { role: 'bot', text: 'Chatbot is temporarily unavailable.' }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="rounded-2xl border border-cyan-900/40 bg-slate-950/60 p-5 shadow-glow">
      <p className="flex items-center gap-2 text-sm font-semibold text-cyan-300">
        <Bot className="h-4 w-4" />
        AI Phishing Assistant
      </p>

      <div className="mt-4 max-h-64 space-y-3 overflow-y-auto rounded-xl border border-slate-800 bg-slate-900/60 p-3">
        {history.map((item, index) => (
          <div
            key={`${item.role}-${index}`}
            className={`max-w-[90%] rounded-lg px-3 py-2 text-sm ${
              item.role === 'user'
                ? 'ml-auto bg-cyan-500/20 text-cyan-100'
                : 'bg-slate-800 text-slate-200'
            }`}
          >
            {item.text}
          </div>
        ))}
        {loading && <p className="text-xs text-slate-400">Analyzing message...</p>}
      </div>

      <form onSubmit={sendMessage} className="mt-3 flex gap-2">
        <input
          value={message}
          onChange={(event) => setMessage(event.target.value)}
          placeholder="Ask: Is this URL safe?"
          className="w-full rounded-xl border border-slate-700 bg-slate-900/70 px-4 py-2 text-sm outline-none ring-cyan-500/30 placeholder:text-slate-500 focus:ring"
        />
        <button
          type="submit"
          disabled={loading}
          className="rounded-xl bg-cyan-500 px-3 py-2 text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-cyan-700"
        >
          <SendHorizonal className="h-4 w-4" />
        </button>
      </form>
    </section>
  )
}

export default Chatbot
