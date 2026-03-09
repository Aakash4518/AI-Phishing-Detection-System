import { MailWarning, Shield, AlertCircle, ExternalLink } from 'lucide-react'

function ScamAdvisory() {
  return (
    <aside className="rounded-2xl border border-cyan-900/40 bg-slate-950/60 p-5 shadow-glow">
      <p className="text-sm font-semibold text-cyan-300">Scam Advisory Panel</p>

      <section className="mt-4 space-y-3 text-sm text-slate-300">
        <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-3">
          <p className="flex items-center gap-2 font-medium text-slate-100"><AlertCircle className="h-4 w-4 text-amber-300" /> Common phishing signs</p>
          <p className="mt-1 text-xs">Urgent language, payment demands, fake login pages, and domain misspellings.</p>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-3">
          <p className="flex items-center gap-2 font-medium text-slate-100"><MailWarning className="h-4 w-4 text-red-300" /> Email scam warning tips</p>
          <p className="mt-1 text-xs">Verify sender domain, hover links, and avoid sharing credentials or OTP codes.</p>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-3">
          <p className="flex items-center gap-2 font-medium text-slate-100"><Shield className="h-4 w-4 text-emerald-300" /> Safe browsing checklist</p>
          <p className="mt-1 text-xs">Check HTTPS, confirm domain age/reputation, keep browser security updates enabled.</p>
        </div>
      </section>

      <a
        href="https://safebrowsing.google.com/safebrowsing/report_phish/"
        target="_blank"
        rel="noreferrer"
        className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-xl border border-red-500/40 bg-red-500/15 px-3 py-2 text-sm font-medium text-red-200 transition hover:bg-red-500/25"
      >
        Report phishing link
        <ExternalLink className="h-4 w-4" />
      </a>
    </aside>
  )
}

export default ScamAdvisory
