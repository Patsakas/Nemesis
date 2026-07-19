/** Reports — the coordinated-disclosure Markdown documents the engine writes. */
import { useEffect, useState } from 'react'
import { fetchReportMarkdown, fetchReports } from '../api'
import type { ReportMeta } from '../types'
import { ACCENT, CARD, Empty, ErrorBox, Loading, MONO, PAGE, accentSoft } from '../ui'

export function ReportsPage() {
  const [reports, setReports] = useState<ReportMeta[]>([])
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [openId, setOpenId] = useState<string | null>(null)
  const [body, setBody] = useState<string>('')
  const [bodyState, setBodyState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle')
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    fetchReports()
      .then((r) => { setReports(r); setState('ready') })
      .catch(() => setState('error'))
  }, [])

  const open = (id: string) => {
    setOpenId(id); setBodyState('loading'); setCopied(false)
    fetchReportMarkdown(id)
      .then((t) => { setBody(t); setBodyState('ready') })
      .catch(() => setBodyState('error'))
  }

  const copy = () => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(body).then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      }).catch(() => {})
    }
  }

  if (openId) {
    return (
      <main style={PAGE}>
        <button onClick={() => setOpenId(null)} style={{ ...MONO, border: 'none', background: 'none', padding: 0, marginBottom: 18, fontSize: 12.5, color: '#9A9A92', cursor: 'pointer' }}>← all reports</button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 18, flexWrap: 'wrap' }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-.02em', margin: 0, ...MONO }}>{openId}</h1>
          <span style={{ flex: 1 }} />
          <button onClick={copy} disabled={bodyState !== 'ready'}
            style={{ height: 34, padding: '0 15px', borderRadius: 8, border: 'none', background: bodyState === 'ready' ? ACCENT : '#EDEDE8', color: bodyState === 'ready' ? '#FFF' : '#B4B4AC', fontSize: 12.5, fontWeight: 600, cursor: bodyState === 'ready' ? 'pointer' : 'default' }}>
            {copied ? 'copied ✓' : 'copy markdown'}
          </button>
        </div>

        {bodyState === 'loading' && <Loading what="report" />}
        {bodyState === 'error' && <ErrorBox>Could not load this report.</ErrorBox>}
        {bodyState === 'ready' && (
          <pre style={{
            ...MONO, ...CARD, margin: 0, padding: '20px 22px', fontSize: 12.5, lineHeight: 1.7,
            color: '#33332E', whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowX: 'auto',
          }}>{body}</pre>
        )}
      </main>
    )
  }

  return (
    <main style={PAGE}>
      <h1 style={{ fontSize: 26, fontWeight: 700, letterSpacing: '-.02em', margin: '0 0 4px' }}>Reports</h1>
      <p style={{ fontSize: 14, color: '#77776F', margin: '0 0 26px' }}>
        Disclosure drafts generated for triaged findings. Review before sending anything upstream.
      </p>

      {state === 'loading' && <Loading what="reports" />}
      {state === 'error' && <ErrorBox>Could not load reports.</ErrorBox>}
      {state === 'ready' && reports.length === 0 && (
        <Empty>No reports yet — they are written when a finding is triaged into a disclosure draft.</Empty>
      )}

      {state === 'ready' && reports.length > 0 && (
        <div style={{ ...CARD, overflow: 'hidden' }}>
          {reports.map((r) => (
            <div key={r.id} className="nem-row" onClick={() => open(r.id)}
              style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 20px', borderBottom: '1px solid #F4F4F0', cursor: 'pointer' }}>
              <div style={{ ...MONO, width: 30, height: 30, borderRadius: 8, background: accentSoft, display: 'flex', alignItems: 'center', justifyContent: 'center', color: ACCENT, fontSize: 13, flexShrink: 0 }}>⚑</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ ...MONO, fontSize: 13.5, color: '#33332E' }}>{r.finding_id}</div>
                <div style={{ fontSize: 11.5, color: '#A3A39C' }}>{r.filename} · {(r.size_bytes / 1024).toFixed(1)} kB</div>
              </div>
              <span style={{ ...MONO, fontSize: 12.5, color: '#A3A39C' }}>open →</span>
            </div>
          ))}
        </div>
      )}
    </main>
  )
}
