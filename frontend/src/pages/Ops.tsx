/**
 * Ops — run the CLI operations from the browser and follow their output.
 * The backend only accepts a fixed whitelist of operations and passes every
 * field as a separate argv entry, so nothing typed here becomes shell syntax.
 */
import { useCallback, useEffect, useState, type CSSProperties } from 'react'
import { fetchJob, fetchJobs, fetchTargets, launchJob, stopJob } from '../api'
import type { JobInfo, JobKind, JobRequest, TargetInfo } from '../types'
import {
  ACCENT, CARD, Empty, ErrorBox, MONO, PAGE, Pill, accentSoft, fmtDate,
} from '../ui'

type Field = 'target' | 'source_root' | 'project_name' | 'url' | 'top'

const OPS: Array<{ kind: JobKind; title: string; blurb: string; fields: Field[] }> = [
  { kind: 'onboard', title: 'Onboard', fields: ['source_root', 'project_name'],
    blurb: 'Scan an already-cloned source tree and generate its target config.' },
  { kind: 'setup', title: 'Setup', fields: ['target', 'url'],
    blurb: 'Prepare the work copy and verify the instrumented + debug builds compile.' },
  { kind: 'recon', title: 'Recon', fields: ['target'],
    blurb: 'Stage 1 only — rank candidate functions without fuzzing.' },
  { kind: 'scout', title: 'Scout', fields: ['top'],
    blurb: 'Find un-fuzzed C/C++ parser libraries worth targeting.' },
  { kind: 'verify-crashes', title: 'Verify crashes', fields: ['target'],
    blurb: 'Replay crashes against the unpatched library to drop patch artifacts.' },
]

const LABELS: Record<Field, string> = {
  target: 'Target', source_root: 'Source root', project_name: 'Project name',
  url: 'Git URL (optional)', top: 'How many',
}

const statusColor = (s: string) =>
  s === 'running' ? ACCENT : s === 'succeeded' ? ACCENT : s === 'failed' ? '#C42B2B' : '#85857D'

export function OpsPage() {
  const [targets, setTargets] = useState<TargetInfo[]>([])
  const [jobs, setJobs] = useState<JobInfo[]>([])
  const [open, setOpen] = useState<string | null>(null)
  const [detail, setDetail] = useState<JobInfo | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => { fetchTargets().then(setTargets).catch(() => {}) }, [])

  const refresh = useCallback(() => {
    fetchJobs().then(setJobs).catch(() => {})
  }, [])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 3000)
    return () => clearInterval(id)
  }, [refresh])

  // Poll the open job's output while it runs.
  useEffect(() => {
    if (!open) { setDetail(null); return }
    let alive = true
    const tick = () => fetchJob(open)
      .then((j) => { if (alive) setDetail(j) })
      .catch(() => {})
    void tick()
    const id = setInterval(tick, 2000)
    return () => { alive = false; clearInterval(id) }
  }, [open])

  const launch = async (req: JobRequest) => {
    setError(null)
    try {
      const job = await launchJob(req)
      setOpen(job.id)
      refresh()
    } catch (e) {
      setError(String(e).replace(/^Error:\s*/, ''))
    }
  }

  return (
    <main style={PAGE}>
      <h1 style={{ fontSize: 26, fontWeight: 700, letterSpacing: '-.02em', margin: '0 0 4px' }}>Operations</h1>
      <p style={{ fontSize: 14, color: '#77776F', margin: '0 0 26px' }}>
        The same commands the CLI runs, launched here and streamed back. Long operations keep
        going if you navigate away.
      </p>

      {error && <div style={{ marginBottom: 18 }}><ErrorBox>{error}</ErrorBox></div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 14, marginBottom: 30 }}>
        {OPS.map((op) => <OpCard key={op.kind} op={op} targets={targets} onLaunch={launch} />)}
      </div>

      <h2 style={{ fontSize: 13, fontWeight: 600, color: '#8A8A82', letterSpacing: '.06em', textTransform: 'uppercase', margin: '0 0 14px' }}>Recent jobs</h2>

      {jobs.length === 0 ? <Empty>Nothing has been run yet.</Empty> : (
        <div style={{ ...CARD, overflow: 'hidden' }}>
          {jobs.map((j) => (
            <div key={j.id}>
              <div className="nem-row" onClick={() => setOpen(open === j.id ? null : j.id)}
                style={{ display: 'grid', gridTemplateColumns: '1.1fr 2fr 1fr .8fr', gap: 12, alignItems: 'center', padding: '13px 20px', borderBottom: '1px solid #F4F4F0', cursor: 'pointer' }}>
                <span style={{ fontSize: 13.5, fontWeight: 600 }}>{j.kind}</span>
                <span style={{ ...MONO, fontSize: 11.5, color: '#A3A39C', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {j.argv.join(' ')}
                </span>
                <span style={{ ...MONO, fontSize: 11.5, color: '#A3A39C' }}>{fmtDate(j.started_at)}</span>
                <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 8 }}>
                  {j.status === 'running' && (
                    <button onClick={(e) => { e.stopPropagation(); void stopJob(j.id).then(refresh) }}
                      style={{ height: 26, padding: '0 10px', borderRadius: 7, border: '1px solid #F3D9D2', background: '#FFF', color: '#C42B2B', fontSize: 11.5, fontWeight: 600, cursor: 'pointer' }}>stop</button>
                  )}
                  <Pill bg={j.status === 'failed' ? '#FEECEC' : accentSoft} color={statusColor(j.status)}>
                    {j.status === 'running' && <span style={{ width: 6, height: 6, borderRadius: '50%', background: ACCENT, animation: 'nemPulse 1.6s ease-in-out infinite' }} />}
                    {j.status}
                  </Pill>
                </div>
              </div>
              {open === j.id && (
                <pre style={{ ...MONO, margin: 0, padding: '14px 20px', background: '#FBFAF7', borderBottom: '1px solid #F0F0EC', fontSize: 11.5, lineHeight: 1.6, color: '#55554E', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 380, overflowY: 'auto' }}>
                  {detail?.output?.length ? detail.output.join('\n') : 'waiting for output…'}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </main>
  )
}

function OpCard({ op, targets, onLaunch }: {
  op: (typeof OPS)[number]
  targets: TargetInfo[]
  onLaunch: (req: JobRequest) => void
}) {
  const [values, setValues] = useState<Record<string, string>>({ top: '25' })
  const set = (k: string, v: string) => setValues((s) => ({ ...s, [k]: v }))

  const missing = op.fields.some((f) =>
    f !== 'url' && f !== 'top' && !(values[f] || '').trim())

  const submit = () => {
    const req: JobRequest = { kind: op.kind }
    for (const f of op.fields) {
      const v = (values[f] || '').trim()
      if (!v) continue
      if (f === 'top') req.top = Number(v) || 25
      else if (f === 'target') req.target = v
      else if (f === 'source_root') req.source_root = v
      else if (f === 'project_name') req.project_name = v
      else if (f === 'url') req.url = v
    }
    onLaunch(req)
  }

  const input: CSSProperties = {
    ...MONO, width: '100%', height: 32, padding: '0 10px', fontSize: 12,
    color: '#1A1A18', background: '#FBFBF9', border: '1px solid #E4E4DE',
    borderRadius: 7, outline: 'none', boxSizing: 'border-box',
  }

  return (
    <div style={{ ...CARD, padding: '17px 18px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ fontSize: 14.5, fontWeight: 700 }}>{op.title}</div>
      <div style={{ fontSize: 12.5, color: '#85857D', margin: '4px 0 12px', flex: 1 }}>{op.blurb}</div>

      {op.fields.map((f) => (
        <div key={f} style={{ marginBottom: 8 }}>
          <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: '#A3A39C', textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 4 }}>{LABELS[f]}</label>
          {f === 'target' ? (
            <select value={values.target || ''} onChange={(e) => set('target', e.target.value)} style={input}>
              <option value="">select a target…</option>
              {targets.map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
            </select>
          ) : (
            <input value={values[f] || ''} onChange={(e) => set(f, e.target.value)}
              placeholder={f === 'source_root' ? '$HOME/libfoo_clean' : f === 'top' ? '25' : ''}
              style={input} />
          )}
        </div>
      ))}

      <button onClick={submit} disabled={missing}
        style={{ marginTop: 6, height: 34, borderRadius: 8, border: 'none', background: missing ? '#EDEDE8' : ACCENT, color: missing ? '#B4B4AC' : '#FFF', fontSize: 13, fontWeight: 600, cursor: missing ? 'default' : 'pointer' }}>
        Run {op.title.toLowerCase()}
      </button>
    </div>
  )
}
