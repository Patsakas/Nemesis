/** Runs — pipeline run history, with per-target drill-down. */
import { useEffect, useState } from 'react'
import { fetchRun, fetchRuns } from '../api'
import type { RunDetail, RunSummary } from '../types'
import {
  ACCENT, CARD, Empty, ErrorBox, Loading, MONO, PAGE, Pill,
  accentSoft, fmtDate, fmtDuration,
} from '../ui'

export function RunsPage() {
  const [runs, setRuns] = useState<RunSummary[]>([])
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [openId, setOpenId] = useState<string | null>(null)

  useEffect(() => {
    fetchRuns()
      .then((r) => { setRuns(r); setState('ready') })
      .catch(() => setState('error'))
  }, [])

  if (openId) return <RunDetailView runId={openId} onBack={() => setOpenId(null)} />

  const head: React.CSSProperties = {
    display: 'grid', gridTemplateColumns: '1.3fr 1.6fr .8fr .8fr .8fr .9fr', gap: 12,
    padding: '12px 20px', fontSize: 11, fontWeight: 600, color: '#A3A39C',
    letterSpacing: '.05em', textTransform: 'uppercase',
  }

  return (
    <main style={PAGE}>
      <h1 style={{ fontSize: 26, fontWeight: 700, letterSpacing: '-.02em', margin: '0 0 4px' }}>Runs</h1>
      <p style={{ fontSize: 14, color: '#77776F', margin: '0 0 26px' }}>Every pipeline execution recorded in the workspace.</p>

      {state === 'loading' && <Loading what="runs" />}
      {state === 'error' && <ErrorBox>Could not load run history.</ErrorBox>}
      {state === 'ready' && runs.length === 0 && <Empty>No runs yet. Start one from a target page.</Empty>}

      {state === 'ready' && runs.length > 0 && (
        <div style={{ ...CARD, overflow: 'hidden' }}>
          <div style={{ ...head, borderBottom: '1px solid #F0F0EC' }}>
            <span>Run</span><span>Started</span><span>Targets</span><span>Crashes</span><span>CVEs</span><span style={{ textAlign: 'right' }}>LLM cost</span>
          </div>
          {runs.map((r) => (
            <div key={r.run_id} className="nem-row" onClick={() => setOpenId(r.run_id)}
              style={{ ...head, textTransform: 'none', letterSpacing: 0, fontSize: 13, fontWeight: 400, color: '#33332E', padding: '14px 20px', borderBottom: '1px solid #F4F4F0', cursor: 'pointer', alignItems: 'center' }}>
              <span style={{ ...MONO, fontSize: 12.5 }}>{r.run_id.slice(0, 12)}</span>
              <span style={{ color: '#66665F' }}>{fmtDate(r.started_at)}</span>
              <span style={{ ...MONO }}>{r.targets_successful}/{r.targets_processed}</span>
              <span style={{ ...MONO, color: r.total_crashes ? '#C42B2B' : '#66665F', fontWeight: r.total_crashes ? 600 : 400 }}>{r.total_crashes}</span>
              <span style={{ ...MONO, color: r.total_cves ? '#C42B2B' : '#66665F' }}>{r.total_cves}</span>
              <span style={{ ...MONO, textAlign: 'right', color: '#66665F' }}>
                {r.total_llm_cost_usd ? `$${r.total_llm_cost_usd.toFixed(2)}` : '—'}
              </span>
            </div>
          ))}
        </div>
      )}
    </main>
  )
}

function RunDetailView({ runId, onBack }: { runId: string; onBack: () => void }) {
  const [run, setRun] = useState<RunDetail | null>(null)
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')

  useEffect(() => {
    fetchRun(runId)
      .then((r) => { setRun(r); setState('ready') })
      .catch(() => setState('error'))
  }, [runId])

  const statusColor = (s: string) =>
    s === 'success' || s === 'completed' ? ACCENT : s === 'failed' ? '#C42B2B' : '#85857D'

  return (
    <main style={PAGE}>
      <button onClick={onBack} style={{ ...MONO, border: 'none', background: 'none', padding: 0, marginBottom: 18, fontSize: 12.5, color: '#9A9A92', cursor: 'pointer' }}>← all runs</button>
      <h1 style={{ fontSize: 24, fontWeight: 700, letterSpacing: '-.02em', margin: '0 0 4px' }}>
        Run <span style={MONO}>{runId.slice(0, 12)}</span>
      </h1>

      {state === 'loading' && <Loading what="run" />}
      {state === 'error' && <ErrorBox>Could not load this run.</ErrorBox>}

      {run && (
        <>
          <p style={{ fontSize: 13.5, color: '#77776F', margin: '0 0 22px' }}>
            {fmtDate(run.started_at)}{run.finished_at ? ` → ${fmtDate(run.finished_at)}` : ' · still running'}
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 14, marginBottom: 26 }}>
            <div style={{ ...CARD, padding: '15px 17px' }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#A3A39C', textTransform: 'uppercase', letterSpacing: '.04em' }}>Targets</div>
              <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4 }}>{run.targets_successful}/{run.targets_processed}</div>
            </div>
            <div style={{ ...CARD, padding: '15px 17px' }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#A3A39C', textTransform: 'uppercase', letterSpacing: '.04em' }}>Crashes</div>
              <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4, color: run.total_crashes ? '#C42B2B' : '#1A1A18' }}>{run.total_crashes}</div>
            </div>
            <div style={{ ...CARD, padding: '15px 17px' }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#A3A39C', textTransform: 'uppercase', letterSpacing: '.04em' }}>CVE candidates</div>
              <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4 }}>{run.total_cves}</div>
            </div>
            <div style={{ ...CARD, padding: '15px 17px' }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#A3A39C', textTransform: 'uppercase', letterSpacing: '.04em' }}>LLM cost</div>
              <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4 }}>{run.total_llm_cost_usd ? `$${run.total_llm_cost_usd.toFixed(2)}` : '—'}</div>
            </div>
          </div>

          <div style={{ ...CARD, overflow: 'hidden' }}>
            <div style={{ padding: '16px 20px 13px', borderBottom: '1px solid #F0F0EC' }}>
              <h2 style={{ fontSize: 15, fontWeight: 700, margin: 0 }}>Per-function results</h2>
            </div>
            {run.results.length === 0 && <Empty>This run recorded no per-function results.</Empty>}
            {run.results.map((r, i) => (
              <div key={`${r.func_name}-${i}`} style={{ display: 'grid', gridTemplateColumns: '2fr 1.6fr .8fr .8fr .9fr', gap: 12, alignItems: 'center', padding: '11px 20px', borderBottom: '1px solid #F4F4F0' }}>
                <span style={{ ...MONO, fontSize: 12.5, color: '#33332E', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.func_name}</span>
                <span style={{ ...MONO, fontSize: 11.5, color: '#A3A39C', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.file_path}</span>
                <span style={{ ...MONO, fontSize: 12, color: statusColor(r.status) }}>{r.status}</span>
                <span style={{ ...MONO, fontSize: 12, color: r.crashes ? '#C42B2B' : '#A3A39C' }}>
                  {r.crashes ? `${r.crashes} crash${r.crashes === 1 ? '' : 'es'}` : '—'}
                </span>
                <span style={{ ...MONO, fontSize: 12, color: '#A3A39C', textAlign: 'right' }}>{fmtDuration(r.duration_seconds)}</span>
              </div>
            ))}
          </div>

          {run.results.some((r) => r.has_patch || r.feedback_iterations > 0) && (
            <div style={{ marginTop: 16, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <Pill bg={accentSoft} color={ACCENT}>
                {run.results.filter((r) => r.has_patch).length} with patch
              </Pill>
              <Pill bg="#F1F1EE" color="#66665F">
                {run.results.reduce((a, r) => a + r.feedback_iterations, 0)} feedback iterations
              </Pill>
            </div>
          )}
        </>
      )}
    </main>
  )
}
