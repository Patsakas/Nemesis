/**
 * Targets — the main flow: pick a target, inspect its functions (pin them,
 * compare OSS-Fuzz vs NEMESIS coverage), launch the engine, review crashes.
 * All data comes from the live API; nothing here is sample data.
 */
import { useCallback, useEffect, useState, type CSSProperties } from 'react'
import {
  fetchActiveScans, fetchCoverage, fetchFinding, fetchFindings,
  fetchFunctions, fetchTargets, launchScan, savePins, stopScan,
} from '../api'
import type {
  ActiveScan, CoverageSummary, FindingDetail, FindingSummary,
  FunctionInfo, FunctionsResponse, PinEntry, PinOptions, TargetInfo,
} from '../types'
import { PIN_DEFAULTS } from '../types'
import {
  ACCENT, CARD, CovCell, Empty, ErrorBox, Loading, MONO, PAGE, Pill, StatCard,
  accentBorder, accentSoft, accentSofter, severityColors,
} from '../ui'

const initials = (n: string) => (n.replace(/^lib/, '').slice(0, 2) || n.slice(0, 2)).toLowerCase()
const covPct = (v: number) => (v >= 0 ? v.toFixed(1) + '%' : '—')

/** Preset fuzzing budgets, in hours. 0 means "use whatever the mode defaults to". */
const BUDGETS: Array<[number, string]> = [
  [0, 'default'], [0.25, '15m'], [0.5, '30m'], [1, '1h'], [2, '2h'], [4, '4h'], [8, '8h'], [24, '24h'],
]

const fmtBudget = (h: number) => (h < 1 ? `${Math.round(h * 60)}m` : `${h}h`)

function repoLabel(t: TargetInfo): string {
  if (t.oss_fuzz_project) return `oss-fuzz/${t.oss_fuzz_project}`
  if (t.source_root) return t.source_root.split(/[\\/]/).filter(Boolean).pop() || t.name
  return 'local source'
}

export function TargetsPage({ route, navigate }:
  { route: string[]; navigate: (sub: string[]) => void }) {
  const [targets, setTargets] = useState<TargetInfo[]>([])
  const [findings, setFindings] = useState<FindingSummary[]>([])
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')

  // route: [] -> list | [name] -> target | [name, 'crashes'] -> crash analysis
  const selected = route[0] ?? null
  const showCrashes = route[1] === 'crashes'

  useEffect(() => {
    Promise.all([fetchTargets(), fetchFindings()])
      .then(([t, f]) => { setTargets(t); setFindings(f); setState('ready') })
      .catch(() => setState('error'))
  }, [])

  const findingsFor = (name: string) =>
    findings.filter((f) => f.library.toLowerCase() === name.toLowerCase())

  if (state === 'loading') return <main style={PAGE}><Loading what="targets" /></main>
  if (state === 'error') return <main style={PAGE}><ErrorBox>Could not load targets.</ErrorBox></main>

  if (selected) {
    if (showCrashes) {
      return <CrashScreen name={selected} findings={findingsFor(selected)}
        onBack={() => navigate([selected])} />
    }
    const t = targets.find((x) => x.name === selected)
    if (t) return (
      <RepoScreen target={t} findings={findingsFor(selected)}
        onBack={() => navigate([])} onViewCrashes={() => navigate([selected, 'crashes'])} />
    )
  }

  return <ListScreen targets={targets} findingsFor={findingsFor} openRepo={(n) => navigate([n])} />
}

// ── Screen 1: target list ────────────────────────────────────
function ListScreen(p: {
  targets: TargetInfo[]
  findingsFor: (name: string) => FindingSummary[]
  openRepo: (name: string) => void
}) {
  const [input, setInput] = useState('')
  const [result, setResult] = useState<null | { ok: boolean; title: string; sub: string; open?: string }>(null)

  const check = () => {
    const base = input.trim().toLowerCase().split('/').pop() || ''
    if (!base) { setResult(null); return }
    const match = p.targets.find((t) => t.name.toLowerCase() === base)
    setResult(match
      ? { ok: true, title: 'Configured target', sub: 'Open it to inspect functions and launch a run.', open: match.name }
      : { ok: false, title: 'Not configured yet', sub: `nemesis onboard --source-root <path> --project-name ${base}` })
  }

  const grid: CSSProperties = { display: 'grid', gridTemplateColumns: '1.8fr .9fr 1fr .9fr', gap: 12 }

  return (
    <main style={PAGE}>
      <h1 style={{ fontSize: 30, fontWeight: 700, letterSpacing: '-.02em', margin: '0 0 8px' }}>Choose a target</h1>
      <p style={{ fontSize: 15, color: '#77776F', margin: '0 0 30px', maxWidth: 560 }}>
        Point NEMESIS at a C/C++ library. Configured targets are listed below; anything new is onboarded from the CLI.
      </p>

      <div style={{ ...CARD, padding: 22 }}>
        <div style={{ display: 'flex', gap: 10 }}>
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 10, background: '#FBFBF9', border: '1px solid #E4E4DE', borderRadius: 10, padding: '0 14px', height: 46 }}>
            <span style={{ ...MONO, fontSize: 13, color: '#B4B4AC' }}>library</span>
            <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && check()}
              placeholder="libpng"
              style={{ ...MONO, flex: 1, border: 'none', outline: 'none', background: 'transparent', fontSize: 13.5, color: '#1A1A18' }} />
          </div>
          <button onClick={check} style={{ height: 46, padding: '0 22px', border: 'none', borderRadius: 10, background: ACCENT, color: '#FFF', fontSize: 14, fontWeight: 600, cursor: 'pointer' }}>Check</button>
        </div>

        {result && (
          <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12, padding: '13px 15px', borderRadius: 10, background: result.ok ? accentSoft : '#FBF3DD', border: `1px solid ${result.ok ? accentBorder : '#EAD9A8'}` }}>
            <span style={{ ...MONO, fontWeight: 600, fontSize: 14, color: result.ok ? ACCENT : '#9A7314' }}>{result.ok ? '✓' : '!'}</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13.5, fontWeight: 600, color: '#33332E' }}>{result.title}</div>
              <div style={{ ...MONO, fontSize: 12, color: '#85857D', marginTop: 2, wordBreak: 'break-word' }}>{result.sub}</div>
            </div>
            {result.open && (
              <button onClick={() => p.openRepo(result.open!)}
                style={{ height: 34, padding: '0 14px', border: 'none', borderRadius: 8, background: ACCENT, color: '#FFF', fontSize: 12.5, fontWeight: 600, cursor: 'pointer' }}>Open →</button>
            )}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', margin: '40px 0 14px' }}>
        <h2 style={{ fontSize: 13, fontWeight: 600, color: '#8A8A82', letterSpacing: '.06em', textTransform: 'uppercase', margin: 0 }}>Configured targets</h2>
        <span style={{ ...MONO, fontSize: 12, color: '#A3A39C' }}>{p.targets.length} targets</span>
      </div>

      {p.targets.length === 0 ? (
        <Empty>No targets configured. Add one with <span style={MONO}>nemesis onboard</span>.</Empty>
      ) : (
        <div style={{ ...CARD, overflow: 'hidden' }}>
          <div style={{ ...grid, padding: '12px 20px', borderBottom: '1px solid #F0F0EC', fontSize: 11, fontWeight: 600, color: '#A3A39C', letterSpacing: '.05em', textTransform: 'uppercase' }}>
            <span>Library</span><span>Strategy</span><span>Pinned funcs</span><span style={{ textAlign: 'right' }}>Result</span>
          </div>
          {p.targets.map((t) => {
            const fs = p.findingsFor(t.name)
            const clean = fs.length === 0
            return (
              <div key={t.name} className="nem-row" onClick={() => p.openRepo(t.name)}
                style={{ ...grid, alignItems: 'center', padding: '15px 20px', borderBottom: '1px solid #F4F4F0', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 11, minWidth: 0 }}>
                  <div style={{ ...MONO, width: 30, height: 30, borderRadius: 8, background: accentSoft, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 600, fontSize: 12, color: ACCENT, flexShrink: 0 }}>{initials(t.name)}</div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 14.5 }}>{t.name}</div>
                    <div style={{ ...MONO, fontSize: 11, color: '#A3A39C', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{repoLabel(t)}</div>
                  </div>
                </div>
                <span style={{ ...MONO, fontSize: 12.5, color: '#66665F' }}>{t.strategy}</span>
                <span style={{ ...MONO, fontSize: 13, color: '#66665F' }}>{t.pinned_func_count || '—'}</span>
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <Pill bg={clean ? accentSoft : '#FEECEC'} color={clean ? ACCENT : '#C42B2B'}>
                    {clean ? 'Clean' : `${fs.length} finding${fs.length === 1 ? '' : 's'}`}
                  </Pill>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </main>
  )
}

// ── Screen 2: target detail ──────────────────────────────────
function RepoScreen(p: {
  target: TargetInfo
  findings: FindingSummary[]
  onBack: () => void
  onViewCrashes: () => void
}) {
  const t = p.target
  const [cov, setCov] = useState<CoverageSummary | null>(null)
  const [covState, setCovState] = useState<'loading' | 'ready' | 'none'>('loading')
  const [active, setActive] = useState<ActiveScan | null>(null)
  const [busy, setBusy] = useState(false)
  const [mode, setMode] = useState<'scan' | 'deep'>('scan')
  const [budget, setBudget] = useState(0)   // hours per target; 0 = mode default

  useEffect(() => {
    let alive = true
    setCovState('loading')
    fetchCoverage(t.name)
      .then((c) => { if (alive) { setCov(c); setCovState('ready') } })
      .catch(() => { if (alive) { setCov(null); setCovState('none') } })
    return () => { alive = false }
  }, [t.name])

  useEffect(() => {
    let alive = true
    const tick = () => fetchActiveScans()
      .then((l) => { if (alive) setActive(l.find((s) => s.target === t.name && s.is_running) ?? null) })
      .catch(() => {})
    void tick()
    const id = setInterval(tick, 4000)
    return () => { alive = false; clearInterval(id) }
  }, [t.name])

  const start = async () => {
    setBusy(true)
    try {
      await launchScan({
        target: t.name, scan: mode === 'scan', deep: mode === 'deep',
        strategy: t.strategy,
        // 0 = keep the mode's preset (15 min for scan)
        timeout_hours: budget,
        ...(mode === 'deep' && budget ? { deep_hours: budget } : {}),
      })
      setActive((await fetchActiveScans()).find((s) => s.target === t.name) ?? null)
    } catch { /* reflected by the active-scan poll */ } finally { setBusy(false) }
  }

  const stop = async () => {
    setBusy(true)
    try { await stopScan(t.name); setActive(null) } catch { /* ignore */ } finally { setBusy(false) }
  }

  const avg = cov?.avg_source_coverage ?? 0
  const crashCount = p.findings.length

  return (
    <main style={PAGE}>
      <button onClick={p.onBack} style={{ ...MONO, border: 'none', background: 'none', padding: 0, marginBottom: 18, fontSize: 12.5, color: '#9A9A92', cursor: 'pointer' }}>← all targets</button>

      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 8, flexWrap: 'wrap' }}>
        <div style={{ ...MONO, width: 46, height: 46, borderRadius: 12, background: accentSoft, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 600, fontSize: 18, color: ACCENT }}>{initials(t.name)}</div>
        <div>
          <h1 style={{ fontSize: 26, fontWeight: 700, letterSpacing: '-.02em', margin: 0 }}>{t.name}</h1>
          <div style={{ ...MONO, fontSize: 12.5, color: '#A3A39C' }}>{repoLabel(t)}</div>
        </div>
        {t.oss_fuzz_project && <Pill bg={accentSoft} color={ACCENT}>OSS-Fuzz integrated</Pill>}
        {active && (
          <Pill bg={accentSoft} color={ACCENT}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: ACCENT, animation: 'nemPulse 1.6s ease-in-out infinite' }} />
            running · PID {active.pid}
          </Pill>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, margin: '26px 0' }}>
        <StatCard label="Avg coverage" value={covState === 'ready' ? covPct(avg) : '—'} sub={cov ? `run ${cov.run_id.slice(0, 8)}` : 'no runs yet'} />
        <StatCard label="Functions" value={cov?.targets.length || t.pinned_func_count || '—'} sub={cov ? 'in latest run' : `${t.pinned_func_count} pinned`} />
        <StatCard label="Covered" value={cov?.targets_with_coverage ?? '—'} sub="functions with data" />
        <StatCard label="Findings" value={crashCount} sub={crashCount ? 'triaged crashes' : 'clean so far'} accent={false} />
      </div>

      {/* Launch panel */}
      <div style={{ ...CARD, padding: '20px 24px 16px', marginBottom: 26 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ fontSize: 15, fontWeight: 700, margin: 0 }}>Run the engine</h2>
            <p style={{ fontSize: 12.5, color: '#85857D', margin: '4px 0 0' }}>
              Pinned functions are fuzzed first; the rest are scored by recon.
              {' '}Budget: <strong>{budget ? fmtBudget(budget) : mode === 'deep' ? '4h' : '15m'} per target</strong>.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', gap: 4, background: '#F1F1EE', borderRadius: 9, padding: 3 }}>
              {(['scan', 'deep'] as const).map((m) => (
                <button key={m} onClick={() => setMode(m)}
                  style={{ padding: '6px 14px', border: 'none', borderRadius: 7, background: mode === m ? '#FFF' : 'transparent', color: mode === m ? '#1A1A18' : '#8A8A82', fontSize: 12.5, fontWeight: 600, cursor: 'pointer' }}>
                  {m === 'scan' ? 'Scan' : 'Deep'}
                </button>
              ))}
            </div>
            {active ? (
              <button onClick={() => void stop()} disabled={busy}
                style={{ height: 40, padding: '0 20px', borderRadius: 10, border: '1px solid #F3D9D2', background: '#FFF', color: '#C42B2B', fontSize: 14, fontWeight: 600, cursor: busy ? 'default' : 'pointer' }}>
                {busy ? '…' : 'Stop run'}
              </button>
            ) : (
              <button onClick={() => void start()} disabled={busy}
                style={{ height: 40, padding: '0 20px', border: 'none', borderRadius: 10, background: busy ? '#EDEDE8' : ACCENT, color: busy ? '#B4B4AC' : '#FFF', fontSize: 14, fontWeight: 600, cursor: busy ? 'default' : 'pointer' }}>
                {busy ? 'Launching…' : `Start ${mode} →`}
              </button>
            )}
          </div>
        </div>

        {/* Time budget */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 16, paddingTop: 14, borderTop: '1px solid #F0F0EC', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: '#A3A39C', letterSpacing: '.05em', textTransform: 'uppercase' }}>
            Fuzz for
          </span>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {BUDGETS.map(([hours, label]) => {
              const on = budget === hours
              return (
                <button key={label} onClick={() => setBudget(hours)} disabled={!!active}
                  style={{ ...MONO, padding: '5px 12px', borderRadius: 8, border: `1px solid ${on ? ACCENT : '#E4E4DE'}`, background: on ? ACCENT : '#FFF', color: on ? '#FFF' : '#66665F', fontSize: 12.5, fontWeight: 600, cursor: active ? 'default' : 'pointer', opacity: active ? 0.55 : 1 }}>
                  {label}
                </button>
              )
            })}
          </div>
          <input type="number" min="0" step="0.25" value={budget || ''} disabled={!!active}
            onChange={(e) => setBudget(Math.max(0, Number(e.target.value) || 0))}
            placeholder="custom h"
            style={{ ...MONO, width: 96, height: 30, padding: '0 10px', fontSize: 12, color: '#1A1A18', background: '#FBFBF9', border: '1px solid #E4E4DE', borderRadius: 8, outline: 'none' }} />
          <span style={{ fontSize: 12, color: '#A3A39C' }}>
            per target{budget ? '' : ` · default for ${mode}`}
          </span>
        </div>
      </div>

      <FunctionsPanel target={t.name} />

      <div onClick={p.onViewCrashes} style={{ ...CARD, display: 'flex', alignItems: 'center', gap: 16, padding: '20px 24px', cursor: 'pointer', background: crashCount ? '#FEF7F5' : '#FFF', borderColor: crashCount ? '#F3D9D2' : '#EAEAE6' }}>
        <div style={{ ...MONO, width: 40, height: 40, borderRadius: 11, background: crashCount ? '#FCE3DC' : accentSoft, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 16, color: crashCount ? '#C42B2B' : ACCENT }}>{crashCount ? '!' : '✓'}</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: crashCount ? '#8A2E1C' : '#1A1A18' }}>
            {crashCount ? `Review ${crashCount} finding${crashCount === 1 ? '' : 's'}` : 'No findings to review'}
          </div>
          <div style={{ fontSize: 13, color: crashCount ? '#B07460' : '#85857D', marginTop: 1 }}>
            {crashCount ? 'Triage, sanitizer traces and root cause' : 'This target is clean so far'}
          </div>
        </div>
        <span style={{ ...MONO, fontSize: 13, color: crashCount ? '#B07460' : '#85857D' }}>view →</span>
      </div>
    </main>
  )
}

// ── Functions + pinning ──────────────────────────────────────

const ROW_CAP = 300

const BOOL_OPTS: Array<[keyof PinOptions, string, string]> = [
  ['indirect_reach', 'Indirect reach', 'Reached through a public API rather than called directly'],
  ['direct_internal', 'Direct internal', 'Call it directly via internal headers'],
  ['force_no_blocker', 'No blocker patch', 'Skip patch generation — already reachable'],
  ['differential_oracle', 'Round-trip oracle', 'Assert decode(encode(x)) == x'],
  ['threaded_oracle', 'Threaded oracle', 'Drive it from several threads (pair with TSan)'],
  ['auto_expose', 'Auto expose', 'Let the pipeline expose a static symbol'],
]

const TEXT_OPTS: Array<[keyof PinOptions, string, string]> = [
  ['harness_hint', 'Harness hint', 'Free-text guidance injected into the harness prompt'],
  ['differential_reference', 'Differential reference', 'Reference impl to compare against, e.g. xmlReadMemoryRecover'],
]

const LIST_OPTS: Array<[keyof PinOptions, string, string]> = [
  ['needed_headers', 'Needed headers', 'Comma-separated headers the harness must include'],
  ['output_invariants', 'Output invariants', 'Comma-separated C expressions asserted after the call'],
]

function pinsPayload(fns: FunctionInfo[]): PinEntry[] {
  return fns.filter((f) => f.pinned).map((f) => ({
    func_name: f.func_name, file_path: f.file_path, line: f.line,
    ...PIN_DEFAULTS, ...f.pin_options,
  }))
}

function FunctionsPanel({ target }: { target: string }) {
  const [data, setData] = useState<FunctionsResponse | null>(null)
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [query, setQuery] = useState('')
  const [pinnedOnly, setPinnedOnly] = useState(false)
  const [showAll, setShowAll] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback((refresh = false) => {
    setState('loading'); setError(null)
    fetchFunctions(target, refresh)
      .then((d) => { setData(d); setState('ready') })
      .catch((e) => { setError(String(e)); setState('error') })
  }, [target])

  useEffect(() => { load() }, [load])

  /** Apply a change locally, then persist the whole pin set. Rolls back on failure. */
  const commit = async (next: FunctionInfo[]) => {
    if (!data) return
    const prev = data
    setData({ ...data, functions: next, pinned_count: next.filter((f) => f.pinned).length })
    setSaving(true); setError(null)
    try {
      await savePins(target, pinsPayload(next))
    } catch (e) {
      setData(prev)
      setError(`Could not save: ${String(e)}`)
    } finally { setSaving(false) }
  }

  const togglePin = (name: string) => {
    if (!data || saving) return
    void commit(data.functions.map((f) => f.func_name !== name ? f : ({
      ...f, pinned: !f.pinned,
      pin_options: !f.pinned ? { ...PIN_DEFAULTS, ...f.pin_options } : f.pin_options,
    })))
  }

  const setOption = (name: string, key: keyof PinOptions, value: unknown) => {
    if (!data || saving) return
    void commit(data.functions.map((f) => f.func_name !== name ? f : ({
      ...f, pin_options: { ...PIN_DEFAULTS, ...f.pin_options, [key]: value },
    })))
  }

  const all = data?.functions ?? []
  const q = query.trim().toLowerCase()
  const shown = all.filter((f) =>
    (!pinnedOnly || f.pinned) &&
    (!q || f.func_name.toLowerCase().includes(q) || f.file_path.toLowerCase().includes(q)))
  const visible = showAll ? shown : shown.slice(0, ROW_CAP)
  const grid: CSSProperties = { display: 'grid', gridTemplateColumns: '26px 2.1fr 1.15fr 1.15fr .7fr', gap: 12, alignItems: 'center' }

  return (
    <div style={{ ...CARD, overflow: 'hidden', marginBottom: 26 }}>
      <div style={{ padding: '18px 22px 14px', borderBottom: '1px solid #F0F0EC' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ fontSize: 15, fontWeight: 700, margin: 0 }}>Functions</h2>
            <p style={{ fontSize: 12.5, color: '#85857D', margin: '4px 0 0' }}>
              Tick to pin — written straight into <span style={MONO}>config/targets/{target}.yaml</span>. Open a pinned row for oracle and harness options.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {saving && <span style={{ ...MONO, fontSize: 11.5, color: '#A3A39C' }}>saving…</span>}
            <Pill bg={accentSoft} color={ACCENT}>{data?.pinned_count ?? 0} pinned</Pill>
            <button onClick={() => load(true)} title="Re-fetch from OSS-Fuzz Introspector"
              style={{ ...MONO, border: '1px solid #E4E4DE', background: '#FFF', color: '#66665F', fontSize: 11.5, fontWeight: 600, padding: '5px 11px', borderRadius: 8, cursor: 'pointer' }}>refresh</button>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 14, flexWrap: 'wrap' }}>
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by name or file…"
            style={{ ...MONO, flex: 1, minWidth: 200, height: 34, padding: '0 12px', fontSize: 12.5, color: '#1A1A18', background: '#FBFBF9', border: '1px solid #E4E4DE', borderRadius: 8, outline: 'none' }} />
          <button onClick={() => setPinnedOnly((v) => !v)}
            style={{ height: 34, padding: '0 13px', borderRadius: 8, border: `1px solid ${pinnedOnly ? ACCENT : '#E4E4DE'}`, background: pinnedOnly ? ACCENT : '#FFF', color: pinnedOnly ? '#FFF' : '#66665F', fontSize: 12.5, fontWeight: 600, cursor: 'pointer' }}>pinned only</button>
        </div>

        {error && <div style={{ marginTop: 12 }}><ErrorBox>{error}</ErrorBox></div>}
        {data?.source === 'local_scan' && (
          <div style={{ marginTop: 12, padding: '10px 13px', borderRadius: 9, background: '#FBF3DD', border: '1px solid #EAD9A8', color: '#7A5C10', fontSize: 12.5 }}>
            Not an OSS-Fuzz project — this list comes from a local source scan, so there is no OSS-Fuzz coverage to compare against.
          </div>
        )}
      </div>

      <div style={{ ...grid, padding: '11px 22px', borderBottom: '1px solid #F0F0EC', fontSize: 11, fontWeight: 600, color: '#A3A39C', letterSpacing: '.05em', textTransform: 'uppercase' }}>
        <span>pin</span><span>Function</span><span>OSS-Fuzz cov.</span><span>NEMESIS cov.</span><span style={{ textAlign: 'right' }}>Status</span>
      </div>

      {state === 'loading' && <Loading what="functions (first Introspector fetch can take a few seconds)" />}
      {state === 'error' && <div style={{ padding: 22 }}><ErrorBox>Could not load functions. {error}</ErrorBox></div>}
      {state === 'ready' && shown.length === 0 && (
        <div style={{ padding: 22, color: '#A3A39C', fontSize: 13.5 }}>
          {all.length === 0 ? 'No functions found for this target.' : 'Nothing matches this filter.'}
        </div>
      )}

      {state === 'ready' && visible.map((f) => {
        const open = expanded === f.func_name
        const opts = { ...PIN_DEFAULTS, ...f.pin_options }
        return (
          <div key={f.func_name} style={{ borderBottom: '1px solid #F4F4F0', background: f.pinned ? accentSofter : '#FFF' }}>
            <div className="nem-row" style={{ ...grid, padding: '11px 22px', cursor: 'pointer' }}
              onClick={() => f.pinned ? setExpanded(open ? null : f.func_name) : togglePin(f.func_name)}>
              <div onClick={(e) => { e.stopPropagation(); togglePin(f.func_name) }}
                style={{ ...MONO, width: 17, height: 17, borderRadius: 5, border: `1.5px solid ${f.pinned ? ACCENT : '#D4D4CC'}`, background: f.pinned ? ACCENT : '#FFF', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: 11, fontWeight: 700, lineHeight: 1 }}>
                {f.pinned ? '✓' : ''}
              </div>
              <div style={{ minWidth: 0 }}>
                <div style={{ ...MONO, fontSize: 13, color: '#33332E', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {f.func_name}
                  {f.pinned && <span style={{ marginLeft: 8, fontSize: 11, color: ACCENT }}>{open ? '▾ options' : '▸ options'}</span>}
                </div>
                <div style={{ ...MONO, fontSize: 11, color: '#A3A39C', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {f.file_path}{f.line ? `:${f.line}` : ''}
                </div>
              </div>
              <CovCell pct={f.oss_fuzz_coverage_pct} color="#C7C7BF" emptyLabel="no data" />
              <CovCell pct={f.nemesis_coverage_pct} color={ACCENT} emptyLabel="not fuzzed yet" />
              <span style={{ ...MONO, fontSize: 11, color: '#A3A39C', textAlign: 'right', textTransform: 'uppercase', letterSpacing: '.04em' }}>{f.status}</span>
            </div>

            {open && f.pinned && (
              <div style={{ padding: '4px 22px 18px 65px', background: '#FBFBF9', borderTop: '1px solid #F0F0EC' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, margin: '14px 0' }}>
                  {BOOL_OPTS.map(([key, label, hint]) => {
                    const on = Boolean(opts[key])
                    return (
                      <button key={key} title={hint} onClick={() => setOption(f.func_name, key, !on)}
                        style={{ padding: '6px 12px', borderRadius: 999, border: `1px solid ${on ? ACCENT : '#E4E4DE'}`, background: on ? ACCENT : '#FFF', color: on ? '#FFF' : '#66665F', fontSize: 12, fontWeight: 600, cursor: 'pointer' }}>
                        {on ? '✓ ' : ''}{label}
                      </button>
                    )
                  })}
                </div>
                {TEXT_OPTS.map(([key, label, hint]) => (
                  <OptionRow key={key} label={label} hint={hint}
                    value={String(opts[key] ?? '')}
                    onCommit={(v) => setOption(f.func_name, key, v)} />
                ))}
                {LIST_OPTS.map(([key, label, hint]) => (
                  <OptionRow key={key} label={label} hint={hint}
                    value={(opts[key] as string[] ?? []).join(', ')}
                    onCommit={(v) => setOption(f.func_name, key,
                      v.split(',').map((s) => s.trim()).filter(Boolean))} />
                ))}
              </div>
            )}
          </div>
        )
      })}

      {state === 'ready' && shown.length > visible.length && (
        <div style={{ padding: '14px 22px', background: '#FBFBF9', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <span style={{ fontSize: 12.5, color: '#85857D' }}>Showing {visible.length} of {shown.length} — filter to narrow down.</span>
          <button onClick={() => setShowAll(true)}
            style={{ height: 32, padding: '0 14px', borderRadius: 8, border: '1px solid #E4E4DE', background: '#FFF', color: '#66665F', fontSize: 12.5, fontWeight: 600, cursor: 'pointer' }}>Show all {shown.length}</button>
        </div>
      )}
    </div>
  )
}

/** Text field that only persists on blur/Enter, so we don't PUT on every keystroke. */
function OptionRow({ label, hint, value, onCommit }:
  { label: string; hint: string; value: string; onCommit: (v: string) => void }) {
  const [draft, setDraft] = useState(value)
  useEffect(() => { setDraft(value) }, [value])
  const commit = () => { if (draft !== value) onCommit(draft) }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
      <label title={hint} style={{ fontSize: 12, fontWeight: 600, color: '#85857D', minWidth: 160 }}>{label}</label>
      <input value={draft} onChange={(e) => setDraft(e.target.value)} onBlur={commit}
        onKeyDown={(e) => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur() }}
        placeholder={hint}
        style={{ ...MONO, flex: 1, height: 32, padding: '0 11px', fontSize: 12, color: '#1A1A18', background: '#FFF', border: '1px solid #E4E4DE', borderRadius: 7, outline: 'none' }} />
    </div>
  )
}

// ── Screen 3: crash analysis ─────────────────────────────────
function CrashScreen(p: { name: string; findings: FindingSummary[]; onBack: () => void }) {
  const [details, setDetails] = useState<Record<string, FindingDetail>>({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    setLoading(true)
    Promise.allSettled(p.findings.map((f) => fetchFinding(f.id))).then((res) => {
      if (!alive) return
      const map: Record<string, FindingDetail> = {}
      res.forEach((r) => { if (r.status === 'fulfilled') map[r.value.id] = r.value })
      setDetails(map); setLoading(false)
    })
    return () => { alive = false }
  }, [p.findings])

  const copy = (txt: string) => { if (navigator.clipboard) navigator.clipboard.writeText(txt).catch(() => {}) }

  return (
    <main style={PAGE}>
      <button onClick={p.onBack} style={{ ...MONO, border: 'none', background: 'none', padding: 0, marginBottom: 18, fontSize: 12.5, color: '#9A9A92', cursor: 'pointer' }}>← {p.name}</button>
      <h1 style={{ fontSize: 26, fontWeight: 700, letterSpacing: '-.02em', margin: '0 0 4px' }}>Crash analysis</h1>
      <p style={{ fontSize: 14, color: '#77776F', margin: '0 0 26px' }}>
        {p.findings.length === 0
          ? 'No sanitizer faults were recorded for this target.'
          : `${p.findings.length} distinct finding${p.findings.length === 1 ? '' : 's'} in the database.`}
      </p>

      {p.findings.length === 0 ? (
        <div style={{ ...CARD, padding: 44, textAlign: 'center' }}>
          <div style={{ ...MONO, width: 54, height: 54, borderRadius: '50%', margin: '0 auto 16px', background: accentSoft, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24, fontWeight: 700, color: ACCENT }}>✓</div>
          <div style={{ fontSize: 18, fontWeight: 700 }}>No crashes found</div>
          <div style={{ fontSize: 14, color: '#85857D', margin: '6px auto 0', maxWidth: 420 }}>Nothing has been triaged for this target yet. Run a scan and crashes will show up here.</div>
        </div>
      ) : loading ? <Loading what="crash details" /> : p.findings.map((f) => {
        const d = details[f.id]
        const sc = severityColors(f.severity)
        const novel = !f.cve_id
        const cvss = f.cvss_estimate ?? d?.cve_assessment?.cvss_estimate ?? null
        const report = d?.root_cause || d?.description || ''
        return (
          <div key={f.id} style={{ ...CARD, overflow: 'hidden', marginBottom: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '18px 22px', borderBottom: '1px solid #F0F0EC', flexWrap: 'wrap' }}>
              <span style={{ fontSize: 12, fontWeight: 700, padding: '4px 11px', borderRadius: 999, background: sc.bg, color: sc.color, textTransform: 'uppercase', letterSpacing: '.03em' }}>{f.severity}</span>
              <span style={{ ...MONO, fontSize: 14, fontWeight: 600 }}>{f.crash_type}</span>
              <span style={{ ...MONO, fontSize: 11.5, color: '#A3A39C' }}>{f.id}</span>
              <span style={{ flex: 1 }} />
              <Pill bg={novel ? accentSoft : '#F3EEFB'} color={novel ? ACCENT : '#7A4FC0'}>
                {novel ? 'Potentially novel' : `Known: ${f.cve_id}`}
              </Pill>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', borderBottom: '1px solid #F0F0EC' }}>
              <div style={{ padding: '16px 22px', borderRight: '1px solid #F0F0EC' }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#A3A39C', letterSpacing: '.05em', textTransform: 'uppercase', marginBottom: 6 }}>Location</div>
                <div style={{ ...MONO, fontSize: 12.5, color: '#33332E' }}>{f.function}()</div>
                <div style={{ ...MONO, fontSize: 11.5, color: '#A3A39C', marginTop: 2 }}>{d?.crash_location || f.file}</div>
              </div>
              <div style={{ padding: '16px 22px' }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#A3A39C', letterSpacing: '.05em', textTransform: 'uppercase', marginBottom: 6 }}>Weakness</div>
                <div style={{ fontSize: 13, color: '#33332E' }}>{f.cwe} — {f.cwe_name}</div>
                <div style={{ fontSize: 11.5, color: '#A3A39C', marginTop: 2 }}>{cvss != null ? `CVSS ${cvss}` : 'CVSS —'} · {f.status}{f.discovered_date ? ` · ${f.discovered_date}` : ''}</div>
              </div>
            </div>
            {d?.asan_error && (
              <div style={{ padding: '16px 22px', borderBottom: '1px solid #F0F0EC' }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#A3A39C', letterSpacing: '.05em', textTransform: 'uppercase', marginBottom: 8 }}>Sanitizer output</div>
                <pre style={{ ...MONO, margin: 0, padding: '14px 16px', background: '#FBFAF7', border: '1px solid #EEEEE8', borderRadius: 10, fontSize: 12, lineHeight: 1.6, color: '#55554E', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{d.asan_error}</pre>
              </div>
            )}
            {report && (
              <div style={{ padding: '18px 22px', background: accentSofter }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 10 }}>
                  <span style={{ ...MONO, fontSize: 13, fontWeight: 700, color: ACCENT }}>⚑</span>
                  <span style={{ fontSize: 13.5, fontWeight: 700, color: '#33332E' }}>Root cause</span>
                  <span style={{ flex: 1 }} />
                  <span onClick={() => copy(report)} style={{ fontSize: 11.5, fontWeight: 600, color: ACCENT, cursor: 'pointer' }}>copy</span>
                </div>
                <div style={{ background: '#FFF', border: `1px solid ${accentBorder}`, borderRadius: 10, padding: '16px 18px', fontSize: 13, lineHeight: 1.65, color: '#44443E', whiteSpace: 'pre-wrap' }}>{report}</div>
              </div>
            )}
          </div>
        )
      })}
    </main>
  )
}
