/**
 * Live — real-time AFL++ stats, streamed over /ws/live with a polled fallback.
 * This is what the engine is doing *right now*: execs/sec, corpus growth,
 * crashes and hangs as they are found.
 */
import { useEffect, useRef, useState } from 'react'
import { createLiveWebSocket, fetchLiveSnapshot, stopScan } from '../api'
import type { LiveSnapshot, LiveTargetStats } from '../types'
import {
  ACCENT, CARD, Empty, ErrorBox, Loading, MONO, PAGE, Pill,
  accentSoft, fmtDuration, fmtNum,
} from '../ui'

export function LivePage() {
  const [snap, setSnap] = useState<LiveSnapshot | null>(null)
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [transport, setTransport] = useState<'ws' | 'poll'>('poll')
  const [stopping, setStopping] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    let alive = true
    let poll: ReturnType<typeof setInterval> | null = null

    const startPolling = () => {
      if (poll) return
      setTransport('poll')
      const tick = () => fetchLiveSnapshot()
        .then((s) => { if (alive) { setSnap(s); setState('ready') } })
        .catch(() => { if (alive) setState('error') })
      void tick()
      poll = setInterval(tick, 3000)
    }

    // Prefer the websocket; fall back to polling if it never opens.
    try {
      const ws = createLiveWebSocket(
        (s) => { if (alive) { setSnap(s); setState('ready'); setTransport('ws') } },
        () => startPolling(),
      )
      wsRef.current = ws
      ws.onclose = () => { if (alive) startPolling() }
    } catch {
      startPolling()
    }
    // Always seed once so the page is never blank while the socket handshakes.
    void fetchLiveSnapshot()
      .then((s) => { if (alive && !snap) { setSnap(s); setState('ready') } })
      .catch(() => { if (alive) startPolling() })

    return () => {
      alive = false
      if (poll) clearInterval(poll)
      wsRef.current?.close()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const stop = async (target: string) => {
    setStopping(target)
    try {
      await stopScan(target)
      setSnap(await fetchLiveSnapshot())
    } catch {
      /* the row will simply stay until the next tick */
    } finally {
      setStopping(null)
    }
  }

  const targets = snap?.targets ?? []
  const running = targets.filter((t) => t.is_running)

  return (
    <main style={PAGE}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ fontSize: 26, fontWeight: 700, letterSpacing: '-.02em', margin: '0 0 4px' }}>Live fuzzing</h1>
          <p style={{ fontSize: 14, color: '#77776F', margin: 0 }}>
            {running.length ? `${running.length} fuzzer${running.length === 1 ? '' : 's'} running.` : 'Nothing is fuzzing right now.'}
          </p>
        </div>
        <span style={{ ...MONO, fontSize: 11.5, color: '#A3A39C' }}>
          {transport === 'ws' ? 'websocket' : 'polling every 3s'}
          {snap?.timestamp ? ` · ${snap.timestamp.slice(11, 19)}` : ''}
        </span>
      </div>

      <div style={{ marginTop: 26 }}>
        {state === 'loading' && <Loading what="live stats" />}
        {state === 'error' && <ErrorBox>Could not read live stats from the engine.</ErrorBox>}
        {state === 'ready' && targets.length === 0 && (
          <Empty>
            No AFL++ instances have reported yet. Start a scan from a target page and it will appear here.
          </Empty>
        )}
        {targets.map((t) => (
          <LiveCard key={t.target_name} t={t} stopping={stopping === t.target_name} onStop={() => void stop(t.target_name)} />
        ))}
      </div>
    </main>
  )
}

function LiveCard({ t, stopping, onStop }: { t: LiveTargetStats; stopping: boolean; onStop: () => void }) {
  const cells: Array<[string, string]> = [
    ['exec/sec', t.exec_per_sec ? t.exec_per_sec.toFixed(0) : '—'],
    ['corpus', fmtNum(t.total_paths)],
    ['crashes', String(t.unique_crashes)],
    ['hangs', String(t.unique_hangs)],
    ['map density', t.map_density_pct ? `${t.map_density_pct.toFixed(2)}%` : '—'],
    ['stability', t.stability_pct ? `${t.stability_pct.toFixed(1)}%` : '—'],
    ['runtime', fmtDuration(t.duration_seconds)],
  ]

  return (
    <div style={{ ...CARD, padding: '18px 22px', marginBottom: 16, borderColor: t.unique_crashes ? '#F3D9D2' : '#EAEAE6' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
        <span style={{ fontSize: 16, fontWeight: 700 }}>{t.target_name}</span>
        {t.is_running
          ? <Pill bg={accentSoft} color={ACCENT}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: ACCENT, animation: 'nemPulse 1.6s ease-in-out infinite' }} />
              running
            </Pill>
          : <Pill bg="#F1F1EE" color="#85857D">idle</Pill>}
        {t.unique_crashes > 0 && <Pill bg="#FEECEC" color="#C42B2B">{t.unique_crashes} crash{t.unique_crashes === 1 ? '' : 'es'}</Pill>}
        <span style={{ flex: 1 }} />
        {t.is_running && (
          <button onClick={onStop} disabled={stopping}
            style={{ height: 32, padding: '0 14px', borderRadius: 8, border: '1px solid #F3D9D2', background: stopping ? '#F1F1EE' : '#FFF', color: stopping ? '#B4B4AC' : '#C42B2B', fontSize: 12.5, fontWeight: 600, cursor: stopping ? 'default' : 'pointer' }}>
            {stopping ? 'stopping…' : 'Stop'}
          </button>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: 12 }}>
        {cells.map(([label, value]) => (
          <div key={label}>
            <div style={{ fontSize: 10.5, fontWeight: 600, color: '#A3A39C', letterSpacing: '.05em', textTransform: 'uppercase' }}>{label}</div>
            <div style={{ ...MONO, fontSize: 17, fontWeight: 600, marginTop: 3, color: label === 'crashes' && t.unique_crashes ? '#C42B2B' : '#1A1A18' }}>{value}</div>
          </div>
        ))}
      </div>

      {t.last_updated && (
        <div style={{ ...MONO, fontSize: 11, color: '#C4C4BC', marginTop: 12 }}>updated {t.last_updated.slice(11, 19)}</div>
      )}
    </div>
  )
}
