import { useCallback, useEffect, useState, type CSSProperties } from 'react'
import { fetchTargets } from './api'
import { LivePage } from './pages/Live'
import { OpsPage } from './pages/Ops'
import { ReportsPage } from './pages/Reports'
import { RunsPage } from './pages/Runs'
import { TargetsPage } from './pages/Targets'
import { ACCENT, CARD, MONO, useHashRoute } from './ui'

type View = 'targets' | 'ops' | 'runs' | 'reports' | 'live'

const TABS: Array<[View, string]> = [
  ['targets', 'Targets'],
  ['live', 'Live'],
  ['ops', 'Operations'],
  ['runs', 'Runs'],
  ['reports', 'Reports'],
]

const VIEWS = new Set<string>(['targets', 'ops', 'runs', 'reports', 'live'])

export default function App() {
  const [route, navigate] = useHashRoute()
  const view: View = (VIEWS.has(route[0]) ? route[0] : 'targets') as View
  const setView = (v: View) => navigate([v])
  const [engine, setEngine] = useState<'checking' | 'online' | 'offline'>('checking')

  const ping = useCallback(() => {
    fetchTargets().then(() => setEngine('online')).catch(() => setEngine('offline'))
  }, [])

  useEffect(() => {
    ping()
    const id = setInterval(ping, 15000)
    return () => clearInterval(id)
  }, [ping])

  const tab = (active: boolean): CSSProperties => ({
    padding: '7px 14px', border: 'none', borderRadius: 8,
    background: active ? '#F1F1EE' : 'transparent',
    color: active ? '#1A1A18' : '#85857D',
    fontSize: 13, fontWeight: 600, cursor: 'pointer',
  })

  const shell: CSSProperties = {
    minHeight: '100vh', background: '#F6F6F4', color: '#1A1A18',
    fontFamily: "'Hanken Grotesk', system-ui, sans-serif", WebkitFontSmoothing: 'antialiased',
  }

  return (
    <div style={shell}>
      <header style={{ height: 60, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, padding: '0 28px', background: '#FFF', borderBottom: '1px solid #EAEAE6', position: 'sticky', top: 0, zIndex: 30 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, cursor: 'pointer' }} onClick={() => setView('targets')}>
          <div style={{ width: 22, height: 22, borderRadius: 6, background: ACCENT, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ width: 7, height: 7, borderRadius: 2, background: '#FFF' }} />
          </div>
          <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: '.14em' }}>NEMESIS</span>
        </div>

        <nav style={{ display: 'flex', gap: 4, flex: 1 }}>
          {TABS.map(([v, label]) => (
            <button key={v} style={tab(view === v)} onClick={() => setView(v)}>{label}</button>
          ))}
        </nav>

        <div style={{ ...MONO, display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: engine === 'online' ? '#8A8A82' : '#C25A17' }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: engine === 'online' ? ACCENT : '#C25A17', animation: engine === 'online' ? 'nemPulse 2s ease-in-out infinite' : 'none' }} />
          {engine === 'online' ? 'engine online' : engine === 'checking' ? 'connecting…' : 'engine offline'}
        </div>
      </header>

      {engine === 'offline' ? (
        <div style={{ maxWidth: 1060, margin: '0 auto', padding: '46px 28px' }}>
          <div style={{ ...CARD, borderColor: '#F3D9D2', padding: '22px 24px', maxWidth: 640 }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#8A2E1C', marginBottom: 6 }}>Can’t reach the API</div>
            <div style={{ fontSize: 14, color: '#77776F', marginBottom: 12 }}>Start the backend, then reload:</div>
            <pre style={{ ...MONO, margin: 0, padding: '12px 14px', background: '#FBFAF7', border: '1px solid #EEEEE8', borderRadius: 10, fontSize: 12.5, color: '#55554E' }}>nemesis serve   # http://localhost:8000</pre>
            <button onClick={ping} style={{ marginTop: 14, height: 38, padding: '0 18px', border: 'none', borderRadius: 9, background: ACCENT, color: '#FFF', fontSize: 13.5, fontWeight: 600, cursor: 'pointer' }}>Retry</button>
          </div>
        </div>
      ) : (
        <>
          {view === 'targets' && (
            <TargetsPage
              route={route.slice(1)}
              navigate={(sub) => navigate(['targets', ...sub])}
            />
          )}
          {view === 'live' && <LivePage />}
          {view === 'ops' && <OpsPage />}
          {view === 'runs' && <RunsPage />}
          {view === 'reports' && <ReportsPage />}
        </>
      )}
    </div>
  )
}
