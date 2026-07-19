/** Shared design tokens and small presentational pieces used across the pages. */
import { useEffect, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'

/**
 * Minimal hash router. Keeps the URL meaningful (`#/targets/libpng/functions`)
 * so views are bookmarkable and the browser back button works — without
 * pulling in a routing library for what is a handful of screens.
 */
export function useHashRoute(): [string[], (segments: string[]) => void] {
  const read = () => window.location.hash.replace(/^#\/?/, '').split('/').filter(Boolean)
  const [segments, setSegments] = useState<string[]>(read)

  useEffect(() => {
    const onChange = () => setSegments(read())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])

  const navigate = (next: string[]) => {
    window.location.hash = '/' + next.join('/')
    setSegments(next)
  }
  return [segments, navigate]
}

export const ACCENT = '#16A34A'
export const accentSoft = `color-mix(in srgb, ${ACCENT} 12%, #ffffff)`
export const accentSofter = `color-mix(in srgb, ${ACCENT} 6%, #ffffff)`
export const accentBorder = `color-mix(in srgb, ${ACCENT} 30%, #ffffff)`
export const MONO: CSSProperties = { fontFamily: "'JetBrains Mono', monospace" }

export const CARD: CSSProperties = {
  background: '#FFF', border: '1px solid #EAEAE6', borderRadius: 14,
}
export const PAGE: CSSProperties = { maxWidth: 1060, margin: '0 auto', padding: '30px 28px 80px' }

export function severityColors(sev: string): { bg: string; color: string } {
  switch (sev.toLowerCase()) {
    case 'critical': return { bg: '#FEECEC', color: '#C42B2B' }
    case 'high': return { bg: '#FDF0E6', color: '#C25A17' }
    case 'medium': return { bg: '#FBF3DD', color: '#9A7314' }
    default: return { bg: '#EAF1FB', color: '#2C63B8' }
  }
}

export function fmtDuration(seconds: number): string {
  if (!seconds || seconds < 0) return '—'
  const h = Math.floor(seconds / 3600)
  const m = Math.round((seconds % 3600) / 60)
  if (h) return m ? `${h}h ${m}m` : `${h}h`
  if (m) return `${m}m`
  return `${Math.round(seconds)}s`
}

export function fmtDate(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return isNaN(d.getTime()) ? iso.slice(0, 16).replace('T', ' ') : d.toLocaleString()
}

export function fmtNum(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'k'
  return String(n)
}

export function StatCard({ label, value, sub, accent }:
  { label: string; value: string | number; sub?: string; accent?: boolean }) {
  return (
    <div style={{ ...CARD, padding: '17px 18px' }}>
      <div style={{ fontSize: 11.5, fontWeight: 600, color: '#A3A39C', letterSpacing: '.04em', textTransform: 'uppercase' }}>{label}</div>
      <div style={{ fontSize: 25, fontWeight: 700, marginTop: 6, fontVariantNumeric: 'tabular-nums', color: accent ? ACCENT : '#1A1A18' }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: '#A3A39C', marginTop: 2 }}>{sub}</div>}
    </div>
  )
}

/** Coverage/progress cell: a bar plus the number, or a muted label when unknown. */
export function CovCell({ pct, color, emptyLabel }:
  { pct: number; color: string; emptyLabel: string }) {
  if (pct < 0) return <span style={{ fontSize: 11.5, color: '#C4C4BC' }}>{emptyLabel}</span>
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, maxWidth: 74, height: 6, borderRadius: 999, background: '#EEEEEA', overflow: 'hidden' }}>
        <div style={{ height: '100%', borderRadius: 999, width: Math.min(100, pct) + '%', background: color }} />
      </div>
      <span style={{ ...MONO, fontSize: 12, color: '#66665F', minWidth: 42 }}>{pct.toFixed(1)}%</span>
    </div>
  )
}

export function Pill({ children, bg, color }: { children: ReactNode; bg: string; color: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600, padding: '4px 11px', borderRadius: 999, background: bg, color }}>
      {children}
    </span>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div style={{ ...CARD, padding: 40, textAlign: 'center', color: '#85857D', fontSize: 14 }}>{children}</div>
}

export function Loading({ what }: { what: string }) {
  return <div style={{ padding: 22, color: '#A3A39C', fontSize: 13.5 }}>Loading {what}…</div>
}

/** Sticky strip showing the run in flight. The pipeline spends its first
 *  several minutes in recon/LLM/build, where there are no AFL statistics yet —
 *  without this the dashboard looks idle while the engine is busy. */
export function RunBanner({ run }: { run: { target: string; stage: string; stage_num: number | string; func: string; detail: string; targets_done: number; targets_total: number; started_at: string } }) {
  const stages = ['recon', 'neural', 'symbolic', 'fuzzing']
  const current = typeof run.stage_num === 'number' ? run.stage_num : parseInt(String(run.stage_num), 10) || 0

  return (
    <div style={{ background: accentSofter, borderBottom: `1px solid ${accentBorder}`, padding: '10px 28px' }}>
      <div style={{ maxWidth: 1060, margin: '0 auto', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: ACCENT, animation: 'nemPulse 1.6s ease-in-out infinite', flexShrink: 0 }} />
        <span style={{ fontSize: 13.5, fontWeight: 700 }}>{run.target}</span>

        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          {stages.map((name, i) => {
            const n = i + 1
            const state = n < current ? 'done' : n === current ? 'now' : 'todo'
            return (
              <span key={name} title={`Stage ${n}: ${name}`}
                style={{
                  ...MONO, fontSize: 10.5, fontWeight: 600, padding: '3px 8px', borderRadius: 6,
                  background: state === 'now' ? ACCENT : state === 'done' ? accentSoft : '#F1F1EE',
                  color: state === 'now' ? '#FFF' : state === 'done' ? ACCENT : '#B4B4AC',
                }}>
                {name}
              </span>
            )
          })}
        </div>

        {run.func && (
          <span style={{ ...MONO, fontSize: 12, color: '#66665F', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 260 }}>
            {run.func}()
          </span>
        )}
        {run.detail && <span style={{ fontSize: 12.5, color: '#77776F' }}>{run.detail}</span>}

        <span style={{ flex: 1 }} />
        {run.targets_total > 0 && (
          <span style={{ ...MONO, fontSize: 11.5, color: '#85857D' }}>
            target {run.targets_done}/{run.targets_total}
          </span>
        )}
        <span style={{ ...MONO, fontSize: 11.5, color: '#A3A39C' }}>
          {fmtDuration((Date.now() - new Date(run.started_at).getTime()) / 1000)} elapsed
        </span>
      </div>
    </div>
  )
}

export function ErrorBox({ children }: { children: ReactNode }) {
  return (
    <div style={{ padding: '10px 13px', borderRadius: 9, background: '#FEECEC', border: '1px solid #F3D9D2', color: '#8A2E1C', fontSize: 12.5 }}>
      {children}
    </div>
  )
}
