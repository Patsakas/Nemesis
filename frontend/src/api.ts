import type {
  ActiveScan,
  CoverageSummary,
  FindingDetail,
  FindingSummary,
  FunctionsResponse,
  JobInfo,
  JobRequest,
  LiveSnapshot,
  PinEntry,
  PinResponse,
  ReportMeta,
  RunDetail,
  RunSummary,
  ScanRequest,
  ScanResponse,
  TargetInfo,
} from './types'

const BASE = '/api'

async function get<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(BASE + path, window.location.origin)
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== '') url.searchParams.set(k, v)
    })
  }
  const res = await fetch(url.toString())
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`)
  return res.json() as Promise<T>
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`HTTP ${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

async function put<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`HTTP ${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

async function del<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path, { method: 'DELETE' })
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`)
  return res.json() as Promise<T>
}

// ── Findings ─────────────────────────────────────────────────

export interface FindingsFilter {
  library?: string
  severity?: string
  cwe?: string
  status?: string
  cve_worthy?: boolean
}

export function fetchFindings(filter: FindingsFilter = {}): Promise<FindingSummary[]> {
  const params: Record<string, string> = {}
  if (filter.library) params.library = filter.library
  if (filter.severity) params.severity = filter.severity
  if (filter.cwe) params.cwe = filter.cwe
  if (filter.status) params.status = filter.status
  if (filter.cve_worthy !== undefined) params.cve_worthy = String(filter.cve_worthy)
  return get<FindingSummary[]>('/findings', params)
}

export function fetchFinding(id: string): Promise<FindingDetail> {
  return get<FindingDetail>(`/findings/${encodeURIComponent(id)}`)
}

// ── Runs ─────────────────────────────────────────────────────

export function fetchRuns(): Promise<RunSummary[]> {
  return get<RunSummary[]>('/runs')
}

export function fetchRun(runId: string): Promise<RunDetail> {
  return get<RunDetail>(`/runs/${encodeURIComponent(runId)}`)
}

// ── Reports ──────────────────────────────────────────────────

export function fetchReports(): Promise<ReportMeta[]> {
  return get<ReportMeta[]>('/reports')
}

export async function fetchReportMarkdown(id: string): Promise<string> {
  const res = await fetch(`${BASE}/reports/${encodeURIComponent(id)}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`)
  return res.text()
}

// ── Live ─────────────────────────────────────────────────────

export function fetchLiveSnapshot(): Promise<LiveSnapshot> {
  return get<LiveSnapshot>('/live/targets')
}

export function createLiveWebSocket(
  onMessage: (snapshot: LiveSnapshot) => void,
  onError?: (err: Event) => void,
): WebSocket {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(`${proto}//${window.location.host}/ws/live`)
  ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data as string) as LiveSnapshot
      onMessage(data)
    } catch {
      // ignore parse errors
    }
  }
  if (onError) ws.onerror = onError
  return ws
}

// ── Targets ──────────────────────────────────────────────────

export function fetchTargets(): Promise<TargetInfo[]> {
  return get<TargetInfo[]>('/targets')
}

// ── Functions + pinning ──────────────────────────────────────

/** All functions for a target, with OSS-Fuzz + NEMESIS coverage and pin state. */
export function fetchFunctions(target: string, refresh = false): Promise<FunctionsResponse> {
  return get<FunctionsResponse>(
    `/targets/${encodeURIComponent(target)}/functions`,
    refresh ? { refresh: 'true' } : undefined,
  )
}

/** Replace the pinned set for a target (writes config/targets/<t>.yaml). */
export function savePins(target: string, pins: PinEntry[]): Promise<PinResponse> {
  return put<PinResponse>(`/targets/${encodeURIComponent(target)}/pins`, { pins })
}

// ── Jobs (CLI operations) ────────────────────────────────────

/** Which operations the backend will run (server-side whitelist). */
export function fetchJobKinds(): Promise<string[]> {
  return get<string[]>('/jobs/kinds')
}

export function launchJob(req: JobRequest): Promise<JobInfo> {
  return post<JobInfo>('/jobs', req)
}

export function fetchJobs(): Promise<JobInfo[]> {
  return get<JobInfo[]>('/jobs')
}

/** Job detail, including the tail of its output. */
export function fetchJob(id: string): Promise<JobInfo> {
  return get<JobInfo>(`/jobs/${encodeURIComponent(id)}`)
}

export function stopJob(id: string): Promise<JobInfo> {
  return del<JobInfo>(`/jobs/${encodeURIComponent(id)}`)
}

/** Fully resolved config for a target (the API twin of `nemesis config --show`). */
export function fetchTargetConfig(target: string): Promise<{
  target_name: string; config_path: string; config: Record<string, unknown>
}> {
  return get(`/targets/${encodeURIComponent(target)}/config`)
}

// ── Scans ────────────────────────────────────────────────────

export function launchScan(req: ScanRequest): Promise<ScanResponse> {
  return post<ScanResponse>('/scans', req)
}

export function fetchActiveScans(): Promise<ActiveScan[]> {
  return get<ActiveScan[]>('/scans/active')
}

export function stopScan(target: string): Promise<ScanResponse> {
  return del<ScanResponse>(`/scans/${encodeURIComponent(target)}`)
}

// ── Coverage ─────────────────────────────────────────────────

export function fetchCoverage(targetName: string): Promise<CoverageSummary> {
  return get<CoverageSummary>(`/coverage/${encodeURIComponent(targetName)}`)
}
