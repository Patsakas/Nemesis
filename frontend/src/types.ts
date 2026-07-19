// Mirrors nemesis/api/models.py + route response schemas

// ── Findings ────────────────────────────────────────────────

export interface FindingSummary {
  id: string
  status: string
  cve_worthy: boolean
  cve_status: string
  cve_id: string | null
  library: string
  function: string
  file: string
  cwe: string
  cwe_name: string
  severity: string
  crash_type: string
  discovered_date: string
  run_id: string | null
  patch_induced: boolean | null
  cvss_estimate: number | null
}

export interface ReproductionInfo {
  direct: string
  bsdtar: string
  note: string
}

export interface CVEAssessmentInfo {
  is_known_cve: boolean
  cve_id: string
  cve_confidence: number
  rationale: string
  cvss_estimate: number
  similar_cves: string[]
  suggested_mitigation: string
}

export interface FindingDetail extends FindingSummary {
  line: number
  crash_location: string
  call_chain: string[]
  asan_error: string
  description: string
  root_cause: string
  trigger: string
  discovered_by: string
  patch_verdict: string
  crash_files: string[]
  notes: string
  reproduction: ReproductionInfo | null
  cve_assessment: CVEAssessmentInfo | null
}

// ── Runs ────────────────────────────────────────────────────

export interface RunSummary {
  run_id: string
  started_at: string
  finished_at: string | null
  targets_processed: number
  targets_successful: number
  total_crashes: number
  total_cves: number
  total_llm_cost_usd: number
}

export interface TargetResultSummary {
  func_name: string
  file_path: string
  status: string
  crashes: number
  has_patch: boolean
  has_analysis: boolean
  feedback_iterations: number
  duration_seconds: number
}

export interface RunDetail extends RunSummary {
  results: TargetResultSummary[]
}

/** Live progress of the run currently in flight (heartbeat from the pipeline). */
export interface CurrentRun {
  active: boolean
  run_id: string
  target: string
  stage: string
  stage_num: number | string
  func: string
  detail: string
  targets_done: number
  targets_total: number
  crashes: number
  status: string
  started_at: string
  updated_at: string
}

// ── Reports ─────────────────────────────────────────────────

export interface ReportMeta {
  id: string
  filename: string
  finding_id: string
  size_bytes: number
}

// ── Live AFL ────────────────────────────────────────────────

export interface LiveTargetStats {
  target_name: string
  is_running: boolean
  exec_per_sec: number
  total_paths: number
  unique_crashes: number
  unique_hangs: number
  map_density_pct: number
  stability_pct: number
  duration_seconds: number
  last_updated: string
}

export interface LiveSnapshot {
  timestamp: string
  active_count: number
  targets: LiveTargetStats[]
}

// ── Targets ─────────────────────────────────────────────────

export interface TargetInfo {
  name: string
  oss_fuzz_project: string
  source_root: string
  work_root: string
  has_pinned_funcs: boolean
  pinned_func_count: number
  strategy: string
}

// ── Functions + pinning ─────────────────────────────────────

/** Advanced per-pin knobs written into config/targets/<t>.yaml. */
export interface PinOptions {
  indirect_reach: boolean
  direct_internal: boolean
  force_no_blocker: boolean
  differential_oracle: boolean
  threaded_oracle: boolean
  auto_expose: boolean
  harness_hint: string
  differential_reference: string
  needed_headers: string[]
  output_invariants: string[]
}

export const PIN_DEFAULTS: PinOptions = {
  indirect_reach: false,
  direct_internal: false,
  force_no_blocker: false,
  differential_oracle: false,
  threaded_oracle: false,
  auto_expose: false,
  harness_hint: '',
  differential_reference: '',
  needed_headers: [],
  output_invariants: [],
}

export interface FunctionInfo {
  func_name: string
  file_path: string
  line: number
  oss_fuzz_coverage_pct: number   // -1 = unknown (not in OSS-Fuzz / no data)
  nemesis_coverage_pct: number    // -1 = NEMESIS has not measured it
  complexity: number
  pinned: boolean
  status: string
  pin_options: Partial<PinOptions>
}

export interface FunctionsResponse {
  target_name: string
  source: 'introspector' | 'local_scan' | 'none'
  run_id: string
  cached: boolean
  functions: FunctionInfo[]
  pinned_count: number
}

export interface PinEntry extends Partial<PinOptions> {
  func_name: string
  file_path?: string
  line?: number
}

export interface PinResponse {
  target_name: string
  pinned_count: number
  config_path: string
}

// ── Jobs (CLI operations run from the dashboard) ────────────

export type JobKind = 'onboard' | 'setup' | 'recon' | 'scout' | 'verify-crashes' | 'run'

export interface JobRequest {
  kind: JobKind
  target?: string
  source_root?: string
  project_name?: string
  oss_fuzz_project?: string
  url?: string
  skip_build?: boolean
  top?: number
  round_trip_only?: boolean
  scan?: boolean
  deep?: boolean
  max_targets?: number
  timeout_hours?: number      // fuzzing budget per target; 0 = mode preset
  strategy?: string
  auto_sanitizer?: boolean
}

export interface JobInfo {
  id: string
  kind: string
  argv: string[]
  status: 'running' | 'succeeded' | 'failed' | 'stopped'
  started_at: string
  finished_at: string | null
  exit_code: number | null
  output: string[]
}

// ── Scans ───────────────────────────────────────────────────

export interface ScanRequest {
  target: string
  max_targets?: number
  timeout_hours?: number      // fuzzing budget per target; 0 = mode preset
  scan?: boolean
  strategy?: string
  deep?: boolean
  deep_top?: number
  deep_hours?: number
}

export interface ScanResponse {
  status: string
  message: string
  target: string
}

export interface ActiveScan {
  target: string
  pid: number
  is_running: boolean
}

// ── Coverage ────────────────────────────────────────────────

export interface TargetCoverage {
  func_name: string
  source_coverage_pct: number
  function_coverage_pct: number
  harness_quality_score: number
  status: string
}

export interface CoverageSummary {
  target_name: string
  run_id: string
  targets: TargetCoverage[]
  avg_source_coverage: number
  targets_with_coverage: number
}
