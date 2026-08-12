/**
 * @module semantic_compression
 * Host ref indirection + delta-only engagement responses to shrink MCP payloads.
 */
import * as crypto from "node:crypto"

export interface HostEntry {
  ref: string
  host: string
  ports?: number[]
  role?: string
}

export interface HostRegistry {
  target: string
  entries: HostEntry[]
  updatedAt: string
}

export interface CompressedHosts {
  refs: string[]
  registry: HostRegistry
  savedBytes: number
}

function hostKey(host: string, ports?: number[]): string {
  const p = ports?.length ? `:${ports.sort((a, b) => a - b).join(",")}` : ""
  return `${host.toLowerCase()}${p}`
}

/** Build or extend a host registry; repeated full host strings become @hN refs. */
export function compressHostList(
  target: string,
  hosts: Array<string | { host: string; openPorts?: number[]; role?: string }>,
  existing?: HostRegistry,
): CompressedHosts {
  const registry: HostRegistry = existing
    ? { ...existing, entries: [...existing.entries] }
    : { target, entries: [], updatedAt: new Date().toISOString() }

  const index = new Map<string, string>()
  for (const e of registry.entries) index.set(hostKey(e.host, e.ports), e.ref)

  let rawBytes = 0
  const refs: string[] = []

  for (const item of hosts) {
    const host = typeof item === "string" ? item : item.host
    const ports = typeof item === "string" ? undefined : item.openPorts
    const role = typeof item === "string" ? undefined : item.role
    rawBytes += JSON.stringify({ host, ports, role }).length

    const key = hostKey(host, ports)
    let ref = index.get(key)
    if (!ref) {
      ref = `@h${registry.entries.length + 1}`
      registry.entries.push({ ref, host, ports, role })
      index.set(key, ref)
    }
    refs.push(ref)
  }

  registry.updatedAt = new Date().toISOString()
  const compressedBytes = JSON.stringify(refs).length
  return { refs, registry, savedBytes: Math.max(0, rawBytes - compressedBytes) }
}

/** Replace inline host arrays in engagement payloads with ref lists + registry artifact. */
export function compressEngagementPayload(payload: Record<string, unknown>): {
  compressed: Record<string, unknown>
  hostRegistry?: HostRegistry
  savedBytes: number
} {
  let savedBytes = 0
  const compressed = { ...payload }

  const otHosts = payload.otHosts as Array<{ host: string; openPorts?: number[] }> | undefined
  if (Array.isArray(otHosts) && otHosts.length > 3) {
    const { refs, registry, savedBytes: s } = compressHostList(String(payload.target ?? ""), otHosts)
    compressed.otHostRefs = refs
    delete compressed.otHosts
    savedBytes += s + JSON.stringify(otHosts).length - JSON.stringify(refs).length
    return { compressed, hostRegistry: registry, savedBytes }
  }

  const confirmed = payload.confirmed as Array<{ label?: string; detail?: string }> | undefined
  if (Array.isArray(confirmed)) {
    const hostLabels = confirmed
      .map((c) => c.detail?.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[\w.-]+\.(?:local|com|net|io)\b/i)?.[0])
      .filter(Boolean) as string[]
    if (hostLabels.length > 3) {
      const { refs, registry, savedBytes: s } = compressHostList(String(payload.target ?? ""), hostLabels)
      compressed.hostRefs = refs
      savedBytes += s
      return { compressed, hostRegistry: registry, savedBytes }
    }
  }

  return { compressed, savedBytes: 0 }
}

export interface EngagementSnapshot {
  cf: number
  cd: number
  bk: number
  ph?: string
  ok?: string
  nxp?: string
  confirmedIds?: string[]
  candidateIds?: string[]
}

function evidenceIds(items: unknown[] | undefined): string[] {
  if (!Array.isArray(items)) return []
  return items.map((item, i) => {
    const e = item as { kind?: string; label?: string }
    const raw = `${e.kind ?? "e"}|${e.label ?? i}`
    return crypto.createHash("sha256").update(raw).digest("base64url").slice(0, 8)
  })
}

export function snapshotFromPayload(payload: Record<string, unknown>): EngagementSnapshot {
  const pr = payload.phaseResult as Record<string, unknown> | undefined
  return {
    cf: Array.isArray(payload.confirmed) ? payload.confirmed.length : 0,
    cd: Array.isArray(payload.candidates) ? payload.candidates.length : 0,
    bk: Array.isArray(payload.blockers) ? payload.blockers.length : 0,
    ph: pr?.phase as string | undefined,
    ok: pr ? `${pr.stepsOk ?? pr.succeeded}/${pr.stepCount ?? "?"}` : undefined,
    nxp: payload.recommendedNextPhase as string | undefined,
    confirmedIds: evidenceIds(payload.confirmed as unknown[]),
    candidateIds: evidenceIds(payload.candidates as unknown[]),
  }
}

/** Delta-only compact body for ares_engagement_continue — omits unchanged counters/phases. */
export function buildEngagementDelta(
  prev: EngagementSnapshot,
  payload: Record<string, unknown>,
): Record<string, unknown> {
  const cur = snapshotFromPayload(payload)
  const delta: Record<string, unknown> = {
    d: true,
    ph: cur.ph,
  }

  if (cur.ok !== prev.ok) delta.ok = cur.ok
  if (cur.cf !== prev.cf) delta.cf = cur.cf
  if (cur.cd !== prev.cd) delta.cd = cur.cd
  if (cur.bk !== prev.bk) delta.bk = cur.bk
  if (cur.nxp && cur.nxp !== prev.nxp) delta.nxp = cur.nxp

  const newConfirmed = cur.confirmedIds?.filter((id) => !prev.confirmedIds?.includes(id)) ?? []
  const newCandidates = cur.candidateIds?.filter((id) => !prev.candidateIds?.includes(id)) ?? []
  if (newConfirmed.length) delta.nc = newConfirmed
  if (newCandidates.length) delta.nd = newCandidates

  if (typeof payload.summary === "string") {
    delta.s = payload.summary.slice(0, 72)
  }

  return delta
}

/** IAB chain stage → 2-char code (ib key in compact payloads). */
export const IAB_STAGE_CODES: Record<string, string> = {
  stealer_log: "sl",
  initial_access: "ia",
  raas_handoff: "rh",
  vpn_session: "vs",
  raas_deploy: "rd",
}

const IAB_STAGE_BY_CODE = Object.fromEntries(
  Object.entries(IAB_STAGE_CODES).map(([k, v]) => [v, k]),
)

export function compressIabStage(stage: string): string {
  return IAB_STAGE_CODES[stage] ?? stage.slice(0, 2)
}

export function expandIabStage(code: string): string {
  return IAB_STAGE_BY_CODE[code] ?? code
}

/** extortionOnly → { eo: true } */
export function compressExtortionFlag(enabled: boolean): { eo: true } | undefined {
  return enabled ? { eo: true } : undefined
}

/** device_code findings → dc key (count + optional high-severity suffix). */
export function compressDeviceCodeFindings(
  findings: Array<{ severity?: string }> | undefined,
): string | undefined {
  if (!findings?.length) return undefined
  const high = findings.filter((f) => f.severity === "critical" || f.severity === "high").length
  return high ? `${findings.length}h${high}` : String(findings.length)
}

/** intel staleness warning → st key (days or ! when missing). */
export function compressIntelStaleness(warning: string | null): string | undefined {
  if (!warning) return undefined
  const age = warning.match(/(\d+)d old/)
  if (age) return age[1]
  return warning.includes("no ransomwatch") ? "!" : "?"
}

/** Merge 2-char intel meta keys into a compact object for MCP slice bodies. */
export function compressIntelMeta(opts: {
  iabStage?: string
  extortionOnly?: boolean
  deviceCodeFindings?: Array<{ severity?: string }>
  staleWarning?: string | null
}): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {}
  if (opts.iabStage) out.ib = compressIabStage(opts.iabStage)
  if (opts.extortionOnly) out.eo = true
  const dc = compressDeviceCodeFindings(opts.deviceCodeFindings)
  if (dc) out.dc = dc
  const st = compressIntelStaleness(opts.staleWarning ?? null)
  if (st) out.st = st
  return out
}

/** Apply intel meta compression to engagement/intel payloads before artifact write. */
export function applyIntelCompression(payload: Record<string, unknown>): {
  compressed: Record<string, unknown>
  meta: Record<string, string | boolean>
} {
  const meta = compressIntelMeta({
    iabStage: payload.iabStage as string | undefined,
    extortionOnly: payload.extortionOnly === true
      || (payload.extortionMode as { enabled?: boolean } | undefined)?.enabled === true,
    deviceCodeFindings: payload.deviceCodeFindings as Array<{ severity?: string }> | undefined,
    staleWarning: typeof payload.staleWarning === "string" ? payload.staleWarning : undefined,
  })
  const compressed = { ...payload }
  if (Object.keys(meta).length) compressed.intelMeta = meta
  return { compressed, meta }
}

export default {
  compressHostList,
  compressEngagementPayload,
  snapshotFromPayload,
  buildEngagementDelta,
  compressIabStage,
  expandIabStage,
  compressExtortionFlag,
  compressDeviceCodeFindings,
  compressIntelStaleness,
  compressIntelMeta,
  applyIntelCompression,
}
