/**
 * @module engagement_watch
 * Continuous engagement — scheduled snapshots, delta findings, retest.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { AttackSurfaceGraph } from "./attack_surface.ts"
import { buildProofPack, writeProofPack } from "./proof_pack.ts"

export interface WatchConfig {
  target: string
  intervalMinutes: number
  scope?: string[]
  live?: boolean
}

export interface WatchSnapshot {
  target: string
  timestamp: string
  graphSummary: ReturnType<AttackSurfaceGraph["summary"]>
  findingIds: string[]
  serviceKeys: string[]
  merkleRoot?: string
}

export interface DeltaReport {
  target: string
  since: string
  now: string
  newFindings: string[]
  removedFindings: string[]
  changedServices: string[]
}

export interface RetestResult {
  findingId: string
  previousState: string
  newState: string
  remediated: boolean
  output: string
}

const WATCH_DIR = path.join(process.cwd(), ".ourmine", "watch")

function watchPath(target: string): string {
  const safe = target.replace(/[^a-zA-Z0-9._-]/g, "_")
  return path.join(WATCH_DIR, safe)
}

function loadSnapshots(target: string): WatchSnapshot[] {
  const dir = watchPath(target)
  if (!fs.existsSync(dir)) return []
  return fs.readdirSync(dir)
    .filter((f) => f.startsWith("snap_") && f.endsWith(".json"))
    .map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")) as WatchSnapshot)
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
}

function graphPersistPath(target: string): string {
  return path.join(watchPath(target), "graph_latest.json")
}

function loadPersistedGraph(target: string): AttackSurfaceGraph | null {
  const file = graphPersistPath(target)
  if (!fs.existsSync(file)) return null
  try {
    return AttackSurfaceGraph.load(file)
  } catch {
    return null
  }
}

function persistGraph(target: string, graph: AttackSurfaceGraph): void {
  const dir = watchPath(target)
  fs.mkdirSync(dir, { recursive: true })
  graph.save(dir)
  fs.writeFileSync(graphPersistPath(target), JSON.stringify(graph.toJSON(), null, 2))
}

function extractServiceKeys(graph: AttackSurfaceGraph): string[] {
  const keys: string[] = []
  const data = graph.toJSON()
  for (const [host, asset] of Object.entries(data.assets ?? {})) {
    for (const [port, svc] of Object.entries((asset as { services?: Record<string, { product?: string; version?: string; state?: string }> }).services ?? {})) {
      const s = svc as { product?: string; version?: string; state?: string }
      keys.push(`${host}:${port}:${s.service ?? "unknown"}:${s.version ?? ""}:${s.state ?? "unknown"}`)
    }
  }
  return keys.sort()
}

function extractFindingIds(graph: AttackSurfaceGraph): string[] {
  const data = graph.toJSON()
  const ids: string[] = []
  for (const asset of Object.values(data.assets ?? {})) {
    for (const svc of Object.values((asset as { services?: Record<string, { vulns?: { id?: string }[] }> }).services ?? {})) {
      for (const v of svc.vulns ?? []) {
        if (v.id) ids.push(v.id)
      }
    }
  }
  return ids
}

export async function captureSnapshot(
  target: string,
  graph: AttackSurfaceGraph,
  opts: { live?: boolean } = {},
): Promise<WatchSnapshot> {
  const dir = watchPath(target)
  fs.mkdirSync(dir, { recursive: true })
  const pack = buildProofPack(graph)
  const snap: WatchSnapshot = {
    target,
    timestamp: new Date().toISOString(),
    graphSummary: graph.summary(),
    findingIds: extractFindingIds(graph),
    serviceKeys: extractServiceKeys(graph),
    merkleRoot: pack.merkleRoot,
  }
  const file = path.join(dir, `snap_${Date.now()}.json`)
  fs.writeFileSync(file, JSON.stringify(snap, null, 2))
  writeProofPack(pack, path.join(dir, "proof"))
  return snap
}

export function computeDelta(target: string): DeltaReport | null {
  const snaps = loadSnapshots(target)
  if (snaps.length < 2) return null
  const prev = snaps[snaps.length - 2]!
  const curr = snaps[snaps.length - 1]!
  const prevSet = new Set(prev.findingIds)
  const currSet = new Set(curr.findingIds)
  const prevServices = new Set(prev.serviceKeys ?? [])
  const currServices = new Set(curr.serviceKeys ?? [])
  const addedServices = (curr.serviceKeys ?? []).filter((k) => !prevServices.has(k))
  const removedServices = (prev.serviceKeys ?? []).filter((k) => !currServices.has(k))
  return {
    target,
    since: prev.timestamp,
    now: curr.timestamp,
    newFindings: curr.findingIds.filter((id) => !prevSet.has(id)),
    removedFindings: prev.findingIds.filter((id) => !currSet.has(id)),
    changedServices: [
      ...addedServices.map((k) => `+ ${k}`),
      ...removedServices.map((k) => `- ${k}`),
    ],
  }
}

export async function runWatchCycle(
  config: WatchConfig,
): Promise<{ snapshot: WatchSnapshot; delta: DeltaReport | null }> {
  const host = config.target.replace(/^https?:\/\//, "").split("/")[0]!
  const graph = loadPersistedGraph(config.target) ?? new AttackSurfaceGraph(config.target)
  graph.upsertAsset(host)

  if (config.live) {
    const { executeAgentTool } = await import("./agent_tools.ts")
    const { ToolBroker } = await import("./tool_broker.ts")
    const ctx = { target: config.target, graph, broker: new ToolBroker(), live: true }
    await executeAgentTool(ctx, "intel_enrich", {})
    await executeAgentTool(ctx, "nmap_scan", {})
    await executeAgentTool(ctx, "nuclei_scan", {})
    await executeAgentTool(ctx, "validate_findings", {})
  }

  const snapshot = await captureSnapshot(config.target, graph, { live: config.live })
  persistGraph(config.target, graph)
  const delta = computeDelta(config.target)
  return { snapshot, delta }
}

/** Start interval watch (returns stop function). */
export function startWatch(
  config: WatchConfig,
  onCycle?: (result: { snapshot: WatchSnapshot; delta: DeltaReport | null }) => void,
): () => void {
  const ms = Math.max(config.intervalMinutes, 5) * 60 * 1000
  const tick = async () => {
    try {
      const result = await runWatchCycle(config)
      onCycle?.(result)
    } catch { /* log locally */ }
  }
  void tick()
  const handle = setInterval(() => void tick(), ms)
  return () => clearInterval(handle)
}

/** Retest a finding — re-run validation, compare against watch history, mark REMEDIATED if gone. */
export async function retestFinding(
  target: string,
  findingId: string,
  opts: { live?: boolean } = {},
): Promise<RetestResult> {
  const graph = new AttackSurfaceGraph(target)
  const host = target.replace(/^https?:\/\//, "").split("/")[0]!
  graph.upsertAsset(host)

  const snaps = loadSnapshots(target)
  const wasTracked = snaps.some((s) => s.findingIds.includes(findingId))
  let previousState = wasTracked ? "SUSPECTED" : "UNKNOWN"

  if (opts.live) {
    const { executeAgentTool } = await import("./agent_tools.ts")
    const { ToolBroker } = await import("./tool_broker.ts")
    const ctx = { target, graph, broker: new ToolBroker(), live: true }
    await executeAgentTool(ctx, "nmap_scan", { host })
    await executeAgentTool(ctx, "nuclei_scan", { host })
    await executeAgentTool(ctx, "validate_findings", {})
  }

  const data = graph.toJSON()
  let found = false
  for (const asset of Object.values(data.assets ?? {})) {
    for (const svc of Object.values((asset as { services?: Record<string, { vulns?: { id?: string; state?: string }[] }> }).services ?? {})) {
      for (const v of svc.vulns ?? []) {
        if (v.id === findingId) {
          found = true
          previousState = v.state ?? previousState
        }
      }
    }
  }

  const remediated = wasTracked && !found && opts.live
  const newState = remediated ? "REMEDIATED" : found ? previousState : wasTracked ? "RETEST_PENDING" : "NOT_FOUND"

  const result: RetestResult = {
    findingId,
    previousState,
    newState,
    remediated,
    output: opts.live ? "live validation cycle complete" : "dry-run retest (pass --live for validation scan)",
  }

  const dir = watchPath(target)
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, `retest_${findingId.replace(/[^a-zA-Z0-9._-]/g, "_")}_${Date.now()}.json`), JSON.stringify(result, null, 2))

  return result
}

export default { captureSnapshot, computeDelta, runWatchCycle, startWatch, retestFinding }
