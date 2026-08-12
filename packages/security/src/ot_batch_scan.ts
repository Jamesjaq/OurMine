/**
 * @module ot_batch_scan
 * Multi-host OT subnet sweep — classify each host by open ICS ports / protocols.
 * Supports /16+ CIDR pagination via offset, resumeToken, and OURMINE_OT_SCAN_MAX.
 */
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as net from "node:net"
import * as path from "node:path"
import { ensureAresDir } from "./ares/_base.ts"
import { buildFlowProfile, type TargetPersona } from "./target_flow.ts"
import { executeScadaAction } from "./iot_scada.ts"
import { resolveLiveMode } from "./exec_options.ts"
import { mcpProgress } from "./mcp_progress.ts"
import { dedupeProbe, probeFingerprint } from "./probe_dedupe.ts"
import { scoreOtSubnets, type SubnetScore } from "./pivot_scorer.ts"
import type { CredentialGraph } from "./credential_graph.ts"
import type { PhaseStepResult } from "./ares/phase_runner.ts"

export const OT_PORTS: Array<{ port: number; protocol: string; udp?: boolean }> = [
  { port: 502, protocol: "modbus" },
  { port: 102, protocol: "iec61850" },
  { port: 20000, protocol: "dnp3" },
  { port: 1883, protocol: "mqtt" },
  { port: 47808, protocol: "bacnet", udp: true },
  { port: 5683, protocol: "coap", udp: true },
  { port: 34964, protocol: "profinet", udp: true },
]

export interface OtHostClassification {
  host: string
  persona: TargetPersona
  openPorts: number[]
  protocols: string[]
  otLikely: boolean
  probeSummary?: string
}

export interface ScanState {
  cidr: string
  offset: number
  maxHosts: number
  nextOffset: number
  totalHosts: number
  hasMore: boolean
  updatedAt: string
  rankedSubnets?: string[]
  subnetIndex?: number
  subnetScores?: SubnetScore[]
}

export interface OtBatchScanResult {
  cidr: string
  scanned: number
  otHosts: OtHostClassification[]
  summary: string
  dryRun: boolean
  offset?: number
  nextOffset?: number
  hasMore?: boolean
  totalHosts?: number
  resumeToken?: string
  nextResumeToken?: string
  subnetScores?: SubnetScore[]
  currentSubnet?: string
  subnetIndex?: number
}

export interface RankedOtScanResult {
  subnetScores: SubnetScore[]
  results: OtBatchScanResult[]
  otHosts: OtHostClassification[]
  summary: string
  dryRun: boolean
  resumeToken?: string
  nextResumeToken?: string
  hasMore: boolean
}

const SCAN_STATE_DIR = ensureAresDir("scan_state")

function defaultMaxHosts(): number {
  const env = process.env.OURMINE_OT_SCAN_MAX
  if (env) {
    const n = parseInt(env, 10)
    if (Number.isFinite(n) && n > 0) return n
  }
  return 64
}

export function buildResumeToken(cidr: string, offset: number, maxHosts: number, subnetIndex = 0): string {
  const raw = `${cidr}|${offset}|${maxHosts}|${subnetIndex}`
  return crypto.createHash("sha256").update(raw).digest("base64url").slice(0, 16)
}

export function buildRankedResumeToken(subnets: string[], subnetIndex: number, offset: number, maxHosts: number): string {
  const raw = `ranked|${subnets.join(",")}|${subnetIndex}|${offset}|${maxHosts}`
  return crypto.createHash("sha256").update(raw).digest("base64url").slice(0, 16)
}

export function saveScanState(token: string, state: ScanState): void {
  fs.writeFileSync(path.join(SCAN_STATE_DIR, `${token}.json`), JSON.stringify(state, null, 2))
}

export function loadScanState(token: string): ScanState | null {
  const safe = token.replace(/[^a-zA-Z0-9_-]/g, "")
  if (!safe) return null
  const fp = path.join(SCAN_STATE_DIR, `${safe}.json`)
  if (!fs.existsSync(fp)) return null
  try {
    return JSON.parse(fs.readFileSync(fp, "utf8")) as ScanState
  } catch {
    return null
  }
}

function ipToInt(ip: string): number {
  const p = ip.split(".").map(Number)
  return ((p[0]! << 24) | (p[1]! << 16) | (p[2]! << 8) | p[3]!) >>> 0
}

function intToIp(n: number): string {
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`
}

export function cidrHostRange(cidr: string): { start: number; end: number } | null {
  const m = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/)
  if (!m) return null
  const prefix = parseInt(m[2]!, 10)
  if (prefix >= 32) return { start: ipToInt(m[1]!), end: ipToInt(m[1]!) }
  const ipNum = ipToInt(m[1]!)
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
  const network = ipNum & mask
  const broadcast = network | (~mask >>> 0)
  if (prefix >= 31) return { start: network, end: broadcast }
  return { start: network + 1, end: broadcast - 1 }
}

export function expandCidrPaginated(
  cidr: string,
  opts: { maxHosts?: number; offset?: number } = {},
): { hosts: string[]; total: number; hasMore: boolean; nextOffset: number } {
  const maxHosts = opts.maxHosts ?? defaultMaxHosts()
  const offset = opts.offset ?? 0

  if (!cidr.includes("/")) {
    return { hosts: [cidr.replace(/\/.*$/, "")], total: 1, hasMore: false, nextOffset: 0 }
  }

  const range = cidrHostRange(cidr)
  if (!range) return { hosts: [cidr.replace(/\/.*$/, "")], total: 1, hasMore: false, nextOffset: 0 }

  const total = range.end - range.start + 1
  const hosts: string[] = []
  let idx = 0
  for (let ip = range.start; ip <= range.end && hosts.length < maxHosts; ip++) {
    if (idx++ < offset) continue
    hosts.push(intToIp(ip))
  }
  const nextOffset = offset + hosts.length
  return { hosts, total, hasMore: nextOffset < total, nextOffset }
}

/** Expand CIDR to host list (paginated slice). */
export function expandCidr(cidr: string, maxHosts = defaultMaxHosts(), offset = 0): string[] {
  return expandCidrPaginated(cidr, { maxHosts, offset }).hosts
}

function tcpOpen(host: string, port: number, timeoutMs = 800): Promise<boolean> {
  return new Promise((resolve) => {
    const s = new net.Socket()
    s.setTimeout(timeoutMs)
    s.once("connect", () => { s.destroy(); resolve(true) })
    s.once("timeout", () => { s.destroy(); resolve(false) })
    s.once("error", () => { s.destroy(); resolve(false) })
    s.connect(port, host)
  })
}

export async function classifyOtHost(host: string, live: boolean): Promise<OtHostClassification> {
  const fp = probeFingerprint("ot_classify", host)
  const { result } = await dedupeProbe(fp, async () => classifyOtHostUncached(host, live))
  return result
}

async function classifyOtHostUncached(host: string, live: boolean): Promise<OtHostClassification> {
  const openPorts: number[] = []
  const protocols: string[] = []

  if (!live) {
    const flow = buildFlowProfile(host)
    return { host, persona: flow.persona, openPorts, protocols, otLikely: flow.isOtLikely, probeSummary: "dry-run" }
  }

  await Promise.all(OT_PORTS.filter((p) => !p.udp).map(async (p) => {
    if (await tcpOpen(host, p.port)) {
      openPorts.push(p.port)
      if (!protocols.includes(p.protocol)) protocols.push(p.protocol)
    }
  }))

  const otLikely = openPorts.some((p) => [502, 102, 20000, 47808, 5683, 34964].includes(p))
  let probeSummary = ""
  if (otLikely && openPorts.includes(502)) {
    const r = await executeScadaAction({ host, protocol: "modbus", action: "read" }, { live: true })
    probeSummary = r.success ? "modbus-read-ok" : (r.error ?? "modbus-no-response")
  } else if (otLikely && openPorts.includes(47808)) {
    const r = await executeScadaAction({ host, protocol: "bacnet", action: "validate" }, { live: true })
    const d = r.data as { readPropertyOk?: boolean; whoisOk?: boolean } | undefined
    probeSummary = d?.readPropertyOk ? "bacnet-read-property-ok" : d?.whoisOk ? "bacnet-whois-ok" : (r.error ?? "bacnet-no-response")
  } else if (otLikely && openPorts.includes(20000)) {
    const r = await executeScadaAction({ host, protocol: "dnp3", action: "probe" }, { live: true })
    const d = r.data as { appReadOk?: boolean; linkAck?: boolean } | undefined
    probeSummary = d?.appReadOk ? "dnp3-app-read-ok" : d?.linkAck ? "dnp3-link-ok" : (r.error ?? "dnp3-no-response")
  }

  const flow = buildFlowProfile(host, undefined, protocols.join(" "))
  return {
    host,
    persona: otLikely ? (openPorts.includes(502) ? "ot_plc" : "ot_scada_plant") : flow.persona,
    openPorts,
    protocols,
    otLikely,
    probeSummary,
  }
}

export async function scanOtSubnet(
  cidr: string,
  opts: {
    live?: boolean
    maxHosts?: number
    offset?: number
    resumeToken?: string
    concurrency?: number
  } = {},
): Promise<OtBatchScanResult> {
  const live = opts.live ?? resolveLiveMode()
  let scanCidr = cidr
  let offset = opts.offset ?? 0
  let maxHosts = opts.maxHosts ?? defaultMaxHosts()

  if (opts.resumeToken) {
    const state = loadScanState(opts.resumeToken)
    if (state) {
      scanCidr = state.cidr
      offset = state.nextOffset
      maxHosts = state.maxHosts
      mcpProgress(`ot_batch_scan resume ${opts.resumeToken}: ${scanCidr} @ offset ${offset}`)
    } else {
      mcpProgress(`ot_batch_scan: unknown resumeToken ${opts.resumeToken} — using params`)
    }
  }

  const resumeToken = buildResumeToken(scanCidr, offset, maxHosts)
  const page = expandCidrPaginated(scanCidr, { maxHosts, offset })
  const hosts = page.hosts
  const otHosts: OtHostClassification[] = []
  const batch = opts.concurrency ?? 8

  mcpProgress(`ot_batch_scan ${scanCidr}: hosts ${offset}+${hosts.length}/${page.total}${!live ? " (dry-run)" : ""}`)

  for (let i = 0; i < hosts.length; i += batch) {
    const chunk = hosts.slice(i, i + batch)
    mcpProgress(`ot_batch_scan: chunk ${Math.floor(i / batch) + 1} (${chunk.length} hosts)`)
    const results = await Promise.all(chunk.map((h) => classifyOtHost(h, live)))
    for (const r of results) {
      if (r.otLikely || r.openPorts.length > 0) otHosts.push(r)
    }
  }

  const plcCount = otHosts.filter((h) => h.persona === "ot_plc").length
  const state: ScanState = {
    cidr: scanCidr,
    offset,
    maxHosts,
    nextOffset: page.nextOffset,
    totalHosts: page.total,
    hasMore: page.hasMore,
    updatedAt: new Date().toISOString(),
  }
  saveScanState(resumeToken, state)

  let nextResumeToken: string | undefined
  if (page.hasMore) {
    nextResumeToken = buildResumeToken(scanCidr, page.nextOffset, maxHosts)
    saveScanState(nextResumeToken, { ...state, offset: page.nextOffset })
  }

  const tokenHint = page.hasMore
    ? ` — resume with resumeToken=${nextResumeToken} or offset=${page.nextOffset}`
    : ""
  return {
    cidr: scanCidr,
    scanned: hosts.length,
    otHosts,
    summary: `Scanned ${hosts.length}/${page.total} host(s) @ offset ${offset}: ${otHosts.length} OT-relevant, ${plcCount} PLC-like${tokenHint}`,
    dryRun: !live,
    offset,
    nextOffset: page.hasMore ? page.nextOffset : undefined,
    hasMore: page.hasMore,
    totalHosts: page.total,
    resumeToken,
    nextResumeToken,
  }
}

/** Rank subnets via pivot_scorer and sweep highest-confidence first (paginated, resumable). */
export async function scanRankedOtSubnets(
  subnets: string[],
  opts: {
    live?: boolean
    maxHosts?: number
    maxSubnets?: number
    resumeToken?: string
    credGraph?: CredentialGraph
    reconSteps?: PhaseStepResult[]
    concurrency?: number
  } = {},
): Promise<RankedOtScanResult> {
  const live = opts.live ?? resolveLiveMode()
  const maxHosts = opts.maxHosts ?? defaultMaxHosts()
  const maxSubnets = opts.maxSubnets ?? 4
  let subnetIndex = 0
  let offset = 0
  let rankedSubnets = subnets

  if (opts.resumeToken) {
    const state = loadScanState(opts.resumeToken)
    if (state?.rankedSubnets?.length) {
      rankedSubnets = state.rankedSubnets
      subnetIndex = state.subnetIndex ?? 0
      offset = state.nextOffset ?? state.offset
      mcpProgress(`scanRankedOtSubnets resume @ subnet ${subnetIndex} offset ${offset}`)
    }
  }

  const subnetScores = scoreOtSubnets(rankedSubnets, opts.credGraph, opts.reconSteps)
  const ordered = subnetScores.map((s) => s.subnet)
  const results: OtBatchScanResult[] = []
  const otHosts: OtHostClassification[] = []
  let scannedSubnets = 0

  while (subnetIndex < ordered.length && scannedSubnets < maxSubnets) {
    const subnet = ordered[subnetIndex]!
    const score = subnetScores.find((s) => s.subnet === subnet)
    mcpProgress(`scanRankedOtSubnets: ${subnet} (conf=${score?.confidence ?? "?"})`)
    const batch = await scanOtSubnet(subnet, { live, maxHosts, offset, concurrency: opts.concurrency })
    batch.subnetScores = subnetScores
    batch.currentSubnet = subnet
    batch.subnetIndex = subnetIndex
    results.push(batch)
    otHosts.push(...batch.otHosts)

    if (batch.hasMore) {
      offset = batch.nextOffset ?? offset + batch.scanned
      const token = buildRankedResumeToken(ordered, subnetIndex, offset, maxHosts)
      saveScanState(token, {
        cidr: subnet,
        offset,
        maxHosts,
        nextOffset: offset,
        totalHosts: batch.totalHosts ?? 0,
        hasMore: true,
        updatedAt: new Date().toISOString(),
        rankedSubnets: ordered,
        subnetIndex,
        subnetScores,
      })
      const top = subnetScores[0]
      return {
        subnetScores,
        results,
        otHosts,
        dryRun: !live,
        resumeToken: token,
        nextResumeToken: token,
        hasMore: true,
        summary: `Ranked sweep: ${subnet} chunk (conf ${score?.confidence}) — ${otHosts.length} OT host(s); resume ${token}${top ? `; next pivot ${top.subnet} (${top.confidence})` : ""}`,
      }
    }

    subnetIndex++
    offset = 0
    scannedSubnets++
  }

  const token = buildRankedResumeToken(ordered, subnetIndex, 0, maxHosts)
  saveScanState(token, {
    cidr: ordered[ordered.length - 1] ?? "done",
    offset: 0,
    maxHosts,
    nextOffset: 0,
    totalHosts: 0,
    hasMore: false,
    updatedAt: new Date().toISOString(),
    rankedSubnets: ordered,
    subnetIndex,
    subnetScores,
  })

  const top = subnetScores[0]
  return {
    subnetScores,
    results,
    otHosts,
    dryRun: !live,
    resumeToken: token,
    hasMore: false,
    summary: `Ranked sweep complete: ${ordered.length} subnet(s), ${otHosts.filter((h) => h.otLikely).length} OT host(s)${top ? `; top pivot ${top.subnet} (${top.confidence})` : ""}`,
  }
}

export default {
  expandCidr,
  expandCidrPaginated,
  cidrHostRange,
  classifyOtHost,
  scanOtSubnet,
  scanRankedOtSubnets,
  buildResumeToken,
  buildRankedResumeToken,
  saveScanState,
  loadScanState,
  OT_PORTS,
}
