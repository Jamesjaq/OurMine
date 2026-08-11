/**
 * @module apt_playbook
 * APT playbook engine — precondition → action → fallback DAG from profile tradecraft.
 */
import type { Phase } from "./pentestgpt_agent.ts"
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { loadAptProfiles, type AptProfile } from "./apt_tradecraft.ts"
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

const INFRA_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../data/intel/apt_playbook_infra.json")

export interface PlaybookInfra {
  profileId: string
  vertical: string
  dwellHoursMin: number
  dwellHoursMax: number
  infra: string[]
  timing: { beaconJitterSec: number[]; activeHoursUtc: number[] }
  fallbackChain: string[]
}

export type PlaybookNodeStatus = "pending" | "ready" | "running" | "done" | "failed" | "skipped"

export interface PlaybookPrecondition {
  type: "phase" | "finding_severity" | "port_open" | "cred_available" | "tool_available"
  value: string
}

export interface PlaybookNode {
  id: string
  tool: string
  phase: Phase
  preconditions: PlaybookPrecondition[]
  fallbacks: string[]
  technique?: string
  params?: Record<string, unknown>
  status: PlaybookNodeStatus
  result?: string
}

export interface PlaybookGraph {
  profileId: string
  profileName: string
  vertical?: string
  infra?: PlaybookInfra
  nodes: PlaybookNode[]
  edges: Array<{ from: string; to: string; on: "success" | "failure" }>
}

export function loadPlaybookInfra(profileId: string): PlaybookInfra | null {
  try {
    const all = JSON.parse(fs.readFileSync(INFRA_PATH, "utf8")) as PlaybookInfra[]
    return all.find((i) => i.profileId === profileId) ?? null
  } catch {
    return null
  }
}

function phaseOrder(p: Phase): number {
  const o: Record<Phase, number> = { recon: 0, scan: 1, exploit: 2, post_exploit: 3, reporting: 4, cleanup: 5 }
  return o[p] ?? 99
}

function toolPhase(tool: string): Phase {
  const recon = ["recon", "live_recon", "intel_enrich", "bountyhunter", "ai_surface_scan"]
  const scan = ["nmap_scan", "nuclei_scan", "gobuster_dir", "ffuf_scan", "validate_findings"]
  const exploit = ["web_exploit", "identity_attack", "ad_exploit", "cred_spray", "evilginx_lab", "idp_audit"]
  const post = ["lateral_move", "postex_harvest", "privesc_check", "exfil", "pivot_replay", "autonomous_pivot"]
  if (recon.includes(tool)) return "recon"
  if (scan.includes(tool)) return "scan"
  if (exploit.includes(tool)) return "exploit"
  if (post.includes(tool)) return "post_exploit"
  return "scan"
}

export function buildPlaybookFromProfile(profile: AptProfile): PlaybookGraph {
  const infra = loadPlaybookInfra(profile.id)
  const infraFallbacks = infra?.fallbackChain ?? []
  const nodes: PlaybookNode[] = profile.tools.map((tool, i) => ({
    id: `${profile.id}_${tool}_${i}`,
    tool,
    phase: toolPhase(tool),
    preconditions: i === 0
      ? [{ type: "phase", value: "recon" }]
      : [{ type: "phase", value: toolPhase(tool) }],
    fallbacks: [
      ...profile.tools.filter((t, j) => j > i && t !== tool).slice(0, 2),
      ...infraFallbacks.filter((t) => t !== tool),
    ].slice(0, 4),
    technique: profile.techniques[i % profile.techniques.length],
    status: "pending",
  }))

  const edges: PlaybookGraph["edges"] = []
  for (let i = 0; i < nodes.length - 1; i++) {
    edges.push({ from: nodes[i]!.id, to: nodes[i + 1]!.id, on: "success" })
    if (nodes[i]!.fallbacks[0]) {
      const fb = nodes.find((n) => n.tool === nodes[i]!.fallbacks[0])
      if (fb) edges.push({ from: nodes[i]!.id, to: fb.id, on: "failure" })
    }
  }

  return { profileId: profile.id, profileName: profile.name, vertical: infra?.vertical, infra: infra ?? undefined, nodes, edges }
}

export function evaluatePreconditions(
  node: PlaybookNode,
  ctx: { currentPhase: Phase; graph: AttackSurfaceGraph; credCount: number; availableTools: Set<string> },
): boolean {
  for (const pre of node.preconditions) {
    switch (pre.type) {
      case "phase":
        if (phaseOrder(ctx.currentPhase) < phaseOrder(pre.value as Phase)) return false
        break
      case "finding_severity": {
        const paths = ctx.graph.analyzeAttackPaths()
        const sev = pre.value
        if (!paths.some((p) => p.severity === sev || (sev === "high" && p.severity === "critical"))) return false
        break
      }
      case "cred_available":
        if (ctx.credCount < parseInt(pre.value, 10) || 0) return false
        break
      case "tool_available":
        if (!ctx.availableTools.has(pre.value)) return false
        break
      case "port_open": {
        const assets = (ctx.graph.toJSON() as { assets?: Record<string, { services?: Record<string, { port: number }> }> }).assets ?? {}
        const ports = Object.values(assets).flatMap((a) => Object.values(a.services ?? {}).map((s) => s.port))
        if (!ports.includes(parseInt(pre.value, 10))) return false
        break
      }
    }
  }
  return true
}

export function nextPlaybookNode(
  playbook: PlaybookGraph,
  ctx: { currentPhase: Phase; graph: AttackSurfaceGraph; credCount: number; availableTools: Set<string> },
): PlaybookNode | null {
  const sorted = [...playbook.nodes].sort((a, b) => phaseOrder(a.phase) - phaseOrder(b.phase))
  for (const node of sorted) {
    if (node.status !== "pending" && node.status !== "ready") continue
    if (evaluatePreconditions(node, ctx)) {
      node.status = "ready"
      return node
    }
  }
  return null
}

export function markNodeDone(playbook: PlaybookGraph, nodeId: string, success: boolean, result?: string): PlaybookNode | null {
  const node = playbook.nodes.find((n) => n.id === nodeId)
  if (!node) return null
  node.status = success ? "done" : "failed"
  node.result = result
  if (!success && node.fallbacks.length) {
    const fb = playbook.nodes.find((n) => n.tool === node.fallbacks[0] && n.status === "pending")
    if (fb) {
      fb.status = "ready"
      return fb
    }
  }
  return null
}

export function loadPlaybook(profileId: string): PlaybookGraph | null {
  const profile = loadAptProfiles().find((p) => p.id === profileId)
  if (!profile) return null
  return buildPlaybookFromProfile(profile)
}

export function listPlaybooks(): Array<{ id: string; name: string; nodeCount: number }> {
  return loadAptProfiles().map((p) => ({
    id: p.id,
    name: p.name,
    nodeCount: p.tools.length,
  }))
}

export default { buildPlaybookFromProfile, evaluatePreconditions, nextPlaybookNode, loadPlaybook, listPlaybooks, loadPlaybookInfra }
