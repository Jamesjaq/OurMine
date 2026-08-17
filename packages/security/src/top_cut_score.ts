/**
 * @module top_cut_score
 * Readiness scoring vs enterprise BAS / autonomous offensive platforms (Pentera, NodeZero, XBOW).
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

export interface TopCutDimension {
  id: string
  name: string
  score: number
  weight: number
  notes: string[]
}

export interface TopCutReport {
  overall: number
  tier: "top_cut" | "workbench" | "developing"
  dimensions: TopCutDimension[]
  blockers: string[]
  meetsTopCut: boolean
  assessedAt: string
}

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)))

function clamp(n: number): number {
  return Math.max(0, Math.min(10, Math.round(n * 10) / 10))
}

async function countSimulateInSrc(): Promise<number> {
  let count = 0
  for (const f of fs.readdirSync(SRC).filter((x) => x.endsWith(".ts") && x !== "top_cut_score.ts")) {
    const c = fs.readFileSync(path.join(SRC, f), "utf8")
    if (/function simulate[A-Z]|generateSimulated|buildSimulated|\[SIMULATED\]/.test(c)) count++
  }
  return count
}

export async function assessTopCut(): Promise<TopCutReport> {
  const blockers: string[] = []
  const dimensions: TopCutDimension[] = []

  const { executeAgentTool } = await import("./agent_tools.ts")
  const { ToolBroker } = await import("./tool_broker.ts")
  const { AttackSurfaceGraph } = await import("./attack_surface.ts")
  const graph = new AttackSurfaceGraph("topcut.local")
  const ctx = { target: "topcut.local", graph, broker: new ToolBroker(), live: false }

  const { bridgedToolNames } = await import("./module_bridge.ts")
  const campaignTools = [
    "intel_enrich", "recon", "ai_recon", "web_exploit", "identity_attack", "ad_exploit",
    "postex_harvest", "lateral_move", "exfil", "nmap_scan", "edge_audit", "cred_spray",
    "ransomware_assess", "esxi_audit", "impact_assess", "impact_engine", "lockfile_scan",
    "cicd_audit", "supply_chain_audit", "dev_target", "cloud_token", "container_audit",
    "ai_surface_scan", "ai_agent_audit", "ai_manipulation_test", "atlas_ml_audit", "caldera_ttp",
    "pivot_replay", "stix_ingest",
    ...bridgedToolNames(),
  ]
  const dispatchResults = await Promise.all(campaignTools.map(async (t) => {
    try {
      const r = await executeAgentTool(ctx, t, {})
      return { tool: t, ok: !r.error?.includes("unknown tool"), error: r.error }
    } catch (error) {
      const message = String(error)
      return { tool: t, ok: !message.includes("unknown tool"), error: message }
    }
  }))
  const wiredTools = dispatchResults.filter((d) => d.ok).length
  const toolScore = clamp((wiredTools / campaignTools.length) * 10)
  if (wiredTools < campaignTools.length) {
    blockers.push(`Campaign tools unwired: ${dispatchResults.filter((d) => !d.ok).map((d) => d.tool).join(", ")}`)
  }
  dimensions.push({
    id: "tool_wiring",
    name: "Autonomous tool dispatch",
    score: toolScore,
    weight: 2,
    notes: [`${wiredTools}/${campaignTools.length} campaign tools dispatchable`],
  })

  const simulateFiles = await countSimulateInSrc()
  const realOnlyScore = clamp(10 - simulateFiles * 0.5)
  if (simulateFiles > 3) blockers.push(`${simulateFiles} modules still contain simulate/fabricate patterns`)
  dimensions.push({
    id: "real_only",
    name: "Real-only execution (no fabricate)",
    score: realOnlyScore,
    weight: 2,
    notes: [`${simulateFiles} files with simulate patterns`],
  })

  const closedLoopChecks = [
    () => import("./validation_engine.ts").then((m) => !!m.ValidationEngine),
    () => import("./proof_pack.ts").then((m) => !!m.buildProofPack),
    () => import("./opsec_gate.ts").then((m) => !!m.gateExecution),
    () => import("./pivot_replay.ts").then((m) => !!m.replayCredentialGraphWithBloodHound),
    () => import("./engagement_watch.ts").then((m) => !!m.startWatch),
    () => import("./cdp_client.ts").then((m) => !!m.CdpClient),
    () => import("./stix_ingest.ts").then((m) => !!m.ingestTaxiiFeed),
    () => import("./pdf_report.ts").then((m) => !!m.writePdfReport),
  ]
  const closedOk = (await Promise.all(closedLoopChecks.map((fn) => fn().then(() => true).catch(() => false)))).filter(Boolean).length
  const closedScore = clamp((closedOk / closedLoopChecks.length) * 10)
  dimensions.push({
    id: "closed_loop",
    name: "Evidence closed loop",
    score: closedScore,
    weight: 2,
    notes: [`${closedOk}/${closedLoopChecks.length} core modules present`],
  })

  const { loadAptProfiles } = await import("./apt_tradecraft.ts")
  const profiles = loadAptProfiles()
  const intelScore = clamp(Math.min(10, profiles.length / 3))
  dimensions.push({
    id: "apt_tradecraft",
    name: "APT profile + tradecraft depth",
    score: intelScore,
    weight: 1.5,
    notes: [`${profiles.length} APT profiles loaded`],
  })

  const { isToolAvailable } = await import("./tool_detection.ts")
  const liveTools = ["nmap", "curl", "nuclei", "netexec", "impacket-GetUserSPNs"].filter((t) => isToolAvailable(t))
  const liveScore = clamp((liveTools.length / 5) * 10)
  dimensions.push({
    id: "live_toolchain",
    name: "Kali live toolchain",
    score: liveScore,
    weight: 1.5,
    notes: [`${liveTools.length}/5 core tools on PATH`],
  })

  const mcpSrc = fs.readFileSync(path.join(SRC, "mcp_server.ts"), "utf8")
  const mcpTools = (mcpSrc.match(/name: "ares_/g) ?? []).length
  const mcpScore = clamp(Math.min(10, mcpTools / 4))
  dimensions.push({
    id: "mcp_surface",
    name: "LLM MCP attack surface",
    score: mcpScore,
    weight: 1,
    notes: [`${mcpTools} ares_* MCP tools`],
  })

  const totalWeight = dimensions.reduce((s, d) => s + d.weight, 0)
  const overall = clamp(dimensions.reduce((s, d) => s + d.score * d.weight, 0) / totalWeight)
  const meetsTopCut = overall >= 8.0 && blockers.length === 0
  const tier = meetsTopCut ? "top_cut" : overall >= 6.5 ? "workbench" : "developing"

  return {
    overall,
    tier,
    dimensions,
    blockers,
    meetsTopCut,
    assessedAt: new Date().toISOString(),
  }
}

export function formatTopCutReport(report: TopCutReport): string {
  const lines = [
    `# OurMine Top-Cut Assessment`,
    `Overall: **${report.overall}/10** (${report.tier}) — meets top cut: ${report.meetsTopCut}`,
    "",
    "## Dimensions",
    ...report.dimensions.map((d) => `- ${d.name}: ${d.score}/10 (w=${d.weight}) — ${d.notes.join("; ")}`),
  ]
  if (report.blockers.length) {
    lines.push("", "## Blockers", ...report.blockers.map((b) => `- ${b}`))
  }
  return lines.join("\n")
}

export default { assessTopCut, formatTopCutReport }
