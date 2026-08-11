/**
 * @module dry_run_simulator
 * Predictive dry-run simulation — plans engagement without fabricating CONFIRMED findings.
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { loadAptProfiles } from "./apt_tradecraft.ts"
import { loadPlaybook } from "./apt_playbook.ts"
import { assessRuntimeCapabilities } from "./runtime_capability.ts"
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

export interface SimulatedPhase {
  phase: string
  tools: string[]
  estimatedFindings: number
  risk: "low" | "medium" | "high"
}

export interface DryRunSimulation {
  target: string
  profile: string
  phases: SimulatedPhase[]
  runtime: Awaited<ReturnType<typeof assessRuntimeCapabilities>>
  estimatedWorkflowPct: number
  recommendations: string[]
}

export async function simulateEngagement(
  target: string,
  opts: { profileId?: string; graph?: AttackSurfaceGraph } = {},
): Promise<DryRunSimulation> {
  const profileId = opts.profileId ?? "scattered_spider"
  const profile = loadAptProfiles().find((p) => p.id === profileId) ?? loadAptProfiles()[0]!
  const playbook = loadPlaybook(profile.id)
  const runtime = await assessRuntimeCapabilities()

  const phases: SimulatedPhase[] = [
    { phase: "recon", tools: profile.tools.filter((t) => /recon|intel|enum/.test(t)), estimatedFindings: 5, risk: "low" },
    { phase: "scan", tools: profile.tools.filter((t) => /scan|nuclei|nmap|gobuster/.test(t)), estimatedFindings: 8, risk: "low" },
    { phase: "exploit", tools: profile.tools.filter((t) => /exploit|identity|web|ad/.test(t)), estimatedFindings: 3, risk: "medium" },
    { phase: "post_exploit", tools: profile.tools.filter((t) => /lateral|postex|exfil|pivot/.test(t)), estimatedFindings: 2, risk: "high" },
  ]

  const graphServices = opts.graph?.summary().services ?? 0
  let estimatedWorkflowPct = 35

  const tier1Modules = [
    "tier1_validation.ts", "campaign_loop.ts", "identity_playbooks.ts",
    "exploit_synthesis.ts", "c2_dwell_ops.ts", "tier1_orchestrator.ts",
  ]
  const srcDir = path.dirname(fileURLToPath(import.meta.url))
  const tier1Present = tier1Modules.filter((m) => {
    try { return fs.existsSync(path.join(srcDir, m)) } catch { return false }
  }).length

  if (playbook) estimatedWorkflowPct += 8
  if (playbook?.infra) estimatedWorkflowPct += 7
  if (runtime.fallbacksAvailable > 0) estimatedWorkflowPct += 5
  if (graphServices > 0) estimatedWorkflowPct += 8
  estimatedWorkflowPct += Math.round((tier1Present / tier1Modules.length) * 25)
  estimatedWorkflowPct = Math.min(88, estimatedWorkflowPct)

  const recommendations: string[] = []
  if (!runtime.probe.rawSockets) recommendations.push("Use connect scans — CAP_NET_RAW unavailable")
  if (runtime.fallbacksAvailable < 3) recommendations.push("Install missing toolchain for full coverage")
  recommendations.push("Enable OURMINE_TIER1=1 on authorized lab for autonomous pivot/C2")

  return {
    target,
    profile: profile.name,
    phases,
    runtime,
    estimatedWorkflowPct,
    recommendations,
  }
}

export default { simulateEngagement }
