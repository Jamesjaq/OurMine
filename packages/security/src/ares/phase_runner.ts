/**
 * @module ares/phase_runner
 * Run an entire engagement phase in one server-side call (1 LLM turn, many modules).
 */
import * as security from "../index.ts"
import { runBridgedModule } from "../module_bridge.ts"
import { AttackSurfaceGraph } from "../attack_surface.ts"
import { CredentialGraph } from "../credential_graph.ts"
import type { AgentToolContext } from "../agent_tools.ts"
import { hostFromTarget } from "../agent_tools.ts"
import { runAresAutoChain } from "./_chain.ts"
import { runAresOrchestrator } from "./orchestrator.ts"
import type { AresPhase } from "../mcp_efficiency.ts"

export interface PhaseStepResult {
  module: string
  success: boolean
  summary: string
}

export interface AresPhaseResult {
  phase: AresPhase
  target: string
  steps: PhaseStepResult[]
  succeeded: number
  summary: string
}

export const PARALLEL_RECON_MODULES = [
  "ares_intel_feed",
  "ares_recon",
  "ares_bountyhunter",
  "ares_vuln_research",
]

function ctx(target: string, live: boolean): AgentToolContext {
  return {
    target,
    live,
    graph: new AttackSurfaceGraph(target),
    credGraph: CredentialGraph.load(),
  }
}

async function runBridge(
  c: AgentToolContext,
  module: string,
  params: Record<string, unknown> = {},
): Promise<PhaseStepResult> {
  const candidates = [module, module.startsWith("ares_") ? module : `ares_${module}`, module.replace(/^ares_/, "")]
  for (const name of [...new Set(candidates)]) {
    try {
      const r = await runBridgedModule(c, name, { target: c.target, ...params })
      if (!r) continue
      let summary = r.output.slice(0, 200)
      try {
        const parsed = JSON.parse(r.output) as { summary?: string }
        if (parsed.summary) summary = parsed.summary.slice(0, 200)
      } catch { /* compact or raw */ }
      return { module: name, success: r.success, summary }
    } catch (err) {
      return { module: name, success: false, summary: String((err as Error).message).slice(0, 150) }
    }
  }
  return { module, success: false, summary: "module not in bridge" }
}

async function runStaticRecon(target: string, live: boolean): Promise<PhaseStepResult[]> {
  const steps: PhaseStepResult[] = []
  try {
    const domain = target.includes(".") ? target : `${target}.local`
    const intel = await security.intel_feeds.enrichTarget(target, { live })
    steps.push({ module: "ares_intel_feed", success: true, summary: JSON.stringify(intel).slice(0, 120) })
    const recon = await security.ai_recon.runRecon({ domain, deep: false }, { live })
    steps.push({ module: "ares_recon", success: true, summary: JSON.stringify(recon).slice(0, 120) })
    const bh = await security.bountyhunter.recon({ target, endpoints: [] }, { live })
    steps.push({ module: "ares_bountyhunter", success: true, summary: JSON.stringify(bh).slice(0, 120) })
    const vuln = await security.vuln_research.checkCisaKev(target.split(".")[0] ?? target, live)
    steps.push({ module: "ares_vuln_research", success: true, summary: `kev=${vuln}` })
  } catch (err) {
    steps.push({ module: "recon_static", success: false, summary: String((err as Error).message).slice(0, 150) })
  }
  return steps
}

export async function runAresPhase(opts: {
  phase: AresPhase
  target: string
  live: boolean
  domain?: string
}): Promise<AresPhaseResult> {
  const target = opts.target
  const live = opts.live
  const c = ctx(target, live)
  const steps: PhaseStepResult[] = []

  switch (opts.phase) {
    case "recon":
      steps.push(...await runStaticRecon(target, live))
      break

    case "identity":
      steps.push(await runBridge(c, "cred_access_auto", { domain: opts.domain }))
      steps.push(await runBridge(c, "ares_kerberos_advanced", { domain: opts.domain }))
      steps.push(await runBridge(c, "ares_lateral_scale", { domain: opts.domain }))
      break

    case "exploit":
      steps.push(await runBridge(c, "ares_evasion_engine", {}))
      steps.push(await runBridge(c, "strix_web", { url: target.startsWith("http") ? target : `http://${target}` }))
      steps.push(await runBridge(c, "ares_network_exploit", {}))
      break

    case "post_ex": {
      const chain = await runAresAutoChain({
        target: hostFromTarget(target),
        domain: opts.domain,
        live,
        credGraph: c.credGraph,
        skipHarvest: false,
      })
      steps.push({
        module: "ares_auto_chain",
        success: chain.phases.some((p) => p.success && !p.skipped),
        summary: chain.summary,
      })
      steps.push(await runBridge(c, "ares_anti_forensics_advanced", {}))
      break
    }

    case "apt": {
      const orch = await runAresOrchestrator({
        live,
        target: hostFromTarget(target),
        domain: opts.domain,
        autoChain: true,
      })
      steps.push({
        module: "ares_orchestrator",
        success: orch.succeeded > 0,
        summary: orch.summary,
      })
      break
    }
  }

  c.credGraph?.save()
  const succeeded = steps.filter((s) => s.success).length
  return {
    phase: opts.phase,
    target,
    steps,
    succeeded,
    summary: `Phase ${opts.phase}: ${succeeded}/${steps.length} module(s) ok on ${target}`,
  }
}

export default { runAresPhase }
