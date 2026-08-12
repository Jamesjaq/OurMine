/**
 * @module ares/phase_runner
 * Run an entire engagement phase in one server-side call (1 LLM turn, many modules).
 * Routes modules by target persona (IT / OT / telecom / ransom).
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
import {
  buildFlowProfile,
  inferFlowObjective,
  modulesForPhase,
  skipAdAutoChain,
  type FlowObjective,
} from "../target_flow.ts"
import { applyPolicyToModules, evaluateEngagementPolicy } from "../engagement_policy.ts"
import { mcpProgress, mcpProgressStep } from "../mcp_progress.ts"
import { scanOtSubnet } from "../ot_batch_scan.ts"

export interface PhaseStepResult {
  module: string
  success: boolean
  summary: string
  elapsedMs?: number
  otHosts?: import("../ot_batch_scan.ts").OtHostClassification[]
}

export interface AresPhaseResult {
  phase: AresPhase
  target: string
  objective: FlowObjective
  persona: string
  steps: PhaseStepResult[]
  succeeded: number
  summary: string
  recommendedNextPhase?: AresPhase
  progressLog: string[]
}

const PHASE_ORDER: AresPhase[] = ["recon", "identity", "exploit", "post_ex", "apt"]

/** Independent recon probes safe for speculative Promise.all (no ordering dependency). */
export const PARALLEL_RECON_MODULES = new Set([
  "ares_intel_feed", "intel_feed",
  "ares_recon", "recon",
  "ares_bountyhunter", "bountyhunter",
  "ares_vuln_research", "vuln_research",
  "ot_scan", "telecom_audit", "net_device_audit", "edge_audit",
  "usb_audit", "wifi_audit", "ble_audit", "proximity_audit",
  "cloud_enum", "ares_cloud_native",
])

function isParallelReconModule(module: string): boolean {
  const key = module.replace(/^ares_/, "")
  return PARALLEL_RECON_MODULES.has(module) || PARALLEL_RECON_MODULES.has(key)
}

function partitionParallelModules(modules: string[], phase: AresPhase): {
  parallel: string[]
  sequential: string[]
} {
  if (phase !== "recon") {
    return { parallel: [], sequential: modules }
  }
  const parallel: string[] = []
  const sequential: string[] = []
  for (const mod of modules) {
    if (isParallelReconModule(mod)) parallel.push(mod)
    else sequential.push(mod)
  }
  return { parallel, sequential }
}

async function runModulesBatch(
  c: AgentToolContext,
  modules: string[],
  target: string,
  live: boolean,
  phase: string,
  progressLog: string[],
  domain?: string,
  objective?: string,
  parallel = false,
): Promise<PhaseStepResult[]> {
  if (!parallel || modules.length <= 1) {
    const out: PhaseStepResult[] = []
    for (const mod of modules) {
      out.push(await runModuleByName(c, mod, target, live, phase, progressLog, domain, objective))
    }
    return out
  }

  mcpProgress(`phase ${phase}: speculative parallel batch (${modules.length} probes)`)
  progressLog.push(`parallel batch: ${modules.join(", ")}`)
  const results = await Promise.all(
    modules.map((mod) => runModuleByName(c, mod, target, live, phase, progressLog, domain, objective)),
  )
  return results
}

function logPhaseProgress(phase: string, module: string, status: string, elapsedMs?: number): void {
  const detail = elapsedMs != null ? `${elapsedMs}ms` : undefined
  mcpProgressStep(phase, module, status, detail)
}

function ctx(
  target: string,
  live: boolean,
  graph?: AttackSurfaceGraph,
  credGraph?: CredentialGraph,
): AgentToolContext {
  return {
    target,
    live,
    graph: graph ?? new AttackSurfaceGraph(target),
    credGraph: credGraph ?? CredentialGraph.load(),
  }
}

async function runBridge(
  c: AgentToolContext,
  module: string,
  params: Record<string, unknown>,
  phase: string,
  progressLog: string[],
): Promise<PhaseStepResult> {
  const candidates = [module, module.startsWith("ares_") ? module : `ares_${module}`, module.replace(/^ares_/, "")]
  const started = Date.now()
  for (const name of [...new Set(candidates)]) {
    try {
      logPhaseProgress(phase, name, "running")
      const r = await runBridgedModule(c, name, { target: c.target, ...params })
      if (!r) continue
      let summary = r.output.slice(0, 200)
      let otHosts: import("../ot_batch_scan.ts").OtHostClassification[] | undefined
      try {
        const parsed = JSON.parse(r.output) as { summary?: string; otHosts?: import("../ot_batch_scan.ts").OtHostClassification[] }
        if (parsed.summary) summary = String(parsed.summary).slice(0, 200)
        if (Array.isArray(parsed.otHosts)) otHosts = parsed.otHosts
      } catch { /* raw */ }
      const elapsedMs = Date.now() - started
      progressLog.push(`${name}: ${r.success ? "ok" : "fail"} — ${summary.slice(0, 80)}`)
      logPhaseProgress(phase, name, r.success ? "ok" : "fail", elapsedMs)
      return { module: name, success: r.success, summary, elapsedMs, otHosts }
    } catch (err) {
      const elapsedMs = Date.now() - started
      const msg = String((err as Error).message).slice(0, 150)
      progressLog.push(`${name}: error — ${msg}`)
      logPhaseProgress(phase, name, "error", elapsedMs)
      return { module: name, success: false, summary: msg, elapsedMs }
    }
  }
  progressLog.push(`${module}: not in bridge`)
  logPhaseProgress(phase, module, "missing")
  return { module, success: false, summary: "module not in bridge" }
}

async function runStaticModule(
  module: string,
  phase: string,
  progressLog: string[],
  fn: () => Promise<unknown>,
): Promise<PhaseStepResult> {
  const started = Date.now()
  logPhaseProgress(phase, module, "running")
  try {
    const result = await fn()
    const summary = JSON.stringify(result).slice(0, 120)
    const elapsedMs = Date.now() - started
    progressLog.push(`${module}: ok — ${summary.slice(0, 80)}`)
    logPhaseProgress(phase, module, "ok", elapsedMs)
    return { module, success: true, summary, elapsedMs }
  } catch (err) {
    const elapsedMs = Date.now() - started
    const msg = String((err as Error).message).slice(0, 150)
    progressLog.push(`${module}: fail — ${msg}`)
    logPhaseProgress(phase, module, "fail", elapsedMs)
    return { module, success: false, summary: msg, elapsedMs }
  }
}

async function runModuleByName(
  c: AgentToolContext,
  module: string,
  target: string,
  live: boolean,
  phase: string,
  progressLog: string[],
  domain?: string,
  objective?: string,
): Promise<PhaseStepResult> {
  const bridgeFirst = [
    "ot_scan", "iot_scada", "ot_batch_scan", "hybrid_pivot", "ics_impact_proof", "telecom_audit", "net_device_audit", "edge_audit",
    "usb_audit", "wifi_audit", "ble_audit", "proximity_audit",
    "esxi_audit", "impact_assess", "raas_campaign", "ares_auto_chain",
    "ares_kerberos_advanced", "ares_lateral_scale", "ares_evasion_engine",
    "ares_network_exploit", "ares_ad_exploit", "ares_anti_forensics_advanced",
    "ares_firmware_implant", "ares_airgap_bridge", "ares_hardware_implant",
    "ares_ss7_exploit", "ares_orchestrator", "strix_web", "cred_access_auto",
    "ares_exfil", "ares_cloud_native", "cloud_enum", "app_security_engine",
    "campaign_loop", "supply_chain_exec", "multi_cloud_asm", "exploit_adapter",
    "identity_chain", "segment_tunnel", "autonomous_pivot", "profinet_l2", "ot_segment_infer",
    "supply_chain_audit", "lockfile_scan", "cicd_audit", "ai_agent_audit",
  ]
  const key = module.replace(/^ares_/, "")
  if (bridgeFirst.includes(key) || bridgeFirst.includes(module)) {
    return runBridge(c, module, { domain, objective }, phase, progressLog)
  }

  switch (module) {
    case "ares_intel_feed":
      return runStaticModule(module, phase, progressLog, () => security.intel_feeds.enrichTarget(target, { live }))
    case "ares_recon": {
      const dom = target.includes(".") ? target : `${target}.local`
      return runStaticModule(module, phase, progressLog, () => security.ai_recon.runRecon({ domain: dom, deep: false }, { live }))
    }
    case "ares_bountyhunter":
      return runStaticModule(module, phase, progressLog, () => security.bountyhunter.recon({ target, endpoints: [] }, { live }))
    case "ares_vuln_research":
      return runStaticModule(module, phase, progressLog, async () => {
        const kev = await security.vuln_research.checkCisaKev(target.split(".")[0] ?? target, live)
        return { kev }
      })
    default:
      return runBridge(c, module, { domain, objective }, phase, progressLog)
  }
}

function recommendNextPhase(current: AresPhase, steps: PhaseStepResult[]): AresPhase | undefined {
  const idx = PHASE_ORDER.indexOf(current)
  if (idx < 0 || idx >= PHASE_ORDER.length - 1) return undefined
  if (!steps.some((s) => s.success)) return current
  return PHASE_ORDER[idx + 1]
}

export async function runAresPhase(opts: {
  phase: AresPhase
  target: string
  live: boolean
  domain?: string
  objective?: string
  hint?: string
  aptHint?: string
  graph?: AttackSurfaceGraph
  credGraph?: CredentialGraph
}): Promise<AresPhaseResult> {
  const target = opts.target
  const live = opts.live
  const flow = buildFlowProfile(target, undefined, opts.hint ?? opts.objective ?? target)
  const objective = inferFlowObjective(flow, opts.hint ?? opts.objective)
  const c = ctx(target, live, opts.graph, opts.credGraph)
  const steps: PhaseStepResult[] = []
  const progressLog: string[] = []
  const moduleList = applyPolicyToModules(opts.phase, flow, objective, c.credGraph, live, opts.aptHint)

  // Cloud IMDS/IAM: prioritize cloud_native early in recon/exploit for cloud personas
  const cloudPersonas = new Set(["cloud_saas", "container_k8s", "esxi_hypervisor"])
  if (
    (opts.phase === "recon" || opts.phase === "exploit")
    && (cloudPersonas.has(flow.persona) || objective === "cloud_ransom")
    && !moduleList.includes("ares_cloud_native")
  ) {
    moduleList.unshift("cloud_enum", "ares_cloud_native")
  }

  logPhaseProgress(opts.phase, "*", `start [${objective}/${flow.persona}]`)
  progressLog.push(`phase ${opts.phase} started — objective=${objective} persona=${flow.persona}`)

  if (opts.phase === "post_ex" && skipAdAutoChain(flow, objective)) {
    for (const mod of moduleList) {
      steps.push(await runModuleByName(c, mod, target, live, opts.phase, progressLog, opts.domain, objective))
    }
  } else if (opts.phase === "post_ex") {
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
    progressLog.push(`ares_auto_chain: ${chain.summary.slice(0, 80)}`)
    for (const mod of moduleList.filter((m) => m !== "ares_auto_chain")) {
      steps.push(await runModuleByName(c, mod, target, live, opts.phase, progressLog, opts.domain, objective))
    }
  } else if (opts.phase === "apt") {
    if (moduleList.includes("ares_orchestrator") && moduleList.length === 1) {
      const orch = await runAresOrchestrator({
        live,
        target: hostFromTarget(target),
        domain: opts.domain,
        autoChain: !skipAdAutoChain(flow, objective),
      })
      steps.push({
        module: "ares_orchestrator",
        success: orch.succeeded > 0,
        summary: orch.summary,
      })
      progressLog.push(`ares_orchestrator: ${orch.summary.slice(0, 80)}`)
    } else {
      for (const mod of moduleList) {
        steps.push(await runModuleByName(c, mod, target, live, opts.phase, progressLog, opts.domain, objective))
      }
    }
  } else {
    const policy = evaluateEngagementPolicy({ profile: flow, objective, live, credGraph: c.credGraph, phase: opts.phase })
    const filtered = moduleList.filter((mod) => {
      if (policy.skipModules.includes(mod)) return false
      if (mod === "cred_access_auto" && skipAdAutoChain(flow, objective)) return false
      if (
        (mod === "ares_kerberos_advanced" || mod === "ares_lateral_scale")
        && skipAdAutoChain(flow, objective)
      ) return false
      return true
    })

    const { parallel, sequential } = partitionParallelModules(filtered, opts.phase)
    steps.push(...await runModulesBatch(c, parallel, target, live, opts.phase, progressLog, opts.domain, objective, true))
    steps.push(...await runModulesBatch(c, sequential, target, live, opts.phase, progressLog, opts.domain, objective, false))
  }

  if (
    opts.phase === "post_ex"
    && objective === "hybrid_it_ot"
    && c.credGraph
  ) {
    const otSubnets = c.credGraph.inferOtSubnets()
    if (otSubnets.length) {
      mcpProgress(`cred-graph OT pivot: ${otSubnets.length} subnet(s) — ${otSubnets.slice(0, 3).join(", ")}`)
      for (const subnet of otSubnets.slice(0, 2)) {
        const batch = await scanOtSubnet(subnet, { live, maxHosts: 32 })
        steps.push({
          module: "ot_batch_scan",
          success: batch.otHosts.length > 0,
          summary: batch.summary,
        })
        progressLog.push(`cred-graph ot_batch_scan ${subnet}: ${batch.summary.slice(0, 80)}`)
      }
    }
  }

  c.credGraph?.save()
  const succeeded = steps.filter((s) => s.success).length
  const recommendedNextPhase = recommendNextPhase(opts.phase, steps)
  logPhaseProgress(opts.phase, "*", `done ${succeeded}/${steps.length}`)

  return {
    phase: opts.phase,
    target,
    objective,
    persona: flow.persona,
    steps,
    succeeded,
    summary: `Phase ${opts.phase} [${objective}]: ${succeeded}/${steps.length} module(s) ok on ${target}`,
    recommendedNextPhase,
    progressLog,
  }
}

export default { runAresPhase }
