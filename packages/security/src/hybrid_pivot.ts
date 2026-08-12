/**
 * @module hybrid_pivot
 * IT → OT pivot orchestration (Volt Typhoon / Salt Typhoon pattern).
 * Phase 1: IT recon → Phase 2: OT protocol sweep on inferred/plant subnets.
 * Infra CIDR targets skip IT recon and run read-only vertical-scoped OT sweeps.
 */
import { runAresPhase, type AresPhaseResult } from "./ares/phase_runner.ts"
import { scanOtSubnet, scanRankedOtSubnets, classifyOtHost, type OtHostClassification } from "./ot_batch_scan.ts"
import { inferPlantSubnets } from "./ot_segment_infer.ts"
import { scoreOtSubnets, type SubnetScore } from "./pivot_scorer.ts"
import { buildFlowProfile } from "./target_flow.ts"
import { CredentialGraph } from "./credential_graph.ts"
import { resolveLiveMode } from "./exec_options.ts"
import { mcpProgress } from "./mcp_progress.ts"
import {
  detectOtVertical,
  isInfraCidrTarget,
  modulesForVertical,
  READ_ONLY_SAFETY_NOTE,
  type OtVertical,
} from "./ot_verticals.ts"

export interface HybridPivotResult {
  target: string
  itRecon: AresPhaseResult
  otHosts: OtHostClassification[]
  otExploit?: AresPhaseResult
  pivotPath: string[]
  inferredSubnets: string[]
  subnetScores: SubnetScore[]
  otVertical?: OtVertical | null
  verticalModules?: string[]
  safetyNote?: string
  summary: string
}

export async function runHybridItOtPivot(opts: {
  target: string
  live?: boolean
  domain?: string
  plantSubnet?: string
  skipItRecon?: boolean
  hint?: string
  credGraph?: CredentialGraph
}): Promise<HybridPivotResult> {
  const live = opts.live ?? resolveLiveMode()
  const target = opts.target
  const hint = opts.hint ?? opts.plantSubnet ?? target
  const otVertical = detectOtVertical(hint, target)
  const infraCidr = isInfraCidrTarget(target, hint)
  const verticalModules = otVertical ? modulesForVertical(otVertical) : []
  const pivotPath: string[] = []
  const credGraph = opts.credGraph ?? CredentialGraph.load()

  const skipItRecon = opts.skipItRecon ?? infraCidr

  if (infraCidr) {
    pivotPath.push(`Infra CIDR scope${otVertical ? ` (${otVertical})` : ""} — read-only OT sweep`)
    pivotPath.push(READ_ONLY_SAFETY_NOTE)
    if (verticalModules.length) {
      pivotPath.push(`Vertical modules: ${verticalModules.join(", ")}`)
    }
  }

  let itRecon: AresPhaseResult
  if (skipItRecon) {
    pivotPath.push(infraCidr
      ? "IT recon skipped (infra CIDR — OT-first pivot)"
      : "IT recon skipped (dispatch-only pivot)")
    itRecon = {
      phase: "recon",
      target,
      objective: infraCidr ? "ot_ics" : "hybrid_it_ot",
      persona: otVertical ? "ot_scada_plant" : "hybrid_it_ot",
      steps: [],
      succeeded: 0,
      summary: "skipped",
      progressLog: [],
    }
  } else {
    pivotPath.push("IT recon (intel, OSINT, vuln research)")
    mcpProgress("hybrid_pivot: starting IT recon phase")
    itRecon = await runAresPhase({
      phase: "recon",
      target,
      live,
      domain: opts.domain,
      objective: "identity_first",
    })
  }

  const otHosts: OtHostClassification[] = []
  let inferredSubnets = inferPlantSubnets({
    target,
    reconSteps: itRecon.steps,
    credGraph,
    itHost: target,
  })

  if (infraCidr && target.includes("/") && !inferredSubnets.includes(target)) {
    inferredSubnets = [target, ...inferredSubnets]
  }

  const scored = scoreOtSubnets(inferredSubnets, credGraph, itRecon.steps)
  const rankedSubnets = scored.map((s) => s.subnet)
  if (opts.plantSubnet) {
    rankedSubnets.unshift(opts.plantSubnet)
    scored.unshift({ subnet: opts.plantSubnet, confidence: 0.95, reason: "explicit plant_subnet param" })
  }

  const uniqueSubnets = [...new Set(rankedSubnets)]
  pivotPath.push(`Inferred ${uniqueSubnets.length} plant subnet(s): ${uniqueSubnets.join(", ") || "none"}`)
  for (const s of scored.slice(0, 3)) {
    pivotPath.push(`Pivot score ${s.subnet}: ${s.confidence} — ${s.reason}`)
  }
  if (scored[0]) pivotPath.push(`Top pivot score: ${scored[0].subnet} (${scored[0].confidence}) — ${scored[0].reason}`)

  if (uniqueSubnets.length > 0) {
    pivotPath.push(`Ranked OT subnet sweep (${uniqueSubnets.length} candidates)`)
    mcpProgress(`hybrid_pivot: ranked sweep ${uniqueSubnets.length} subnet(s)`)
    const ranked = await scanRankedOtSubnets(uniqueSubnets, {
      live,
      maxHosts: infraCidr ? 64 : 64,
      maxSubnets: infraCidr ? 6 : 4,
      credGraph,
      reconSteps: itRecon.steps,
    })
    otHosts.push(...ranked.otHosts)
    if (ranked.hasMore && ranked.nextResumeToken) {
      pivotPath.push(`Sweep partial — resume with resumeToken=${ranked.nextResumeToken}`)
    }
  } else {
    const flow = buildFlowProfile(target, undefined, hint)
    if (!flow.isOtLikely && !target.includes("/")) {
      pivotPath.push("No OT subnets inferred and target lacks OT hints — skipping live OT sweep")
    } else if (target.includes("/") || flow.kind === "cidr") {
      const cidr = target.includes("/") ? target : `${target.split(".").slice(0, 3).join(".")}.0/24`
      pivotPath.push(`OT batch scan ${cidr} (explicit CIDR / OT scope)`)
      const batch = await scanOtSubnet(cidr, { live, maxHosts: infraCidr ? 48 : 32 })
      otHosts.push(...batch.otHosts)
    } else if (flow.isOtLikely) {
      pivotPath.push(`OT classify anchor host ${target}`)
      otHosts.push(await classifyOtHost(target, live))
    } else {
      pivotPath.push("Private target without OT hints — no Modbus sweep (pass plant_subnet or modbus/scada hint)")
    }
  }

  const credSubnets = credGraph.inferOtSubnets().filter((s) => !uniqueSubnets.includes(s))
  if (credSubnets.length) {
    pivotPath.push(`Cred-graph OT sweep: ${credSubnets.join(", ")}`)
    for (const subnet of credSubnets.slice(0, 4)) {
      mcpProgress(`hybrid_pivot: cred-graph sweep ${subnet}`)
      const batch = await scanOtSubnet(subnet, { live, maxHosts: 32 })
      otHosts.push(...batch.otHosts)
    }
  }

  const seen = new Set<string>()
  const deduped = otHosts.filter((h) => {
    if (seen.has(h.host)) return false
    seen.add(h.host)
    return true
  })

  let otExploit: AresPhaseResult | undefined
  const primaryOt = deduped.find((h) => h.otLikely) ?? deduped[0]
  if (primaryOt) {
    pivotPath.push(`OT semantic impact on ${primaryOt.host} (${primaryOt.protocols.join(",") || "probe"}) — read-only`)
    mcpProgress(`hybrid_pivot: OT semantic impact on ${primaryOt.host}`)
    otExploit = await runAresPhase({
      phase: "exploit",
      target: primaryOt.host,
      live,
      domain: opts.domain,
      objective: "ot_ics",
    })
  }

  return {
    target,
    itRecon,
    otHosts: deduped,
    otExploit,
    pivotPath,
    inferredSubnets: uniqueSubnets,
    subnetScores: scored,
    otVertical,
    verticalModules: verticalModules.length ? verticalModules : undefined,
    safetyNote: infraCidr ? READ_ONLY_SAFETY_NOTE : undefined,
    summary: `Hybrid pivot${otVertical ? ` [${otVertical}]` : ""}: IT ${itRecon.succeeded}/${itRecon.steps.length} ok → ${deduped.filter((h) => h.otLikely).length} OT host(s) from ${uniqueSubnets.length} subnet(s) [top conf ${scored[0]?.confidence ?? 0}] → ${otExploit ? otExploit.summary : "no OT semantic impact"}`,
  }
}

export default { runHybridItOtPivot }
