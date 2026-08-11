/**
 * @module tier1_orchestrator
 * Full tier-1 APT engagement orchestrator — live execution only (no simulation path).
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { CredentialGraph } from "./credential_graph.ts"
import { EngagementMemory } from "./engagement_memory.ts"
import { runTier1ValidationSuite } from "./tier1_validation.ts"
import { runCampaignLoop } from "./campaign_loop.ts"
import { runFullIdentityPlaybook } from "./identity_playbooks.ts"
import { synthesizeFromIndicator } from "./exploit_synthesis.ts"
import { runC2DwellOps } from "./c2_dwell_ops.ts"
import { stageCollection } from "./collection_engine.ts"
import { runAutonomousCredAccess } from "./cred_access_auto.ts"
import { loadPlaybook } from "./apt_playbook.ts"
import { collectTier1Metrics } from "./tier1_depth_metrics.ts"
import { runEdrFeedbackLoop } from "./edr_feedback_loop.ts"
import { runPrivescChains } from "./privesc_chains.ts"
import { fuseMultiCloudAsm } from "./multi_cloud_asm.ts"
import { runDwellSchedule } from "./c2_dwell_scheduler.ts"
import { resolveLiveMode } from "./exec_options.ts"
import { enableTier1Mode } from "./tier1_config.ts"

export interface Tier1OrchestratorResult {
  validation: Awaited<ReturnType<typeof runTier1ValidationSuite>>
  campaign: Awaited<ReturnType<typeof runCampaignLoop>>
  identity: Awaited<ReturnType<typeof runFullIdentityPlaybook>>
  synthesis: Awaited<ReturnType<typeof synthesizeFromIndicator>>
  c2Dwell: Awaited<ReturnType<typeof runC2DwellOps>>
  collection: Awaited<ReturnType<typeof stageCollection>>
  credAccess: Awaited<ReturnType<typeof runAutonomousCredAccess>>
  edrLoop: Awaited<ReturnType<typeof runEdrFeedbackLoop>>
  privesc: Awaited<ReturnType<typeof runPrivescChains>>
  cloudAsm: Awaited<ReturnType<typeof fuseMultiCloudAsm>>
  dwell: Awaited<ReturnType<typeof runDwellSchedule>>
  metrics: Awaited<ReturnType<typeof collectTier1Metrics>>
  playbook: ReturnType<typeof loadPlaybook>
  live: boolean
  summary: string
}

export async function runTier1Orchestrator(opts: {
  target: string
  graph: AttackSurfaceGraph
  credGraph?: CredentialGraph
  live: boolean
  profileId?: string
}): Promise<Tier1OrchestratorResult> {
  enableTier1Mode()
  const live = resolveLiveMode({ live: opts.live })
  const credGraph = opts.credGraph ?? CredentialGraph.load()
  const mem = EngagementMemory.loadForTarget(opts.target)
  const profileId = opts.profileId ?? "scattered_spider"
  const playbook = loadPlaybook(profileId)
  const baseUrl = opts.target.startsWith("http") ? opts.target : `http://${opts.target}:8080`

  if (!live) {
    throw new Error("Tier-1 orchestrator requires live execution — set OURMINE_TIER1=1, --live, or OURMINE_LIVE=1")
  }

  const validation = await runTier1ValidationSuite(baseUrl, { live: true })
  const campaign = await runCampaignLoop({ graph: opts.graph, credGraph, target: opts.target, live: true, engagementMem: mem })
  const identity = await runFullIdentityPlaybook(opts.target, { live: true })
  const synthesis = await synthesizeFromIndicator(opts.target, "java.lang.NullPointerException struts", { live: true })
  const c2Dwell = await runC2DwellOps({ graph: opts.graph, scopeHosts: [opts.target], live: true })
  const collection = await stageCollection(process.cwd(), { live: true, maxFiles: 50 })
  const credAccess = await runAutonomousCredAccess({ target: opts.target, live: true, credGraph })
  const edrLoop = await runEdrFeedbackLoop({ live: true })
  const privesc = await runPrivescChains({ live: true })
  const cloudAsm = await fuseMultiCloudAsm(opts.graph, { live: true, target: opts.target })
  const dwell = await runDwellSchedule({ graph: opts.graph, scopeHosts: [opts.target], live: true, maxTicks: 2 })

  const metrics = await collectTier1Metrics()
  const l4 = validation.fuzz.l4ImpactProven || validation.idor.proven

  return {
    validation,
    campaign,
    identity,
    synthesis,
    c2Dwell,
    collection,
    credAccess,
    edrLoop,
    privesc,
    cloudAsm,
    dwell,
    metrics,
    playbook,
    live: true,
    summary: `Tier-1 live orchestrator: L4=${l4}, campaign hosts=${campaign.hostsCompromised.length}, metrics ${metrics.overall}/10`,
  }
}

export default { runTier1Orchestrator }
