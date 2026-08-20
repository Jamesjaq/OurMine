import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"
import { result } from "./_shared.ts"

export const tier1_bridge: Record<
  string,
  (ctx: AgentToolContext, params: Record<string, unknown>) => Promise<ToolRunResult>
> = {
  tier1_validation: async (ctx, params) => {
    const { runTier1ValidationSuite } = await import("../tier1_validation.ts")
    const r = await runTier1ValidationSuite(params.target as string ?? ctx.target, { live: ctx.live })
    return result("tier1_validation", "runTier1ValidationSuite", ctx, r, true)
  },
  campaign_loop: async (ctx, params) => {
    const { runCampaignLoop } = await import("../campaign_loop.ts")
    const { AttackSurfaceGraph } = await import("../attack_surface.ts")
    const graph = new AttackSurfaceGraph(params.target as string ?? ctx.target)
    const r = await runCampaignLoop({ graph, target: params.target as string ?? ctx.target, live: ctx.live })
    return result("campaign_loop", "runCampaignLoop", ctx, r, (r.hostsCompromised?.length ?? 0) >= 0)
  },
  identity_playbooks: async (ctx, params) => {
    const { runFullIdentityPlaybook } = await import("../identity_playbooks.ts")
    const r = await runFullIdentityPlaybook(params.target as string ?? ctx.target, { live: ctx.live })
    return result("identity_playbooks", "runFullIdentityPlaybook", ctx, r, true)
  },
  exploit_synthesis: async (ctx, params) => {
    const { synthesizeFromIndicator } = await import("../exploit_synthesis.ts")
    const r = await synthesizeFromIndicator(params.target as string ?? ctx.target, params.indicator as string ?? "NullPointer", { live: ctx.live })
    return result("exploit_synthesis", "synthesizeFromIndicator", ctx, r, true)
  },
  c2_dwell_ops: async (ctx, params) => {
    const { runC2DwellOps } = await import("../c2_dwell_ops.ts")
    const { AttackSurfaceGraph } = await import("../attack_surface.ts")
    const graph = new AttackSurfaceGraph(params.target as string ?? ctx.target)
    const r = await runC2DwellOps({ graph, scopeHosts: [params.target as string ?? ctx.target], live: ctx.live })
    return result("c2_dwell_ops", "runC2DwellOps", ctx, r, true)
  },
  collection_engine: async (ctx, params) => {
    const { stageCollection } = await import("../collection_engine.ts")
    const r = await stageCollection(params.dir as string ?? process.cwd(), { live: ctx.live })
    return result("collection_engine", "stageCollection", ctx, r, true)
  },
  cred_access_auto: async (ctx, params) => {
    const { runAutonomousCredAccess } = await import("../cred_access_auto.ts")
    const r = await runAutonomousCredAccess({ target: params.target as string ?? ctx.target, live: ctx.live })
    return result("cred_access_auto", "runAutonomousCredAccess", ctx, r, true)
  },
  tier1_orchestrator: async (ctx, params) => {
    const { runTier1Orchestrator } = await import("../tier1_orchestrator.ts")
    const { AttackSurfaceGraph } = await import("../attack_surface.ts")
    const graph = new AttackSurfaceGraph(params.target as string ?? ctx.target)
    const r = await runTier1Orchestrator({ target: params.target as string ?? ctx.target, graph, live: ctx.live })
    return result("tier1_orchestrator", "runTier1Orchestrator", ctx, r, true)
  },
} as const
