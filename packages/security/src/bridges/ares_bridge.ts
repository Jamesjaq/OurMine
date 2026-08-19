
import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"
import { result } from "./_shared.ts"

export const ares_bridge: Record<
  string,
  (ctx: AgentToolContext, params: Record<string, unknown>) => Promise<ToolRunResult>
> = {
  ares_innovation_engine: async (ctx, params) => {
    const { runInnovationEngine } = await import("../ares/innovation_engine.ts")
    const r = await runInnovationEngine({ target: params.target as string ?? ctx.target }, { live: ctx.live })
    const data = r.data ?? r
    return result("ares_innovation_engine", "runInnovationEngine", ctx, r, (data.hypothesesCount ?? 0) > 0)
  },
  ares_self_healing: async (ctx, params) => {
    const { runSelfHealing } = await import("../ares/self_healing.ts")
    const r = await runSelfHealing({ agentIds: params.agent_ids as string[] | undefined, checkin: params.checkin as any }, { live: ctx.live })
    const data = r.data ?? r
    return result("ares_self_healing", "runSelfHealing", ctx, r, (data.lostAgents?.length ?? 0) >= 0)
  },
  ares_self_improvement: async (ctx, params) => {
    const { runSelfImprovement } = await import("../ares/self_improvement.ts")
    const r = await runSelfImprovement({ techniqueId: params.technique_id as string | undefined, testCommand: params.test_command as string | undefined }, { live: ctx.live })
    const data = r.data ?? r
    return result("ares_self_improvement", "runSelfImprovement", ctx, r, data.validation?.ok ?? false)
  },
  ares_specialized_impact: async (ctx, params) => {
    const { runSpecializedImpact } = await import("../ares/specialized_impact.ts")
    const r = await runSpecializedImpact({ sector: params.sector as any, target: params.target as string | undefined }, { live: ctx.live })
    const data = r.data ?? r
    return result("ares_specialized_impact", "runSpecializedImpact", ctx, r, (data.impactScore ?? 0) > 0)
  },
  ares_ghost_autonomy: async (ctx, params) => {
    const { runGhostAutonomy } = await import("../ares/ghost_autonomy.ts")
    const r = await runGhostAutonomy({ baselineActivity: params.baseline_activity as string[] | undefined, targetHost: params.target_host as string | undefined }, { live: ctx.live })
    const data = r.data ?? r
    return result("ares_ghost_autonomy", "runGhostAutonomy", ctx, r, data.active ?? false)
  },
  ares_lateral_movement: async (ctx, params) => {
    const { runLateralMovement } = await import("../ares/lateral_movement.ts")
    const r = await runLateralMovement({ source: params.source as string | undefined, target: params.target as string | undefined, highValueTargets: params.high_value_targets as string[] | undefined }, { live: ctx.live })
    const data = r.data ?? r
    return result("ares_lateral_movement", "runLateralMovement", ctx, r, !!data.path || !!data.nextHop)
  },
} as const
