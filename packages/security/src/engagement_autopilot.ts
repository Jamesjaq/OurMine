/**
 * @module engagement_autopilot
 * Tier-1 autonomous campaign loop — agent steers once, server runs until scope boundary.
 * Orchestrates engagement_slice + engagement_graph actions without per-step LLM turns.
 */
import { AttackSurfaceGraph } from "./attack_surface.ts"
import { CredentialGraph } from "./credential_graph.ts"
import { ToolBroker } from "./tool_broker.ts"
import type { AgentToolContext } from "./agent_tools.ts"
import { runEngagementSlice, runEngagementContinue, type EngagementSliceResult } from "./engagement_slice.ts"
import { EXTERNAL_MODULES_BY_DESIGN } from "./module_registry.ts"
import type { PlanAction } from "./pentest_plan_builder.ts"
import type { AresPhase } from "./mcp_efficiency.ts"
import { MODULE_BRIDGE } from "./module_bridge.ts"
import { buildFlowProfile } from "./target_flow.ts"
import { writeArtifact } from "./mcp_artifacts.ts"
import { mcpProgress } from "./mcp_progress.ts"

export interface EngagementAutopilotResult {
  summary: string
  confirmedCount: number
  artifactId: string
  phasesRun: number
  stoppedReason: string
  dryRun: boolean
  objective: string
  persona: string
  blockers: string[]
  progressLog: string[]
}

const HUMAN_BLOCKER_PATTERNS = [
  /outside declared scope/i,
  /OUT_OF_SCOPE/i,
  /dry-run.*live/i,
  /live probes skipped/i,
  /live execution required/i,
  /live mode required/i,
  /RoE not attested/i,
  /OURMINE_ROE_SIGNED/i,
]

function parseScope(scope?: string, target?: string): string[] {
  if (scope) return scope.split(",").map((s) => s.trim()).filter(Boolean)
  return target ? [target] : []
}

function ipInCidr(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split("/")
  if (!network || !prefixStr) return ip === network
  const prefix = parseInt(prefixStr, 10)
  if (Number.isNaN(prefix) || prefix < 0 || prefix > 32) return ip === network
  const ipParts = ip.split(".").map(Number)
  const netParts = network.split(".").map(Number)
  if (ipParts.length !== 4 || netParts.some(Number.isNaN) || netParts.length !== 4) return false
  const ipNum = ((ipParts[0]! << 24) | (ipParts[1]! << 16) | (ipParts[2]! << 8) | ipParts[3]!) >>> 0
  const netNum = ((netParts[0]! << 24) | (netParts[1]! << 16) | (netParts[2]! << 8) | netParts[3]!) >>> 0
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
  return (ipNum & mask) === (netNum & mask)
}

/** Scope check for pivot targets — CIDR prefix, domain suffix, exact host. */
export function hostInAuthorizedScope(host: string, scope: string[]): boolean {
  if (!scope.length) return true
  const h = host.replace(/\/.*$/, "").toLowerCase()
  return scope.some((s) => {
    const anchor = s.toLowerCase()
    if (h === anchor) return true
    if (anchor.includes("/") && /^\d+\.\d+\.\d+\.\d+$/.test(h)) return ipInCidr(h, anchor)
    if (/^\d+\.\d+\.\d+\.\d+$/.test(anchor)) return h === anchor
    return h.endsWith(`.${anchor}`) || h.endsWith(anchor.replace(/^\./, "")) || anchor.includes(h)
  })
}

export function isActionInScope(action: PlanAction, scope: string[]): boolean {
  const args = action.args
  const targets = [args.target, args.plant_subnet, args.domain, args.network]
    .filter(Boolean)
    .map(String)
  if (!targets.length) return true
  return targets.every((t) => hostInAuthorizedScope(t, scope))
}

export function requiresHumanIntervention(blockers: string[]): string | null {
  for (const b of blockers) {
    if (HUMAN_BLOCKER_PATTERNS.some((re) => re.test(b))) return b
  }
  return null
}

/** Pick next autopilot-eligible graph action — skips external MCP/HITL tools and same-phase slice. */
export function pickAutopilotAction(
  actions: PlanAction[],
  lastPhase?: AresPhase,
): PlanAction | null {
  let fallback: PlanAction | null = null
  for (const a of actions) {
    if (EXTERNAL_MODULES_BY_DESIGN.has(a.tool)) {
      mcpProgress(`autopilot: skip ${a.tool} — external MCP/HITL-only (${a.rationale ?? a.label})`)
      continue
    }
    if (a.tool === "ares_engagement_slice" && a.args.phase === lastPhase) {
      fallback = fallback ?? a
      continue
    }
    return a
  }
  return fallback
}

async function executeGraphAction(
  action: PlanAction,
  ctx: AgentToolContext & { credGraph: CredentialGraph },
  scope?: string,
): Promise<{ success: boolean; detail: string }> {
  const params: Record<string, unknown> = {
    ...action.args,
    target: action.args.target ?? ctx.target,
  }
  if (scope) params.scope = scope

  if (EXTERNAL_MODULES_BY_DESIGN.has(action.tool)) {
    mcpProgress(`autopilot: skip ${action.tool} — external MCP/HITL-only (${action.rationale ?? action.label})`)
    return { success: false, detail: `skipped external tool: ${action.tool}` }
  }

  mcpProgress(`autopilot: ${action.tool} — ${action.label}`)

  const fn = MODULE_BRIDGE[action.tool]
  let r
  if (fn) {
    r = await fn(ctx, params)
  } else {
    const { executeAgentTool } = await import("./agent_tools.ts")
    r = await executeAgentTool(ctx, action.tool, params)
    if (!r.success && r.error?.includes("unknown tool")) {
      return { success: false, detail: `unknown tool: ${action.tool}` }
    }
  }
  ctx.graph.save()
  ctx.credGraph.save()
  return { success: r.success, detail: (r.output ?? "").slice(0, 200) }
}

/** Parse multi-target scope — comma-separated hosts/CIDRs/domains. */
export function parseMultiTargets(scope?: string, primary?: string): string[] {
  const list = parseScope(scope, primary ?? "")
  if (list.length > 1) return list
  if (primary && !list.includes(primary)) return [primary, ...list]
  return list.length ? list : (primary ? [primary] : [])
}

export async function runEngagementAutopilot(opts: {
  target: string
  scope?: string
  targets?: string
  maxPhases?: number
  live: boolean
}): Promise<EngagementAutopilotResult> {
  const scopeList = parseMultiTargets(opts.targets ?? opts.scope, opts.target)
  const multiTarget = scopeList.length > 1
  const target = multiTarget ? scopeList[0]! : opts.target
  const maxPhases = opts.maxPhases ?? 5
  const progressLog: string[] = []
  let phasesRun = 0
  let stoppedReason = "complete"
  let lastPhase: AresPhase | undefined
  let confirmedCount = 0
  let objective = "standard"
  let persona = "generic_ip"
  let blockers: string[] = []

  const graph = new AttackSurfaceGraph(target)
  const credGraph = CredentialGraph.load()
  const ctx: AgentToolContext & { credGraph: CredentialGraph } = {
    target,
    graph,
    credGraph,
    broker: new ToolBroker(),
    live: opts.live,
  }

  mcpProgress(`autopilot: start ${target} maxPhases=${maxPhases} live=${opts.live}${multiTarget ? ` multi=${scopeList.length}` : ""}`)

  const scopeArg = opts.targets ?? opts.scope ?? (multiTarget ? scopeList.join(",") : undefined)

  let slice: EngagementSliceResult = await runEngagementSlice({
    target,
    live: opts.live,
    scope: scopeArg,
  })
  phasesRun++
  progressLog.push(slice.summary)
  objective = slice.objective
  persona = slice.persona
  confirmedCount = slice.confirmed.length
  blockers = slice.blockers
  lastPhase = slice.phaseResult.phase

  while (phasesRun < maxPhases) {
    const humanBlock = requiresHumanIntervention(slice.blockers)
    if (humanBlock) {
      stoppedReason = humanBlock.includes("scope") ? "OUT_OF_SCOPE"
        : humanBlock.includes("RoE") ? "roe_required"
        : "live_required"
      blockers = slice.blockers
      break
    }

    // Multi-target: rotate to next scope entry after completing a slice cycle
    if (multiTarget && phasesRun >= 2 && phasesRun % 2 === 0) {
      const idx = scopeList.indexOf(slice.target)
      const nextTarget = scopeList[(idx + 1) % scopeList.length]
      if (nextTarget && nextTarget !== slice.target && hostInAuthorizedScope(nextTarget, scopeList)) {
        progressLog.push(`multi-target: rotating to ${nextTarget}`)
        slice = await runEngagementSlice({ target: nextTarget, live: opts.live, scope: scopeArg })
        phasesRun++
        progressLog.push(slice.summary)
        confirmedCount = slice.confirmed.length
        objective = slice.objective
        persona = slice.persona
        blockers = slice.blockers
        lastPhase = slice.phaseResult.phase
        continue
      }
    }

    const actions = slice.graphNextActions ?? []
    if (!actions.length) {
      stoppedReason = "no_actions"
      break
    }

    const top = pickAutopilotAction(actions, lastPhase)
    if (!top) {
      stoppedReason = "no_actions"
      break
    }

    if (!isActionInScope(top, scopeList)) {
      stoppedReason = "OUT_OF_SCOPE"
      blockers = [`action target outside scope: ${JSON.stringify(top.args)}`]
      break
    }

    const flow = buildFlowProfile(target, scopeArg)
    if (opts.live && scopeList.length > 1 && !hostInAuthorizedScope(flow.target, scopeList)) {
      stoppedReason = "OUT_OF_SCOPE"
      blockers = [`target ${flow.target} outside declared scope`]
      break
    }

    if (top.tool === "ares_engagement_slice") {
      slice = await runEngagementSlice({
        target,
        live: opts.live,
        scope: scopeArg,
        objective: top.args.objective ?? objective,
        phase: (top.args.phase as AresPhase) ?? undefined,
      })
      progressLog.push(`${top.label}: ${slice.summary.slice(0, 120)}`)
    } else if (top.tool === "ares_engagement_continue") {
      const token = String(top.args.resumeToken ?? top.args.resume_token ?? slice.resumeToken ?? "")
      slice = await runEngagementContinue({
        resumeToken: token,
        phase: (top.args.phase as AresPhase) ?? undefined,
      })
      progressLog.push(`${top.label}: ${slice.summary.slice(0, 120)}`)
    } else {
      const exec = await executeGraphAction(top, ctx, scopeArg)
      progressLog.push(`${top.label}: ${exec.detail}`)
      slice = await runEngagementSlice({
        target,
        live: opts.live,
        scope: scopeArg,
        objective,
        phase: (top.phase as AresPhase) ?? lastPhase,
      })
      progressLog.push(slice.summary)
    }

    phasesRun++
    confirmedCount = slice.confirmed.length
    objective = slice.objective
    persona = slice.persona
    blockers = slice.blockers
    lastPhase = slice.phaseResult.phase
  }

  const summary = `Autopilot ${phasesRun}/${maxPhases} phases on ${target} [${objective}/${persona}]: ${confirmedCount} confirmed; stopped: ${stoppedReason}`

  const artifactId = writeArtifact("engagement_autopilot", {
    target,
    scope: scopeList,
    maxPhases,
    phasesRun,
    stoppedReason,
    confirmedCount,
    objective,
    persona,
    blockers,
    progressLog,
    dryRun: !opts.live,
  })

  mcpProgress(`autopilot: done — ${summary.slice(0, 120)}`)

  return {
    summary,
    confirmedCount,
    artifactId,
    phasesRun,
    stoppedReason,
    dryRun: !opts.live,
    objective,
    persona,
    blockers,
    progressLog,
  }
}

/** Estimate LLM turns: 1 autopilot call vs manual slice+action chain. */
export function compareTurnEfficiency(target: string, scope?: string): {
  autopilotTurns: number
  manualTurns: number
  manualWorkflow: string[]
  savings: string
} {
  const flow = buildFlowProfile(target, scope)
  const manualWorkflow = ["ares_engagement_slice"]
  if (flow.isAdLikely) {
    manualWorkflow.push(
      "ares_phase(identity)",
      "ares_phase(exploit)",
      "ares_dispatch(campaign_loop)",
      "ares_auto_chain",
    )
  } else if (flow.isOtLikely) {
    manualWorkflow.push("ares_dispatch(ot_batch_scan)", "ares_phase(exploit)")
  } else {
    manualWorkflow.push("ares_phase(exploit)", "ares_phase(post_ex)")
  }
  manualWorkflow.push("ares_artifact_get (optional)")

  const manualTurns = manualWorkflow.length
  return {
    autopilotTurns: 1,
    manualTurns,
    manualWorkflow,
    savings: `${manualTurns - 1} fewer LLM turns (${Math.round((1 - 1 / manualTurns) * 100)}% reduction)`,
  }
}

export default { runEngagementAutopilot, compareTurnEfficiency, hostInAuthorizedScope, requiresHumanIntervention, parseMultiTargets, isActionInScope, pickAutopilotAction }
