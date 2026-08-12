/**
 * @module engagement_slice
 * One MCP turn: plan + execute first recommended phase + unified graph evidence.
 * Multi-turn via resumeToken — no re-plan on continue.
 */
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import { ensureAresDir } from "./ares/_base.ts"
import { AttackSurfaceGraph } from "./attack_surface.ts"
import { CredentialGraph } from "./credential_graph.ts"
import { runAresPhase, PARALLEL_RECON_MODULES, type AresPhaseResult } from "./ares/phase_runner.ts"
import { buildActionablePlan, type ActionablePlan, type PlanAction } from "./pentest_plan_builder.ts"
import type { AresPhase } from "./mcp_efficiency.ts"
import { mcpProgress } from "./mcp_progress.ts"
import {
  buildEngagementGraph,
  getNextActions,
  validateGraphCandidates,
  proveOtImpacts,
  type EvidenceItem,
  type ProximityEvidence,
} from "./engagement_graph.ts"
import { evaluateEngagementPolicy } from "./engagement_policy.ts"
import { buildFlowProfile, phasesForObjective, type FlowObjective } from "./target_flow.ts"
import type { OtHostClassification } from "./ot_batch_scan.ts"
import { scoreOtSubnets } from "./pivot_scorer.ts"
import { runIntelPrefetch, type IntelPrefetchResult } from "./intel_autonomous.ts"
import { preloadTechniquesForPersona } from "./apt_intel_feed.ts"
import { buildCachedActionablePlan } from "./engagement_cache.ts"
import { EngagementMemory, intelCacheKey } from "./engagement_memory.ts"
import { snapshotFromPayload } from "./semantic_compression.ts"
import { runPassiveIntel } from "./passive_intel.ts"

export type { EvidenceItem as GraphEvidenceItem }

export interface EngagementResumeState {
  target: string
  scope?: string
  objective: string
  persona: string
  completedPhases: AresPhase[]
  lastPhase: AresPhase
  otResumeToken?: string
  live: boolean
  updatedAt: string
}

export interface EngagementSliceResult {
  target: string
  summary: string
  objective: string
  persona: string
  resumeToken: string
  planNextActions: PlanAction[]
  phaseResult: Pick<AresPhaseResult, "phase" | "succeeded" | "summary" | "recommendedNextPhase"> & {
    stepCount: number
    stepsOk: number
  }
  confirmed: EvidenceItem[]
  candidates: EvidenceItem[]
  blockers: string[]
  recommendedNextPhase?: AresPhase
  dryRun: boolean
  graphNextActions: PlanAction[]
  intelSnippet?: string
  intelDigest?: string
  intelArtifactId?: string
  aptTechniques?: Array<{ id: string; name: string }>
  cacheHit?: boolean
  parallelProbes?: number
  intelFromMemory?: boolean
}

const ENGAGEMENT_STATE_DIR = ensureAresDir("engagement_state")

export function buildEngagementResumeToken(
  target: string,
  objective: string,
  completedPhases: AresPhase[],
): string {
  const raw = `${target}|${objective}|${completedPhases.join(",")}|${Date.now()}`
  return `eng_${crypto.createHash("sha256").update(raw).digest("base64url").slice(0, 14)}`
}

export function saveEngagementState(token: string, state: EngagementResumeState): void {
  const safe = token.replace(/[^a-zA-Z0-9_-]/g, "")
  fs.writeFileSync(path.join(ENGAGEMENT_STATE_DIR, `${safe}.json`), JSON.stringify(state))
}

export function loadEngagementState(token: string): EngagementResumeState | null {
  const safe = token.replace(/[^a-zA-Z0-9_-]/g, "")
  if (!safe) return null
  const fp = path.join(ENGAGEMENT_STATE_DIR, `${safe}.json`)
  if (!fs.existsSync(fp)) return null
  try {
    return JSON.parse(fs.readFileSync(fp, "utf8")) as EngagementResumeState
  } catch {
    return null
  }
}

function pickFirstPhase(plan: ActionablePlan, policyPhases: AresPhase[]): AresPhase {
  const phaseAction = plan.nextActions.find((a) => a.tool === "ares_phase" || a.tool === "ares_engagement_slice")
  const fromAction = phaseAction?.args?.phase as AresPhase | undefined
  if (fromAction && !policyPhases.includes(fromAction) && plan.recommendedPhases.includes(fromAction)) {
    return fromAction
  }
  const available = plan.recommendedPhases.filter((p) => !policyPhases.includes(p))
  return available[0] ?? "recon"
}

function pickNextPhase(
  objective: FlowObjective,
  completedPhases: AresPhase[],
  skipPhases: AresPhase[],
  override?: AresPhase,
): AresPhase {
  if (override && !skipPhases.includes(override)) return override
  const phases = phasesForObjective(objective)
  const remaining = phases.filter((p) => !completedPhases.includes(p) && !skipPhases.includes(p))
  return remaining[0] ?? completedPhases[completedPhases.length - 1] ?? "recon"
}

function extractOtHostsFromSteps(steps: AresPhaseResult["steps"]): OtHostClassification[] {
  const hosts: OtHostClassification[] = []
  const seen = new Set<string>()
  for (const step of steps) {
    for (const h of step.otHosts ?? []) {
      if (!seen.has(h.host)) {
        seen.add(h.host)
        hosts.push(h)
      }
    }
  }
  return hosts
}

function extractProximityFromSteps(steps: AresPhaseResult["steps"]): ProximityEvidence[] {
  const out: ProximityEvidence[] = []
  for (const step of steps) {
    if (!["usb_audit", "wifi_audit", "ble_audit", "proximity_audit", "ares_hardware_implant"].includes(step.module)) continue
    try {
      const parsed = JSON.parse(step.summary) as {
        findings?: Array<{ id: string; title: string; severity?: string; detail?: string }>
        usb?: { findings?: Array<{ id: string; title: string; severity?: string; detail?: string }> }
        wifi?: { findings?: Array<{ id: string; title: string; severity?: string; detail?: string }> }
        ble?: { findings?: Array<{ id: string; title: string; severity?: string; detail?: string }> }
        channels?: string[]
      }
      const channel = step.module.includes("usb") || step.module.includes("hardware") ? "usb"
        : step.module.includes("wifi") ? "wifi" : "ble"
      const lists = [
        parsed.findings,
        parsed.usb?.findings,
        parsed.wifi?.findings,
        parsed.ble?.findings,
      ].filter(Boolean) as Array<Array<{ id: string; title: string; severity?: string; detail?: string }>>
      for (const list of lists) {
        for (const f of list) {
          out.push({ channel, id: f.id, title: f.title, severity: f.severity, detail: f.detail })
        }
      }
      if (step.module === "proximity_audit" && !lists.length && step.success) {
        out.push({ channel: "usb", id: "proximity-dry", title: "Proximity templates staged", severity: "info" })
      }
    } catch { /* summary not JSON */ }
  }
  return out
}

async function resolveIntelWithMemory(
  target: string,
  persona: string,
  opts: {
    objective: FlowObjective
    aptHint?: string
    live: boolean
    hint: string
  },
): Promise<{ intel: IntelPrefetchResult; fromMemory: boolean }> {
  const memory = EngagementMemory.loadForTarget(target)
  const profileKey = intelCacheKey(opts.aptHint ?? persona, persona, opts.objective)
  const cachedId = `intel_${profileKey}_${target.replace(/[^a-zA-Z0-9._-]/g, "_")}`

  if (memory.hasReadIntel(cachedId) && !opts.aptHint?.trim()) {
    const snippet = memory.getIntelSnippet(cachedId)!
    mcpProgress("engagement: intel from memory (skip prefetch)")
    const techniquesJson = memory.getDecision(`intel_techniques_${cachedId}`)
    let techniques = techniquesJson
      ? (JSON.parse(techniquesJson) as Array<{ id: string; name: string }>)
      : []
    if (techniques.length < 3) {
      techniques = preloadTechniquesForPersona({
        persona: persona as import("./target_flow.ts").TargetPersona,
        objective: opts.objective,
        aptHint: opts.aptHint,
        count: 5,
      }).map((t) => ({ id: t.id, name: t.name }))
    }
    return {
      intel: {
        target,
        persona: persona as import("./target_flow.ts").TargetPersona,
        objective: opts.objective,
        intelDigest: snippet,
        artifactId: cachedId,
        techniques,
        modules: [],
        kevHits: [],
        stackSignals: [],
        stackCves: [],
        ransomActions: [],
        pocHints: [],
        recommendedNextActions: [],
        cachedAt: new Date().toISOString(),
      },
      fromMemory: true,
    }
  }

  const intel = await runIntelPrefetch(target, persona as import("./target_flow.ts").TargetPersona, {
    objective: opts.objective,
    aptHint: opts.aptHint,
    live: opts.live,
    hint: opts.hint,
  })
  memory.markIntelRead(cachedId, intel.intelDigest, intel.profileId)
  if (intel.techniques?.length) {
    memory.recordDecision(`intel_techniques_${cachedId}`, JSON.stringify(intel.techniques.map((t) => ({ id: t.id, name: t.name }))))
  }
  memory.recordDecision("persona", persona)
  memory.recordDecision("objective", opts.objective)
  return { intel, fromMemory: false }
}

function countParallelProbes(steps: AresPhaseResult["steps"], phase: AresPhase): number {
  if (phase !== "recon") return 0
  return steps.filter((s) => PARALLEL_RECON_MODULES.has(s.module) || PARALLEL_RECON_MODULES.has(s.module.replace(/^ares_/, ""))).length
}

async function executeEngagementPhase(opts: {
  target: string
  phase: AresPhase
  live: boolean
  objective: string
  hint?: string
  aptHint?: string
  scope?: string
  graph?: AttackSurfaceGraph
  credGraph?: CredentialGraph
}): Promise<{
  phaseResult: AresPhaseResult
  graph: AttackSurfaceGraph
  credGraph: CredentialGraph
  otHosts: OtHostClassification[]
  extraBlockers: string[]
  icsProofs: EvidenceItem[]
  proximityFindings: ProximityEvidence[]
}> {
  const graph = opts.graph ?? new AttackSurfaceGraph(opts.target)
  const credGraph = opts.credGraph ?? CredentialGraph.load()
  const plan = buildActionablePlan(opts.target, { scope: opts.scope, objective: opts.objective })

  mcpProgress(`engagement: phase ${opts.phase} [${plan.objective}/${plan.profile.persona}]`)

  const phaseResult = await runAresPhase({
    phase: opts.phase,
    target: opts.target,
    live: opts.live,
    domain: plan.profile.scope[0],
    objective: opts.objective,
    hint: opts.hint ?? opts.objective,
    aptHint: opts.aptHint,
    graph,
    credGraph,
  })

  if (opts.live) {
    mcpProgress("engagement: validating graph candidates")
    await validateGraphCandidates(graph, opts.live)
  }

  const otHosts = extractOtHostsFromSteps(phaseResult.steps)
  let icsProofs: EvidenceItem[] = []
  if (opts.live && otHosts.length) {
    mcpProgress(`engagement: ICS semantic impact on ${otHosts.filter((h) => h.openPorts.includes(502)).length} Modbus host(s)`)
    icsProofs = await proveOtImpacts(graph, otHosts, opts.live)
  }

  credGraph.injectIntoGraph(graph)
  graph.save(ensureAresDir("asm"))
  credGraph.save()

  const extraBlockers = phaseResult.steps
    .filter((s) => !s.success)
    .map((s) => `${s.module}: ${s.summary.slice(0, 100)}`)

  return { phaseResult, graph, credGraph, otHosts, extraBlockers, icsProofs, proximityFindings: extractProximityFromSteps(phaseResult.steps) }
}

function assembleSliceResult(opts: {
  target: string
  plan: ActionablePlan
  phase: AresPhase
  phaseResult: AresPhaseResult
  graph: AttackSurfaceGraph
  otHosts: OtHostClassification[]
  extraBlockers: string[]
  live: boolean
  credGraph: CredentialGraph
  resumeToken: string
  completedPhases: AresPhase[]
  icsProofs?: EvidenceItem[]
  proximityFindings?: ProximityEvidence[]
  passiveHits?: Array<{ source: string; port?: number; service?: string; banner?: string }>
  intelSnippet?: string
  intelDigest?: string
  intelArtifactId?: string
  aptTechniques?: Array<{ id: string; name: string }>
  intelPrefetch?: IntelPrefetchResult
  cacheHit?: boolean
  parallelProbes?: number
  intelFromMemory?: boolean
}): EngagementSliceResult {
  const pivotScores = scoreOtSubnets(
    opts.plan.profile.scope.filter((s) => s.includes("/") || /^\d+\.\d+\.\d+\.\d+$/.test(s)),
    opts.credGraph,
    [],
  )
  const eg = buildEngagementGraph({
    target: opts.target,
    graph: opts.graph,
    credGraph: opts.credGraph,
    otHosts: opts.otHosts,
    objective: opts.plan.objective,
    live: opts.live,
    extraBlockers: opts.extraBlockers,
    pivotScores,
    proximityFindings: opts.proximityFindings,
    personaOverride: opts.plan.profile.persona,
    passiveHits: opts.passiveHits,
  })

  const confirmed = [...eg.confirmed]
  for (const p of opts.icsProofs ?? []) {
    if (!confirmed.some((c) => c.kind === "ics_impact" && c.label === p.label)) confirmed.push(p)
  }

  const graphNextActions = getNextActions(eg, {
    engagementResumeToken: opts.resumeToken,
    completedPhases: opts.completedPhases,
    lastPhase: opts.phase,
    credGraph: opts.credGraph,
    attackGraph: opts.graph,
    intelPrefetch: opts.intelPrefetch,
  })

  const summary = `Slice ${opts.phase} on ${opts.target} [${opts.plan.objective}]: ${opts.phaseResult.succeeded}/${opts.phaseResult.steps.length} ok; ${eg.confirmed.length} confirmed, ${eg.candidates.length} candidates`

  mcpProgress(`engagement_slice: done — ${summary.slice(0, 120)}`)

  return {
    target: opts.target,
    summary,
    objective: opts.plan.objective,
    persona: opts.plan.profile.persona,
    resumeToken: opts.resumeToken,
    planNextActions: opts.plan.nextActions,
    phaseResult: {
      phase: opts.phaseResult.phase,
      succeeded: opts.phaseResult.succeeded,
      summary: opts.phaseResult.summary,
      recommendedNextPhase: opts.phaseResult.recommendedNextPhase,
      stepCount: opts.phaseResult.steps.length,
      stepsOk: opts.phaseResult.succeeded,
    },
    confirmed,
    candidates: eg.candidates,
    blockers: eg.blockers,
    recommendedNextPhase: opts.phaseResult.recommendedNextPhase
      ?? phasesForObjective(opts.plan.objective as FlowObjective)
        .find((p) => !opts.completedPhases.includes(p) && p !== opts.phase),
    dryRun: !opts.live,
    graphNextActions,
    intelSnippet: opts.intelDigest ?? opts.intelSnippet,
    intelDigest: opts.intelDigest ?? opts.intelSnippet,
    intelArtifactId: opts.intelArtifactId,
    aptTechniques: opts.aptTechniques,
    cacheHit: opts.cacheHit,
    parallelProbes: opts.parallelProbes,
    intelFromMemory: opts.intelFromMemory,
  }
}

export async function runEngagementSlice(opts: {
  target: string
  live: boolean
  scope?: string
  objective?: string
  phase?: AresPhase
  aptHint?: string
}): Promise<EngagementSliceResult> {
  const target = opts.target
  mcpProgress(`engagement_slice: planning ${target}`)

  const hint = opts.aptHint ?? opts.objective ?? target
  const { plan, cacheHit } = buildCachedActionablePlan(target, {
    scope: opts.scope,
    objective: opts.objective,
    aptHint: opts.aptHint,
  })

  const flow = buildFlowProfile(target, opts.scope, hint)
  const { intel, fromMemory } = await resolveIntelWithMemory(target, flow.persona, {
    objective: plan.objective as FlowObjective,
    aptHint: opts.aptHint ?? opts.objective,
    live: opts.live,
    hint,
  })
  const credGraph = CredentialGraph.load()
  const policy = evaluateEngagementPolicy({
    profile: flow,
    objective: plan.objective as FlowObjective,
    live: opts.live,
    credGraph,
    aptHint: opts.aptHint,
  })

  const phase = opts.phase ?? pickFirstPhase(plan, policy.skipPhases)

  const passive = await runPassiveIntel(target, { live: opts.live })
  const passiveHits = passive.enabled ? passive.hits : undefined

  const { phaseResult, graph, credGraph: cg, otHosts, extraBlockers, icsProofs, proximityFindings } = await executeEngagementPhase({
    target,
    phase,
    live: opts.live,
    objective: plan.objective,
    hint,
    aptHint: opts.aptHint,
    scope: opts.scope,
    credGraph,
  })

  const completedPhases = [phase]
  const resumeToken = buildEngagementResumeToken(target, plan.objective, completedPhases)
  saveEngagementState(resumeToken, {
    target,
    scope: opts.scope,
    objective: plan.objective,
    persona: plan.profile.persona,
    completedPhases,
    lastPhase: phase,
    live: opts.live,
    updatedAt: new Date().toISOString(),
  })

  const memory = EngagementMemory.loadForTarget(target)
  memory.setPhase(phase)

  const result = assembleSliceResult({
    target,
    plan,
    phase,
    phaseResult,
    graph,
    otHosts,
    extraBlockers,
    live: opts.live,
    credGraph: cg,
    resumeToken,
    completedPhases,
    icsProofs,
    proximityFindings,
    passiveHits,
    intelDigest: intel.intelDigest,
    intelArtifactId: intel.artifactId,
    aptTechniques: intel.techniques?.map((t) => ({ id: t.id, name: t.name })),
    intelPrefetch: intel,
    cacheHit,
    parallelProbes: countParallelProbes(phaseResult.steps, phase),
    intelFromMemory: fromMemory,
  })
  memory.saveSliceSnapshot(resumeToken, snapshotFromPayload(result as unknown as Record<string, unknown>))
  return result
}

/** Continue multi-turn engagement from resumeToken — skips re-planning. */
export async function runEngagementContinue(opts: {
  resumeToken: string
  phase?: AresPhase
}): Promise<EngagementSliceResult> {
  const state = loadEngagementState(opts.resumeToken)
  if (!state) {
    throw new Error(`engagement resumeToken not found: ${opts.resumeToken}`)
  }

  mcpProgress(`engagement_continue: ${state.target} [${state.completedPhases.join("→")}]`)

  const flow = buildFlowProfile(state.target, state.scope, state.objective)
  const credGraph = CredentialGraph.load()
  const policy = evaluateEngagementPolicy({
    profile: flow,
    objective: state.objective as FlowObjective,
    live: state.live,
    credGraph,
  })

  const phase = pickNextPhase(
    state.objective as FlowObjective,
    state.completedPhases,
    policy.skipPhases,
    opts.phase,
  )

  const plan = buildCachedActionablePlan(state.target, {
    scope: state.scope,
    objective: state.objective,
  }).plan

  const memory = EngagementMemory.loadForTarget(state.target)
  memory.setPhase(phase)

  const graph = new AttackSurfaceGraph(state.target)
  const { phaseResult, graph: updatedGraph, credGraph: cg, otHosts, extraBlockers, icsProofs, proximityFindings } = await executeEngagementPhase({
    target: state.target,
    phase,
    live: state.live,
    objective: state.objective,
    scope: state.scope,
    graph,
    credGraph,
  })

  const completedPhases = state.completedPhases.includes(phase)
    ? state.completedPhases
    : [...state.completedPhases, phase]

  saveEngagementState(opts.resumeToken, {
    ...state,
    completedPhases,
    lastPhase: phase,
    updatedAt: new Date().toISOString(),
  })

  const result = assembleSliceResult({
    target: state.target,
    plan,
    phase,
    phaseResult,
    graph: updatedGraph,
    otHosts,
    extraBlockers,
    live: state.live,
    credGraph: cg,
    resumeToken: opts.resumeToken,
    completedPhases,
    icsProofs,
    proximityFindings,
    cacheHit: true,
    parallelProbes: countParallelProbes(phaseResult.steps, phase),
    intelFromMemory: true,
  })
  memory.saveSliceSnapshot(opts.resumeToken, snapshotFromPayload(result as unknown as Record<string, unknown>))
  return result
}

export default { runEngagementSlice, runEngagementContinue, buildEngagementResumeToken, saveEngagementState, loadEngagementState }
