/**
 * @module engagement_cache
 * Precomputed persona playbooks — load once per persona/objective, slice reuses cache.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { ensureAresDir } from "./ares/_base.ts"
import type { AresPhase } from "./mcp_efficiency.ts"
import type { ActionablePlan } from "./pentest_plan_builder.ts"
import { buildActionablePlan } from "./pentest_plan_builder.ts"
import type { FlowObjective, TargetPersona } from "./target_flow.ts"
import { buildFlowProfile } from "./target_flow.ts"
import { profileForPersona, preloadTechniquesForPersona } from "./apt_intel_feed.ts"

const CACHE_DIR = ensureAresDir("cache")

export interface PersonaPlaybookCache {
  key: string
  persona: TargetPersona
  objective: FlowObjective
  recommendedPhases: AresPhase[]
  workflow: string
  profileId?: string
  intelSnippet: string
  techniqueIds: string[]
  modulePriorities: string[]
  gaps: string[]
  cachedAt: string
}

function cacheKey(persona: TargetPersona, objective: FlowObjective): string {
  return `${persona}__${objective}`.replace(/[^a-zA-Z0-9._-]/g, "_")
}

function cachePath(key: string): string {
  return path.join(CACHE_DIR, `${key}.json`)
}

export function readPlaybookCache(persona: TargetPersona, objective: FlowObjective): PersonaPlaybookCache | null {
  const fp = cachePath(cacheKey(persona, objective))
  if (!fs.existsSync(fp)) return null
  try {
    return JSON.parse(fs.readFileSync(fp, "utf8")) as PersonaPlaybookCache
  } catch {
    return null
  }
}

export function writePlaybookCache(entry: PersonaPlaybookCache): string {
  const fp = cachePath(entry.key)
  fs.writeFileSync(fp, JSON.stringify(entry, null, 2))
  return fp
}

/** Warm cache from a full plan + optional intel — called once per persona/objective pair. */
export function warmPlaybookCache(opts: {
  persona: TargetPersona
  objective: FlowObjective
  plan: ActionablePlan
  intelSnippet?: string
  profileId?: string
}): PersonaPlaybookCache {
  const key = cacheKey(opts.persona, opts.objective)
  const profile = profileForPersona(opts.persona, opts.objective)
  const techniques = preloadTechniquesForPersona({
    persona: opts.persona,
    objective: opts.objective,
    count: 5,
  })

  const entry: PersonaPlaybookCache = {
    key,
    persona: opts.persona,
    objective: opts.objective,
    recommendedPhases: opts.plan.recommendedPhases,
    workflow: opts.plan.workflow,
    profileId: opts.profileId ?? profile?.id,
    intelSnippet: opts.intelSnippet ?? `[${opts.objective}] ${techniques.map((t) => t.id).join("→")}`.slice(0, 200),
    techniqueIds: techniques.map((t) => t.id),
    modulePriorities: opts.plan.nextActions.map((a) => a.tool).slice(0, 8),
    gaps: opts.plan.gaps ?? [],
    cachedAt: new Date().toISOString(),
  }

  writePlaybookCache(entry)
  return entry
}

/** Get or build persona playbook cache (disk-backed, process-local warm). */
export function getPersonaPlaybook(
  persona: TargetPersona,
  objective: FlowObjective,
  target = "placeholder.local",
): PersonaPlaybookCache {
  const cached = readPlaybookCache(persona, objective)
  if (cached) return cached

  const plan = buildActionablePlan(target, { objective })
  return warmPlaybookCache({ persona, objective, plan })
}

/** Merge cached playbook into a target-specific plan — skips PTT rebuild for static fields. */
export function applyPlaybookCache(plan: ActionablePlan, cache: PersonaPlaybookCache): ActionablePlan {
  return {
    ...plan,
    recommendedPhases: cache.recommendedPhases.length ? cache.recommendedPhases : plan.recommendedPhases,
    workflow: cache.workflow || plan.workflow,
    gaps: [...new Set([...(plan.gaps ?? []), ...cache.gaps])],
  }
}

/** One-call: build plan with persona cache overlay. */
export function buildCachedActionablePlan(
  target: string,
  opts: { scope?: string; objective?: string; aptHint?: string } = {},
): { plan: ActionablePlan; cache: PersonaPlaybookCache; cacheHit: boolean } {
  const hint = opts.aptHint ?? opts.objective ?? target
  const flow = buildFlowProfile(target, opts.scope, hint)
  const plan = buildActionablePlan(target, opts)
  const cached = readPlaybookCache(flow.persona, plan.objective as FlowObjective)
  if (cached) {
    return { plan: applyPlaybookCache(plan, cached), cache: cached, cacheHit: true }
  }
  const warmed = warmPlaybookCache({
    persona: flow.persona,
    objective: plan.objective as FlowObjective,
    plan,
  })
  return { plan: applyPlaybookCache(plan, warmed), cache: warmed, cacheHit: false }
}

export default {
  readPlaybookCache,
  writePlaybookCache,
  warmPlaybookCache,
  getPersonaPlaybook,
  applyPlaybookCache,
  buildCachedActionablePlan,
}
