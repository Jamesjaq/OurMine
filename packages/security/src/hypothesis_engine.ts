import * as crypto from "node:crypto"
import { SecurityWorldModel, type KnowledgeStatus } from "./security_world_model.ts"
import { CapabilityEffectRegistry, type PreconditionsResult } from "./capability_effects.ts"

export type HypothesisStatus = "OPEN" | "SUPPORTED" | "FALSIFIED" | "BLOCKED"

export interface Hypothesis {
  id: string
  premises: string[]
  claim: string
  expectedObservations: string[]
  requiredEvidence: string[]
  falsifiers: string[]
  verificationMethods: string[]
  confidence: number
  status: HypothesisStatus
  alternatives: string[]
}

export interface RankedExperiment {
  id: string
  hypothesisId: string
  capabilityId: string
  score: number
  informationGain: number
  reversibility: number
  risk: number
  cost: number
  prerequisite: PreconditionsResult
  reason: string
}

export interface Critique {
  hypothesisId: string
  supported: boolean
  issues: string[]
  alternatives: string[]
  falsificationTests: string[]
}

const uid = (prefix: string) => `${prefix}_${crypto.randomUUID()}`

export class HypothesisEngine {
  private readonly world: SecurityWorldModel
  private readonly capabilities: CapabilityEffectRegistry

  constructor(world: SecurityWorldModel, capabilities: CapabilityEffectRegistry) {
    this.world = world
    this.capabilities = capabilities
  }

  generate(): Hypothesis[] {
    const snapshot = this.world.snapshot()
    const uncertain = this.world.uncertainties()
    const hypotheses: Hypothesis[] = []
    for (const entity of snapshot.entities.filter((item) => item.status === "OBSERVED" || item.status === "INFERRED")) {
      for (const capability of this.capabilities.all()) {
        const missing = capability.preconditions.filter((fact) => !snapshot.observations.some((observation) => observation.fact === fact))
        const premise = missing.length ? `${entity.label} may satisfy ${missing.join(", ")}` : `${entity.label} satisfies ${capability.preconditions.join(", ") || "the capability scope"}`
        hypotheses.push({
          id: uid("hyp"),
          premises: [premise, ...uncertain.slice(0, 2).map((item) => "id" in item ? item.id : "")].filter(Boolean),
          claim: `${capability.id} may produce ${capability.effects.join(", ") || "a measurable security observation"} for ${entity.label}`,
          expectedObservations: capability.observableEffects,
          requiredEvidence: capability.evidenceIds,
          falsifiers: capability.failureModes,
          verificationMethods: capability.rollback.length ? [`execute ${capability.id} with rollback`] : [`execute ${capability.id} and independently verify output`],
          confidence: Math.max(0.05, Math.min(0.95, capability.confidence * (missing.length ? 0.45 : 0.8))),
          status: "OPEN",
          alternatives: [`The observed state on ${entity.label} may have an alternative explanation`, `The prerequisite may be present but not observable through current evidence`],
        })
      }
    }
    return hypotheses
  }

  rank(hypotheses: Hypothesis[]): RankedExperiment[] {
    return hypotheses.flatMap((hypothesis) => {
      const capability = this.capabilities.all().find((item) => hypothesis.claim.startsWith(item.id))
      if (!capability) return []
      const prerequisite = this.capabilities.checkPreconditions(this.world, capability.id)
      const informationGain = Math.min(1, (hypothesis.expectedObservations.length + hypothesis.falsifiers.length + hypothesis.alternatives.length) / 6)
      const reversibility = capability.rollback.length ? 1 : 0.55
      const risk = capability.rollback.length ? 0.1 : 0.35
      const cost = Math.min(1, 0.1 + capability.preconditions.length * 0.15)
      const score = (informationGain * 0.4) + (hypothesis.confidence * 0.25) + (reversibility * 0.2) + ((1 - risk) * 0.1) + ((1 - cost) * 0.05) - (prerequisite.satisfied ? 0 : 0.25)
      return [{ id: uid("exp"), hypothesisId: hypothesis.id, capabilityId: capability.id, score, informationGain, reversibility, risk, cost, prerequisite, reason: prerequisite.satisfied ? "high information gain with satisfied prerequisites" : `blocked by ${prerequisite.missing.join(", ")}` }]
    }).sort((a, b) => b.score - a.score)
  }

  critique(hypothesis: Hypothesis): Critique {
    const issues: string[] = []
    const alternatives = [...hypothesis.alternatives]
    if (hypothesis.requiredEvidence.length === 0) issues.push("hypothesis has no provenance requirements")
    if (hypothesis.expectedObservations.length === 0) issues.push("hypothesis has no observable consequence")
    if (hypothesis.confidence > 0.8 && alternatives.length === 0) issues.push("confidence is high without competing explanation")
    const falsificationTests = hypothesis.falsifiers.length ? hypothesis.falsifiers.map((f) => `check absence or presence of: ${f}`) : ["repeat with independent evidence source"]
    return { hypothesisId: hypothesis.id, supported: issues.length === 0, issues, alternatives, falsificationTests }
  }

  applyCritique(hypothesis: Hypothesis, critique: Critique): Hypothesis {
    return { ...hypothesis, status: critique.supported ? "OPEN" : "BLOCKED", confidence: critique.supported ? hypothesis.confidence : Math.min(hypothesis.confidence, 0.35) }
  }
}

export default HypothesisEngine
