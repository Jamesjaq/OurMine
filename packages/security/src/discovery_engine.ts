import * as crypto from "node:crypto"
import { SecurityWorldModel } from "./security_world_model.ts"
import { CapabilityEffectRegistry } from "./capability_effects.ts"
import { HypothesisEngine, type Hypothesis, type RankedExperiment } from "./hypothesis_engine.ts"

export interface ExperimentResult {
  success: boolean
  observations?: string[]
  evidenceIds?: string[]
  error?: string
}

export type ExperimentExecutor = (experiment: RankedExperiment, hypothesis: Hypothesis) => Promise<ExperimentResult>

export interface DiscoveryStep {
  experiment: RankedExperiment
  hypothesis: Hypothesis
  result?: ExperimentResult
  status: "SELECTED" | "SUPPORTED" | "FALSIFIED" | "BLOCKED" | "VERIFICATION_FAILED"
}

export class DiscoveryEngine {
  readonly hypotheses: HypothesisEngine
  private history: DiscoveryStep[] = []
  private attempted = new Set<string>()
  private plannedHypotheses = new Map<string, Hypothesis>()

  readonly world: SecurityWorldModel
  readonly capabilities: CapabilityEffectRegistry

  constructor(world: SecurityWorldModel, capabilities: CapabilityEffectRegistry) {
    this.world = world
    this.capabilities = capabilities
    this.hypotheses = new HypothesisEngine(world, capabilities)
  }

  observe(): void {
    this.world.syncAttackSurface()
  }

  plan(): RankedExperiment[] {
    this.observe()
    const hypotheses = this.hypotheses.generate().map((hypothesis) => this.hypotheses.applyCritique(hypothesis, this.hypotheses.critique(hypothesis)))
    this.plannedHypotheses = new Map(hypotheses.map((hypothesis) => [hypothesis.id, hypothesis]))
    return this.hypotheses.rank(hypotheses).filter((experiment) => !this.attempted.has(experiment.capabilityId))
  }

  async executeNext(executor: ExperimentExecutor): Promise<DiscoveryStep | null> {
    const experiment = this.plan()[0]
    if (!experiment) return null
    this.attempted.add(experiment.capabilityId)
    const hypothesis = this.plannedHypotheses.get(experiment.hypothesisId) ?? {
      id: experiment.hypothesisId,
      premises: [],
      claim: experiment.capabilityId,
      expectedObservations: this.capabilities.get(experiment.capabilityId)?.observableEffects ?? [],
      requiredEvidence: this.capabilities.get(experiment.capabilityId)?.evidenceIds ?? [],
      falsifiers: this.capabilities.get(experiment.capabilityId)?.failureModes ?? [],
      verificationMethods: [],
      confidence: 0.1,
      status: "OPEN",
      alternatives: [],
    }
    if (!experiment.prerequisite.satisfied) {
      const result = { success: false, error: `blocked: ${experiment.prerequisite.missing.join(", ")}` }
      this.capabilities.applyFailure(this.world, experiment.capabilityId, "discovery-planner", result.error)
      const step = { experiment, hypothesis: { ...hypothesis, status: "BLOCKED" }, result, status: "BLOCKED" as const }
      this.history.push(step)
      return step
    }

    let result: ExperimentResult
    try { result = await executor(experiment, hypothesis) } catch (error) { result = { success: false, error: error instanceof Error ? error.message : String(error) } }
    if (!result.success) {
      this.capabilities.applyFailure(this.world, experiment.capabilityId, "discovery-experiment", result.error ?? "experiment failed")
      const step = { experiment, hypothesis: { ...hypothesis, status: "FALSIFIED" }, result, status: "FALSIFIED" as const }
      this.history.push(step)
      return step
    }

    const applied = this.capabilities.applySuccess(this.world, experiment.capabilityId, "discovery-experiment", result.evidenceIds ?? [])
    const expected = hypothesis.expectedObservations
    const observed = new Set([...(result.observations ?? []), ...applied.observations.map((item) => item.fact)])
    const verified = expected.length === 0 || expected.some((item) => observed.has(item))
    const status = verified ? "SUPPORTED" : "VERIFICATION_FAILED"
    const step = { experiment, hypothesis: { ...hypothesis, status: verified ? "SUPPORTED" as const : "FALSIFIED" as const }, result, status }
    this.history.push(step)
    return step
  }

  async run(maxSteps: number, executor: ExperimentExecutor): Promise<DiscoveryStep[]> {
    for (let i = 0; i < maxSteps; i++) {
      const step = await this.executeNext(executor)
      if (!step) break
    }
    return [...this.history]
  }

  historySnapshot(): DiscoveryStep[] { return this.history.map((step) => ({ ...step, experiment: { ...step.experiment }, hypothesis: { ...step.hypothesis }, result: step.result ? { ...step.result } : undefined })) }
  sessionId(): string { return crypto.randomUUID() }
}

export default DiscoveryEngine
