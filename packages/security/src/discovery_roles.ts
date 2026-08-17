import { CapabilityEffectRegistry } from "./capability_effects.ts"
import { DiscoveryEngine, type ExperimentExecutor, type ExperimentResult, type DiscoveryStep } from "./discovery_engine.ts"
import { HypothesisEngine, type Hypothesis, type RankedExperiment, type Critique } from "./hypothesis_engine.ts"
import { SecurityWorldModel } from "./security_world_model.ts"

export class ReconAnalyst {
  private readonly hypotheses: HypothesisEngine
  constructor(hypotheses: HypothesisEngine) { this.hypotheses = hypotheses }
  generateHypotheses(): Hypothesis[] { return this.hypotheses.generate() }
}

export class InvestigationPlanner {
  private readonly hypotheses: HypothesisEngine
  constructor(hypotheses: HypothesisEngine) { this.hypotheses = hypotheses }
  rank(hypotheses: Hypothesis[]): RankedExperiment[] { return this.hypotheses.rank(hypotheses) }
}

export class HypothesisCritic {
  private readonly hypotheses: HypothesisEngine
  constructor(hypotheses: HypothesisEngine) { this.hypotheses = hypotheses }
  critique(hypothesis: Hypothesis): Critique { return this.hypotheses.critique(hypothesis) }
}

export class ControlledExperimenter {
  private readonly discovery: DiscoveryEngine
  constructor(discovery: DiscoveryEngine) { this.discovery = discovery }
  execute(executor: ExperimentExecutor): Promise<DiscoveryStep | null> { return this.discovery.executeNext(executor) }
}

export class IndependentVerifier {
  verify(step: DiscoveryStep): { verified: boolean; reason: string } {
    if (!step.result?.success) return { verified: false, reason: step.result?.error ?? "experiment failed" }
    const expected = step.hypothesis.expectedObservations
    const observed = new Set(step.result.observations ?? [])
    const verified = expected.length === 0 || expected.some((item) => observed.has(item))
    return { verified, reason: verified ? "independent expected observation present" : "expected observation absent" }
  }
}

export class DiscoveryOrchestrator {
  readonly analyst: ReconAnalyst
  readonly planner: InvestigationPlanner
  readonly critic: HypothesisCritic
  readonly experimenter: ControlledExperimenter
  readonly verifier = new IndependentVerifier()

  readonly world: SecurityWorldModel
  readonly capabilities: CapabilityEffectRegistry

  constructor(world: SecurityWorldModel, capabilities: CapabilityEffectRegistry) {
    this.world = world
    this.capabilities = capabilities
    const hypotheses = new HypothesisEngine(world, capabilities)
    const discovery = new DiscoveryEngine(world, capabilities)
    this.analyst = new ReconAnalyst(hypotheses)
    this.planner = new InvestigationPlanner(hypotheses)
    this.critic = new HypothesisCritic(hypotheses)
    this.experimenter = new ControlledExperimenter(discovery)
  }

  async run(executor: (experiment: RankedExperiment, hypothesis: Hypothesis) => Promise<ExperimentResult>, maxSteps = 1): Promise<DiscoveryStep[]> {
    const steps: DiscoveryStep[] = []
    for (let i = 0; i < maxSteps; i++) {
      const step = await this.experimenter.execute(executor)
      if (!step) break
      const independent = this.verifier.verify(step)
      steps.push({ ...step, status: independent.verified ? "SUPPORTED" : step.status === "SUPPORTED" ? "VERIFICATION_FAILED" : step.status })
    }
    return steps
  }
}

export default DiscoveryOrchestrator
