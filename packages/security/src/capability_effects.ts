import { SecurityWorldModel, type CapabilityContract, type WorldObservation } from "./security_world_model.ts"

export interface CapabilityEffectDefinition {
  id: string
  namespace: string
  trusted: boolean
  preconditions: string[]
  effects: string[]
  observableEffects: string[]
  failureModes: string[]
  rollback: string[]
  evidenceIds: string[]
  confidence: number
}

export interface PreconditionsResult {
  satisfied: boolean
  missing: string[]
}

export interface EffectApplicationResult {
  capabilityId: string
  applied: string[]
  observations: WorldObservation[]
}

export interface CapabilityComposition {
  first: string
  second: string
  bridgeEffects: string[]
  rationale: string
}

function hasFact(model: SecurityWorldModel, fact: string): boolean {
  return model.snapshot().observations.some((observation) => observation.fact === fact && observation.status !== "REJECTED")
    || model.snapshot().entities.some((entity) => entity.label === fact || Object.values(entity.properties).includes(fact))
}

export class CapabilityEffectRegistry {
  private definitions = new Map<string, CapabilityEffectDefinition>()

  register(definition: CapabilityEffectDefinition): void {
    if (!definition.trusted) throw new Error(`Capability ${definition.id} is not trusted`)
    if (definition.evidenceIds.length === 0) throw new Error(`Capability ${definition.id} has no proof evidence`)
    this.definitions.set(definition.id, { ...definition, preconditions: [...definition.preconditions], effects: [...definition.effects], observableEffects: [...definition.observableEffects], failureModes: [...definition.failureModes], rollback: [...definition.rollback] })
  }

  registerTrusted(contract: CapabilityContract, definition: Omit<CapabilityEffectDefinition, "id" | "namespace" | "trusted" | "evidenceIds" | "confidence">): void {
    if (contract.status !== "TRUSTED_PRIMITIVE") throw new Error(`Capability ${contract.id} is not trusted`)
    this.register({ ...definition, id: contract.id, namespace: contract.namespace, trusted: true, evidenceIds: contract.evidenceIds, confidence: contract.confidence })
  }

  get(id: string): CapabilityEffectDefinition | undefined { return this.definitions.get(id) }
  all(): CapabilityEffectDefinition[] { return [...this.definitions.values()] }

  discoverCompositions(): CapabilityComposition[] {
    const definitions = this.all()
    const compositions: CapabilityComposition[] = []
    for (const first of definitions) {
      for (const second of definitions) {
        if (first.id === second.id) continue
        const bridgeEffects = first.effects.filter((effect) => second.preconditions.includes(effect))
        if (bridgeEffects.length) compositions.push({ first: first.id, second: second.id, bridgeEffects, rationale: `${first.id} produces ${bridgeEffects.join(", ")}, satisfying a prerequisite of ${second.id}` })
      }
    }
    return compositions
  }

  checkPreconditions(model: SecurityWorldModel, capabilityId: string): PreconditionsResult {
    const definition = this.definitions.get(capabilityId)
    if (!definition) return { satisfied: false, missing: [`unknown capability: ${capabilityId}`] }
    const missing = definition.preconditions.filter((precondition) => !hasFact(model, precondition))
    return { satisfied: missing.length === 0, missing }
  }

  applySuccess(model: SecurityWorldModel, capabilityId: string, source: string, evidenceIds: string[] = []): EffectApplicationResult {
    const definition = this.definitions.get(capabilityId)
    if (!definition) throw new Error(`unknown capability: ${capabilityId}`)
    const preconditions = this.checkPreconditions(model, capabilityId)
    if (!preconditions.satisfied) throw new Error(`preconditions unsatisfied for ${capabilityId}: ${preconditions.missing.join(", ")}`)
    const observations = definition.effects.map((effect) => model.observe(capabilityId, effect, source, "VERIFIED", definition.confidence, []))
    return { capabilityId, applied: [...definition.effects], observations }
  }

  applyFailure(model: SecurityWorldModel, capabilityId: string, source: string, reason: string): WorldObservation {
    const definition = this.definitions.get(capabilityId)
    if (!definition) throw new Error(`unknown capability: ${capabilityId}`)
    return model.observe(capabilityId, `FAILED: ${reason}`, source, "REJECTED", Math.min(definition.confidence, 0.5), [])
  }
}

export default CapabilityEffectRegistry
