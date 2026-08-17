import test from "node:test"
import assert from "node:assert/strict"
import { SecurityWorldModel } from "../../packages/security/src/security_world_model.ts"
import { CapabilityEffectRegistry } from "../../packages/security/src/capability_effects.ts"
import { DiscoveryEngine } from "../../packages/security/src/discovery_engine.ts"

test("effect graph discovers an unencoded capability composition", () => {
  const registry = new CapabilityEffectRegistry()
  registry.register({ id: "discover-service", namespace: "agent_tools", trusted: true, preconditions: ["scope:authorized"], effects: ["service:observed"], observableEffects: ["service evidence"], failureModes: ["timeout"], rollback: [], evidenceIds: ["p1"], confidence: 0.9 })
  registry.register({ id: "enumerate-service", namespace: "agent_tools", trusted: true, preconditions: ["service:observed"], effects: ["endpoint:observed"], observableEffects: ["endpoint evidence"], failureModes: ["unavailable"], rollback: [], evidenceIds: ["p2"], confidence: 0.8 })
  const composition = registry.discoverCompositions()
  assert.equal(composition.length, 1)
  assert.equal(composition[0].first, "discover-service")
  assert.equal(composition[0].second, "enumerate-service")
})

test("discovery loop verifies success and learns failure", async () => {
  const world = new SecurityWorldModel("authorized.example")
  world.upsertEntity({ kind: "HOST", label: "10.0.0.9", properties: {}, status: "OBSERVED", confidence: 0.9, evidenceIds: [] })
  world.observe("scope", "scope:authorized", "operator", "VERIFIED", 1)
  const registry = new CapabilityEffectRegistry()
  registry.register({ id: "http-probe", namespace: "agent_tools", trusted: true, preconditions: ["scope:authorized"], effects: ["service:observed"], observableEffects: ["HTTP status"], failureModes: ["timeout"], rollback: [], evidenceIds: ["p1"], confidence: 0.9 })
  registry.register({ id: "optional-probe", namespace: "agent_tools", trusted: true, preconditions: ["scope:authorized"], effects: ["optional:observed"], observableEffects: ["optional evidence"], failureModes: ["missing dependency"], rollback: [], evidenceIds: ["p2"], confidence: 0.5 })
  const engine = new DiscoveryEngine(world, registry)
  const first = await engine.executeNext(async () => ({ success: true, observations: ["HTTP status"] }))
  assert.equal(first?.status, "SUPPORTED")
  const second = await engine.executeNext(async () => ({ success: false, error: "missing dependency" }))
  assert.equal(second?.status, "FALSIFIED")
  assert.ok(world.snapshot().observations.some((item) => item.fact.includes("FAILED:")))
})
