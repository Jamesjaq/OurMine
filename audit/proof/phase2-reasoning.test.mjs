import test from 'node:test'
import assert from 'node:assert/strict'
import { SecurityWorldModel } from '../../packages/security/src/security_world_model.ts'
import { CapabilityEffectRegistry } from '../../packages/security/src/capability_effects.ts'
import { HypothesisEngine } from '../../packages/security/src/hypothesis_engine.ts'

test('effect registry applies only after a real prerequisite and records effects', () => {
  const world = new SecurityWorldModel('authorized.example')
  const registry = new CapabilityEffectRegistry()
  registry.register({ id: 'http-probe', namespace: 'agent_tools', trusted: true, preconditions: ['scope:authorized'], effects: ['service:https:observed'], observableEffects: ['HTTP status'], failureModes: ['timeout'], rollback: [], evidenceIds: ['proof-1'], confidence: 0.9 })
  assert.equal(registry.checkPreconditions(world, 'http-probe').satisfied, false)
  world.observe('scope', 'scope:authorized', 'operator', 'VERIFIED', 1)
  assert.equal(registry.checkPreconditions(world, 'http-probe').satisfied, true)
  const applied = registry.applySuccess(world, 'http-probe', 'http probe')
  assert.deepEqual(applied.applied, ['service:https:observed'])
})

test('hypothesis engine produces competing ranked investigations and a critique', () => {
  const world = new SecurityWorldModel('authorized.example')
  world.upsertEntity({ kind: 'HOST', label: '10.0.0.5', properties: {}, status: 'OBSERVED', confidence: 0.9, evidenceIds: [] })
  world.observe('scope', 'scope:authorized', 'operator', 'VERIFIED', 1)
  const registry = new CapabilityEffectRegistry()
  registry.register({ id: 'http-probe', namespace: 'agent_tools', trusted: true, preconditions: ['scope:authorized'], effects: ['service:https:observed'], observableEffects: ['HTTP status'], failureModes: ['timeout'], rollback: [], evidenceIds: ['proof-1'], confidence: 0.9 })
  registry.register({ id: 'header-probe', namespace: 'agent_tools', trusted: true, preconditions: ['scope:authorized'], effects: ['header:observed'], observableEffects: ['header value'], failureModes: ['timeout'], rollback: ['close'], evidenceIds: ['proof-2'], confidence: 0.7 })
  const engine = new HypothesisEngine(world, registry)
  const hypotheses = engine.generate()
  const ranked = engine.rank(hypotheses)
  assert.equal(hypotheses.length, 2)
  assert.equal(ranked.length, 2)
  assert.ok(ranked[0].score >= ranked[1].score)
  const critique = engine.critique(hypotheses[0])
  assert.equal(critique.supported, true)
})
