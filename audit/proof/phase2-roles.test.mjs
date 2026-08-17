import test from 'node:test'
import assert from 'node:assert/strict'
import { SecurityWorldModel } from '../../packages/security/src/security_world_model.ts'
import { CapabilityEffectRegistry } from '../../packages/security/src/capability_effects.ts'
import { DiscoveryOrchestrator } from '../../packages/security/src/discovery_roles.ts'

test('separated discovery roles plan, criticize, execute, and independently verify', async () => {
  const world = new SecurityWorldModel('authorized.example')
  world.upsertEntity({ kind: 'HOST', label: '10.0.0.20', properties: {}, status: 'OBSERVED', confidence: 0.8, evidenceIds: [] })
  world.observe('scope', 'scope:authorized', 'operator', 'VERIFIED', 1)
  const capabilities = new CapabilityEffectRegistry()
  capabilities.register({ id: 'safe-probe', namespace: 'agent_tools', trusted: true, preconditions: ['scope:authorized'], effects: ['probe:complete'], observableEffects: ['probe evidence'], failureModes: ['timeout'], rollback: ['close'], evidenceIds: ['proof'], confidence: 0.9 })
  const team = new DiscoveryOrchestrator(world, capabilities)
  assert.equal(team.analyst.generateHypotheses().length, 1)
  const steps = await team.run(async () => ({ success: true, observations: ['probe evidence'] }))
  assert.equal(steps.length, 1)
  assert.equal(steps[0].status, 'SUPPORTED')
  assert.equal(team.verifier.verify(steps[0]).verified, true)
})
