/**
 * Extortion-only mode — Phase 3.1
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  applyExtortionMode,
  extortionModeForGroup,
  shouldSkipDestructiveRaas,
} from "../src/extortion_mode.ts"
import { evaluateEngagementPolicy } from "../src/engagement_policy.ts"
import { buildFlowProfile } from "../src/target_flow.ts"

describe("extortion_mode", () => {
  test("applyExtortionMode strips destructive raas modules", () => {
    const mods = ["raas_leak_catalog", "raas_vss_wipe", "raas_esxi_encrypt", "collection_engine"]
    const filtered = applyExtortionMode(mods, {
      enabled: true,
      skipEncrypt: true,
      catalogOnly: true,
      publishSimulation: true,
    })
    assert.ok(!filtered.includes("raas_vss_wipe"))
    assert.ok(!filtered.includes("raas_esxi_encrypt"))
    assert.ok(filtered.includes("raas_leak_catalog"))
  })

  test("world_leaks group triggers extortion-only", () => {
    const cfg = extortionModeForGroup("world_leaks")
    assert.equal(cfg.enabled, true)
    assert.ok(shouldSkipDestructiveRaas(cfg))
  })

  test("engagement policy skips encrypt modules for interlock hint", () => {
    const profile = buildFlowProfile("corp.example.com", undefined, "interlock extortion")
    const policy = evaluateEngagementPolicy({
      profile,
      objective: "extortion_only",
      live: false,
      aptHint: "interlock",
    })
    assert.ok(policy.skipModules.includes("raas_esxi_encrypt"))
  })
})
