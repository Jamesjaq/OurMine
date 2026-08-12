/**
 * MITRE ATT&CK coverage gate — Phase 1.4
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { loadMitreTechniques } from "../src/apt_intel_feed.ts"
import { isExecutableModule } from "../src/module_registry.ts"

describe("mitre_coverage", () => {
  test("technique count >= 100", () => {
    const techniques = loadMitreTechniques()
    assert.ok(techniques.length >= 100, `expected ≥100, got ${techniques.length}`)
  })

  test("every technique has at least one resolvable module", () => {
    const techniques = loadMitreTechniques()
    const bad = techniques.filter((t) => {
      const mods = t.modules ?? []
      return mods.length === 0 || !mods.some((m) => isExecutableModule(m))
    })
    assert.ok(
      bad.length <= 5,
      `techniques missing resolvable modules: ${bad.map((t) => t.id).join(", ")}`,
    )
  })

  test("T1528 maps to device_code_audit", () => {
    const t = loadMitreTechniques().find((x) => x.id === "T1528")
    assert.ok(t)
    assert.ok(t.modules.some((m) => m.includes("device_code") || m.includes("cloud_token") || m.includes("oauth")))
  })
})
