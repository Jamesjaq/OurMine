/**
 * APT intel feed pipeline tests
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"

describe("apt_intel_feed", () => {
  test("resolveAptProfile matches Volt Typhoon by name", async () => {
    const { resolveAptProfile } = await import("../src/apt_intel_feed.ts")
    const p = resolveAptProfile("Volt Typhoon")
    assert.ok(p)
    assert.equal(p.id, "volt_typhoon")
  })

  test("objectiveFromAptName maps actors to objectives", async () => {
    const { objectiveFromAptName } = await import("../src/apt_intel_feed.ts")
    assert.equal(objectiveFromAptName("Volt Typhoon"), "hybrid_it_ot")
    assert.equal(objectiveFromAptName("Salt Typhoon"), "telecom")
    assert.equal(objectiveFromAptName("Lazarus"), "supply_chain")
  })

  test("loadMitreTechniques returns enterprise + ICS entries", async () => {
    const { loadMitreTechniques } = await import("../src/apt_intel_feed.ts")
    const techs = loadMitreTechniques()
    assert.ok(techs.length >= 10)
    assert.ok(techs.some((t) => t.domain === "ics"))
    assert.ok(techs.some((t) => t.domain === "enterprise"))
  })

  test("getThreatIntel returns compact snippet + artifact for Volt Typhoon", async () => {
    const { getThreatIntel } = await import("../src/apt_intel_feed.ts")
    const r = await getThreatIntel({
      target: "10.0.0.0/24",
      actor: "Volt Typhoon",
      live: false,
      refresh: true,
    })
    assert.ok(r)
    assert.equal(r.profileId, "volt_typhoon")
    assert.equal(r.objectiveHint, "hybrid_it_ot")
    assert.ok(r.intelSnippet.length <= 200)
    assert.ok(r.intelSnippet.includes("Volt Typhoon") || r.intelSnippet.includes("hybrid_it_ot"))
    assert.ok(r.techniques.length >= 3)
    assert.ok(r.modules.includes("edge_audit") || r.modules.includes("iot_scada"))
    assert.ok(r.artifactId.startsWith("apt_intel_"))
  })

  test("buildAptIntelBundle caches to .ourmine/intel/", async () => {
    const { buildAptIntelBundle } = await import("../src/apt_intel_feed.ts")
    await buildAptIntelBundle({ aptHint: "Salt Typhoon", refresh: true, live: false })
    const fp = path.resolve(process.cwd(), ".ourmine/intel/salt_typhoon.json")
    assert.ok(fs.existsSync(fp))
    const cached = JSON.parse(fs.readFileSync(fp, "utf8"))
    assert.equal(cached.profileId, "salt_typhoon")
    assert.ok(Array.isArray(cached.techniques))
  })

  test("preloadTechniquesForPersona returns 3-5 techniques", async () => {
    const { preloadTechniquesForPersona } = await import("../src/apt_intel_feed.ts")
    const techs = preloadTechniquesForPersona({
      persona: "hybrid_it_ot",
      objective: "hybrid_it_ot",
      count: 5,
    })
    assert.ok(techs.length >= 3 && techs.length <= 5)
    assert.ok(techs.every((t) => t.id.startsWith("T")))
  })
})

describe("pentest_plan_builder apt hints", () => {
  test("Volt Typhoon objective routes to hybrid_it_ot", async () => {
    const { buildActionablePlan } = await import("../src/pentest_plan_builder.ts")
    const plan = buildActionablePlan("10.0.0.0/24", { aptHint: "Volt Typhoon" })
    assert.equal(plan.objective, "hybrid_it_ot")
    assert.ok(plan.nextActions.some((a) => a.tool === "ares_dispatch" || a.tool === "ares_engagement_slice"))
  })
})
