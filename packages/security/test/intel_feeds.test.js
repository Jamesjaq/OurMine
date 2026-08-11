import test from "node:test"
import assert from "node:assert"

test("loadCvePriority returns hot CVE entries", async () => {
  const { loadCvePriority, loadVxFamilyIndex } = await import("../src/intel_feeds.ts")
  const cves = loadCvePriority()
  assert.ok(cves.length >= 3)
  assert.ok(cves.every((c) => c.cve.startsWith("CVE-")))
  assert.ok(cves.every((c) => Array.isArray(c.tools) && c.tools.length > 0))

  const families = loadVxFamilyIndex()
  assert.ok(families.length >= 3)
  assert.ok(families.some((f) => f.ruleset))
})

test("enrichTarget builds intel brief (dry-run)", async () => {
  const { enrichTarget } = await import("../src/intel_feeds.ts")
  const brief = await enrichTarget("example.com", { live: false })
  assert.strictEqual(brief.host, "example.com")
  assert.ok(brief.activeProfiles.length >= 1)
  assert.ok(brief.priorityCves.length >= 1)
  assert.ok(brief.records.length >= 1)
  assert.ok(Array.isArray(brief.recommendedTools))
})

test("watchOrg tracks domains", async () => {
  const { watchOrg } = await import("../src/intel_feeds.ts")
  const result = watchOrg("Acme Corp", ["acme.com", "api.acme.com"])
  assert.ok(result.records.length >= 2)
  assert.ok(result.hits.length >= 1)
})

test("lookupVxFamily resolves family metadata", async () => {
  const { lookupVxFamily, loadVxFamilyIndex } = await import("../src/intel_feeds.ts")
  const first = loadVxFamilyIndex()[0]
  assert.ok(first)
  const hit = lookupVxFamily(first.family)
  assert.ok(hit)
  assert.strictEqual(hit?.family, first.family)
})

test("pollFeeds returns records in dry-run", async () => {
  const { pollFeeds } = await import("../src/intel_feeds.ts")
  const records = await pollFeeds({ live: false })
  assert.ok(records.length >= 1)
  assert.ok(records.some((r) => r.type === "cve"))
})

test("injectIntelIntoGraph adds notes", async () => {
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const { enrichTarget, injectIntelIntoGraph } = await import("../src/intel_feeds.ts")
  const graph = new AttackSurfaceGraph("example.com")
  const brief = await enrichTarget("example.com", { live: false })
  injectIntelIntoGraph(graph, brief)
  const asset = graph.upsertAsset("example.com")
  assert.ok(asset.notes.some((n) => n.includes("[INTEL]")))
})
