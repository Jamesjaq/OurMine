/**
 * Ransomware profile expansion — Phase 1.1
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { loadRansomwareGroups } from "../src/intel_feeds.ts"
import { loadAptPlaybookMappings } from "../src/apt_intel_feed.ts"
import { findUnresolvedModules } from "../src/module_registry.ts"
import { resolveAptProfile } from "../src/apt_intel_feed.ts"

const NEW_GROUPS = [
  "play", "ransomhub", "interlock", "world_leaks", "ghost", "gunra", "nightspire", "inc_ransom",
]

describe("ransomware_profiles", () => {
  test("all 8 new groups exist in ransomware_groups.json", () => {
    const catalog = loadRansomwareGroups()
    for (const id of NEW_GROUPS) {
      const hit = catalog.find((g) => g.id === id)
      assert.ok(hit, `missing group ${id}`)
    }
  })

  test("each new group resolves APT/playbook profile", () => {
    const mappings = loadAptPlaybookMappings()
    for (const id of NEW_GROUPS) {
      assert.ok(mappings[id]?.modules?.length, `missing playbook for ${id}`)
    }
  })

  test("playbook modules resolve via module_registry", () => {
    const mappings = loadAptPlaybookMappings()
    const mods = NEW_GROUPS.flatMap((id) => mappings[id]?.modules ?? [])
    const unresolved = findUnresolvedModules(mods)
    assert.deepEqual(unresolved, [], `unresolved: ${unresolved.join(", ")}`)
  })

  test("RansomHub query returns playbook", () => {
    const profile = resolveAptProfile("RansomHub")
    assert.ok(profile)
    assert.equal(profile.id, "ransomhub")
    const mappings = loadAptPlaybookMappings()
    assert.ok(mappings.ransomhub.modules.includes("edge_audit"))
  })
})
