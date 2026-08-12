/**
 * Engagement memory — cross-turn intel dedup + .ourmine/ares/memory/ persistence
 */
import { describe, test, beforeEach, afterEach } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"
import { EngagementMemory, intelCacheKey } from "../src/engagement_memory.ts"

const TEST_TARGET = "mem-test.corp.example.com"
const TEST_DIR = path.resolve(process.cwd(), ".ourmine/ares/memory")

describe("engagement_memory", () => {
  beforeEach(() => {
    const safe = TEST_TARGET.replace(/[^a-zA-Z0-9._-]/g, "_")
    const fp = path.join(TEST_DIR, `engagement_${safe}.json`)
    if (fs.existsSync(fp)) fs.unlinkSync(fp)
  })

  test("persists under .ourmine/ares/memory/", () => {
    const mem = EngagementMemory.loadForTarget(TEST_TARGET, TEST_DIR)
    mem.recordDecision("phase", "recon")
    mem.save()
    const fp = path.join(TEST_DIR, `engagement_${TEST_TARGET.replace(/[^a-zA-Z0-9._-]/g, "_")}.json`)
    assert.ok(fs.existsSync(fp))
    const reloaded = EngagementMemory.loadForTarget(TEST_TARGET, TEST_DIR)
    assert.equal(reloaded.getDecision("phase"), "recon")
  })

  test("markIntelRead prevents re-read", () => {
    const mem = EngagementMemory.loadForTarget(TEST_TARGET, TEST_DIR)
    const id = intelCacheKey("scattered_spider", "enterprise_ad", "identity_first")
    assert.equal(mem.hasReadIntel(id), false)
    mem.markIntelRead(id, "Scattered Spider: T1566→T1078", "scattered_spider")
    assert.equal(mem.hasReadIntel(id), true)
    assert.ok(mem.getIntelSnippet(id).includes("Scattered Spider"))
  })

  test("registerHostRef returns stable refs", () => {
    const mem = EngagementMemory.loadForTarget(TEST_TARGET, TEST_DIR)
    const r1 = mem.registerHostRef("dc01.corp.example.com")
    const r2 = mem.registerHostRef("dc01.corp.example.com")
    assert.equal(r1, r2)
    assert.match(r1, /^@h\d+$/)
    assert.equal(mem.resolveHostRef(r1), "dc01.corp.example.com")
  })

  test("saveSliceSnapshot round-trips for delta continue", () => {
    const mem = EngagementMemory.loadForTarget(TEST_TARGET, TEST_DIR)
    const snap = { cf: 2, cd: 5, bk: 1, ph: "recon", ok: "4/6" }
    mem.saveSliceSnapshot("eng_test123", snap)
    assert.deepEqual(mem.getSliceSnapshot("eng_test123"), snap)
    assert.equal(mem.getSliceSnapshot("eng_other"), undefined)
  })
})
