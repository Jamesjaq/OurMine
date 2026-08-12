/**
 * Intel cache freshness tests — Phase 0
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

const CACHE = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel/cache",
)

describe("intel_cache_freshness", () => {
  test("cache/ransomwatch.json has 100+ records", async () => {
    const posts = JSON.parse(fs.readFileSync(path.join(CACHE, "ransomwatch.json"), "utf8"))
    assert.ok(Array.isArray(posts))
    assert.ok(posts.length > 100, `expected >100 posts, got ${posts.length}`)
  })

  test("offline fetchRansomwatch returns 100+ records", async () => {
    const { fetchRansomwatch } = await import("../src/intel_feeds.ts")
    const records = await fetchRansomwatch(false)
    assert.ok(records.length > 100, `expected >100 records, got ${records.length}`)
  })

  test("latest discovered is after 2025-01-01 when cache refreshed", () => {
    const meta = JSON.parse(fs.readFileSync(path.join(CACHE, "_meta.json"), "utf8"))
    const latest = meta.ransomwatch?.latestDiscovered
    assert.ok(latest, "missing latestDiscovered in _meta.json")
    assert.ok(latest >= "2025-01-01", `stale latestDiscovered: ${latest}`)
  })

  test("intelStalenessWarning emits when cache age exceeds TTL", async () => {
    const { intelStalenessWarning } = await import("../src/intel_autonomous.ts")
    const metaPath = path.join(CACHE, "_meta.json")
    const orig = fs.readFileSync(metaPath, "utf8")
    try {
      const stale = JSON.parse(orig)
      stale.ransomwatch.cachedAt = "2020-01-01T00:00:00Z"
      stale.ransomwatch.ttlDays = 7
      fs.writeFileSync(metaPath, JSON.stringify(stale, null, 2))
      const warn = intelStalenessWarning()
      assert.ok(warn?.includes("INTEL_STALE"), warn)
    } finally {
      fs.writeFileSync(metaPath, orig)
    }
  })
})
