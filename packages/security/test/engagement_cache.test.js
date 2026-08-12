/**
 * Persona playbook cache — load once, slice reuses
 */
import { describe, test, beforeEach } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"
import {
  buildCachedActionablePlan,
  getPersonaPlaybook,
  readPlaybookCache,
} from "../src/engagement_cache.ts"
import { buildFlowProfile } from "../src/target_flow.ts"
import { ensureAresDir } from "../src/ares/_base.ts"

const CACHE_DIR = ensureAresDir("cache")

describe("engagement_cache", () => {
  beforeEach(() => {
    const flow = buildFlowProfile("corp.example.com")
    const key = `${flow.persona}__identity_first`.replace(/[^a-zA-Z0-9._-]/g, "_")
    const fp = path.join(CACHE_DIR, `${key}.json`)
    if (fs.existsSync(fp)) fs.unlinkSync(fp)
  })

  test("warm + hit playbook cache for enterprise AD persona", () => {
    const flow = buildFlowProfile("corp.example.com")
    const first = buildCachedActionablePlan("corp-cache-test.example.com", { objective: "identity_first" })
    assert.equal(first.cacheHit, false)
    assert.ok(first.cache.intelSnippet.length > 0)
    assert.ok(first.plan.recommendedPhases.length >= 2)

    const second = buildCachedActionablePlan("corp-cache-test2.example.com", { objective: "identity_first" })
    assert.equal(second.cacheHit, true)
    assert.equal(second.cache.persona, flow.persona)
  })

  test("getPersonaPlaybook returns disk-backed entry", () => {
    const flow = buildFlowProfile("corp.example.com")
    const cache = getPersonaPlaybook(flow.persona, "standard", "corp.example.com")
    const loaded = readPlaybookCache(flow.persona, "standard")
    assert.ok(loaded)
    assert.equal(loaded.key, cache.key)
    assert.ok(Array.isArray(loaded.techniqueIds))
  })
})
