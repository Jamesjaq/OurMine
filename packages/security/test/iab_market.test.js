/**
 * IAB market schema tests — Phase 1.2
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  loadIabMarket,
  matchStealerPattern,
  iabHandoffPlaybook,
  iabModulesForHint,
} from "../src/iab_intel.ts"

describe("iab_market", () => {
  test("loadIabMarket returns schema v1 with chain stages", () => {
    const m = loadIabMarket()
    assert.equal(m.schemaVersion, 1)
    assert.ok(m.chainStages.length >= 3)
    assert.ok(m.stealerToAccessPatterns.length >= 2)
  })

  test("matchStealerPattern matches session_cookie artifacts", () => {
    const hits = matchStealerPattern(["session_cookie", "vpn_portal"])
    assert.ok(hits.some((h) => h.id === "cookie_vpn_pivot"))
  })

  test("iabHandoffPlaybook returns sylvanite paired actor", () => {
    const pb = iabHandoffPlaybook("sylvanite")
    assert.ok(pb.broker)
    assert.equal(pb.pairedActor, "voltzite")
    assert.ok(pb.modules.includes("ot_batch_scan"))
    assert.ok(pb.artifactId?.startsWith("iab_handoff_"))
  })

  test('hint "stealer log vpn" prioritizes citrix_audit + edge_audit', () => {
    const mods = iabModulesForHint("stealer log vpn portal")
    assert.ok(mods.includes("citrix_audit"))
    assert.ok(mods.includes("edge_audit"))
  })
})
