/**
 * IAB handoff simulation — Phase 3.2
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { runIabChain, applyIabChainToGraph } from "../src/iab_handoff_sim.ts"
import { CredentialGraph } from "../src/credential_graph.ts"
import { runBridgedModule } from "../src/module_bridge.ts"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"

function bridgeCtx(live = false) {
  return { target: "corp.example.com", live, graph: new AttackSurfaceGraph("corp.example.com") }
}

describe("iab_handoff_sim", () => {
  test("runIabChain produces 3 staged evidence items", () => {
    const chain = runIabChain("corp.example.com", ["session_cookie"])
    assert.equal(chain.stages.length, 3)
    assert.ok(chain.stages[0].stage === "stealer_log")
    assert.ok(chain.artifactId.startsWith("iab_handoff_sim_"))
    assert.ok(chain.stages.every((s) => s.synthetic))
  })

  test("applyIabChainToGraph adds stealer_log credentials", () => {
    const graph = new CredentialGraph()
    const chain = runIabChain("vpn.corp.example.com")
    const n = applyIabChainToGraph(graph, chain)
    assert.ok(n >= 3)
    const pivots = graph.iabPivotCandidates()
    assert.ok(pivots.some((c) => c.source === "stealer_log"))
    assert.ok(pivots.some((c) => c.source === "iab_market"))
  })

  test("bridge module returns compact payload", async () => {
    const r = await runBridgedModule(bridgeCtx(), "iab_handoff_sim", { target: "corp.example.com" })
    assert.ok(r?.success)
    assert.ok(r.output.length <= 8000)
  })
})
