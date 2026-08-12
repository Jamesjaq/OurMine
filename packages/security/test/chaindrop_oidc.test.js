/**
 * ChainDrop OIDC CI supply chain — Phase 2.2
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { auditChainDropOidc } from "../src/chaindrop_oidc.ts"
import { runBridgedModule } from "../src/module_bridge.ts"
import { loadAptPlaybookMappings } from "../src/apt_intel_feed.ts"

describe("chaindrop_oidc", () => {
  test("dry-run detects OIDC env patterns", () => {
    const r = auditChainDropOidc("repo.example.com", { dryRun: true })
    assert.equal(r.dryRun, true)
    assert.ok(r.envPatterns.includes("ACTIONS_ID_TOKEN_REQUEST_URL"))
    assert.ok(r.findings.length >= 1)
  })

  test("chaindrop playbook modules resolve", () => {
    const mappings = loadAptPlaybookMappings()
    assert.ok(mappings.chaindrop?.modules.includes("chaindrop_oidc"))
    assert.ok(mappings.chaindrop?.techniqueChain.includes("T1528"))
  })

  test("bridge returns compact JSON", async () => {
    const r = await runBridgedModule(
      { target: ".", live: false, sessionId: "test" },
      "chaindrop_oidc",
      { target: "github.com/org/repo" },
    )
    assert.ok(r.success)
    assert.ok(r.output.length <= 8000)
  })
})
