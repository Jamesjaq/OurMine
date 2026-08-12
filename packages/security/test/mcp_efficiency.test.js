/**
 * MCP efficiency mode tests
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  compactToolOutput,
  filterToolsForEfficiency,
  isEfficientMode,
  EFFICIENT_TOOL_ALLOWLIST,
} from "../src/mcp_efficiency.ts"

describe("mcp_efficiency", () => {
  test("compactToolOutput keeps summary not full artifacts", () => {
    const raw = compactToolOutput({
      summary: "Phase recon: 3/4 ok",
      artifacts: new Array(50).fill("/tmp/x"),
      steps: [{ success: true }, { success: false }],
      techniques: ["a", "b", "c"],
    })
    const p = JSON.parse(raw)
    assert.equal(p.summary, "Phase recon: 3/4 ok")
    assert.equal(p.artifactCount, 50)
    assert.ok(!raw.includes("/tmp/x"))
    assert.ok(raw.length < 500)
  })

  test("filterToolsForEfficiency reduces tool count", () => {
    const tools = [
      { name: "bash" },
      { name: "ares_phase" },
      { name: "ares_obscure_tool" },
      { name: "ares_recon" },
    ]
    process.env.OURMINE_MCP_EFFICIENT = "1"
    const filtered = filterToolsForEfficiency(tools)
    assert.equal(filtered.length, 3)
    assert.ok(!filtered.some((t) => t.name === "ares_obscure_tool"))
  })

  test("efficient mode off uses search allowlist not full catalog", () => {
    process.env.OURMINE_MCP_EFFICIENT = "0"
    assert.equal(isEfficientMode(), false)
    const tools = [
      { name: "bash" },
      { name: "ares_phase" },
      { name: "ares_obscure_tool" },
      { name: "ares_kerberos_advanced" },
      { name: "ares_iot_scada" },
    ]
    const filtered = filterToolsForEfficiency(tools)
    assert.equal(filtered.length, 3)
    assert.ok(filtered.some((t) => t.name === "bash"))
    assert.ok(filtered.some((t) => t.name === "ares_phase"))
    assert.ok(filtered.some((t) => t.name === "ares_iot_scada"))
    process.env.OURMINE_MCP_EFFICIENT = "1"
  })

  test("allowlist includes engagement continue and watch", () => {
    assert.ok(EFFICIENT_TOOL_ALLOWLIST.has("ares_engagement_continue"))
    assert.ok(EFFICIENT_TOOL_ALLOWLIST.has("ares_engagement_watch"))
    assert.ok(EFFICIENT_TOOL_ALLOWLIST.has("ares_phase"))
    assert.ok(EFFICIENT_TOOL_ALLOWLIST.has("ares_dispatch"))
    assert.ok(EFFICIENT_TOOL_ALLOWLIST.has("ares_opsec_throttle"))
  })

  test("compactToolOutput preserves stdout stderr exitCode", () => {
    const raw = compactToolOutput({
      stdout: "hello world",
      stderr: "warn",
      exitCode: 0,
      dryRun: false,
    })
    const p = JSON.parse(raw)
    assert.equal(p.stdout, "hello world")
    assert.equal(p.exitCode, 0)
  })

  test("compactToolOutput caps lolbins payload", () => {
    const bins = Array.from({ length: 100 }, (_, i) => ({ name: `bin${i}` }))
    const raw = compactToolOutput({ discoveredLOLBins: bins, platform: "linux" })
    const p = JSON.parse(raw)
    assert.equal(p.lolbinCount, 100)
    assert.equal(p.lolbinSample.length, 5)
    assert.ok(raw.length < 800)
  })
})
