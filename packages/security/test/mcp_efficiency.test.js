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
    ]
    const filtered = filterToolsForEfficiency(tools)
    assert.equal(filtered.length, 2)
    assert.ok(filtered.some((t) => t.name === "bash"))
    assert.ok(filtered.some((t) => t.name === "ares_phase"))
    process.env.OURMINE_MCP_EFFICIENT = "1"
  })

  test("allowlist includes phase and dispatch", () => {
    assert.ok(EFFICIENT_TOOL_ALLOWLIST.has("ares_phase"))
    assert.ok(EFFICIENT_TOOL_ALLOWLIST.has("ares_dispatch"))
  })
})
