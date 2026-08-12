/**
 * MCP response formatting tests
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  shouldThrottleTool,
  normalizeToolPayload,
  formatMcpToolResponse,
  compactEngagementResponse,
  flattenBridgedResult,
  THROTTLE_EXEMPT_TOOLS,
} from "../src/mcp_response.ts"

describe("mcp_response", () => {
  test("shouldThrottleTool exempts meta tools", () => {
    assert.equal(shouldThrottleTool("ares_tool_search"), false)
    assert.equal(shouldThrottleTool("ares_pentest_plan"), false)
    assert.equal(shouldThrottleTool("ares_recon"), true)
  })

  test("normalizeToolPayload flattens nested output JSON", () => {
    const flat = normalizeToolPayload({
      success: true,
      output: JSON.stringify({ summary: "Phase recon: 4/4 ok", succeeded: 4 }),
    })
    assert.equal(flat.summary, "Phase recon: 4/4 ok")
    assert.equal(flat.succeeded, 4)
    assert.equal(flat.success, true)
  })

  test("formatMcpToolResponse preserves bash stdout and exitCode", () => {
    process.env.OURMINE_MCP_EFFICIENT = "1"
    const text = formatMcpToolResponse({
      stdout: "Nmap version 7.94",
      stderr: "",
      exitCode: 0,
    })
    const p = JSON.parse(text)
    assert.ok(p.stdout.includes("Nmap"))
    assert.equal(p.exitCode, 0)
  })

  test("formatMcpToolResponse preserves dry-run reason", () => {
    process.env.OURMINE_MCP_EFFICIENT = "1"
    const text = formatMcpToolResponse({
      stdout: "",
      stderr: "dry-run: pass --live or run on Kali",
      exitCode: 0,
      dryRun: true,
    })
    const p = JSON.parse(text)
    assert.equal(p.dryRun, true)
    assert.ok(p.stderr.includes("dry-run") || p.reason?.includes("dry-run"))
  })

  test("flattenBridgedResult removes nested JSON string", () => {
    const flat = flattenBridgedResult({
      tool: "ares_phase",
      success: true,
      dryRun: false,
      output: JSON.stringify({ summary: "Phase recon: 4/4 ok", succeeded: 4 }),
    })
    assert.equal(flat.summary, "Phase recon: 4/4 ok")
    assert.equal(flat.succeeded, 4)
    assert.ok(!("output" in flat))
  })

  test("THROTTLE_EXEMPT_TOOLS includes engagement continue", () => {
    assert.ok(THROTTLE_EXEMPT_TOOLS.has("ares_engagement_continue"))
  })

  test("formatMcpToolResponse compacts engagement slice to ≤400B", async () => {
    process.env.OURMINE_MCP_EFFICIENT = "1"
    const { runEngagementSlice } = await import("../src/engagement_slice.ts")
    const r = await runEngagementSlice({ target: "127.0.0.1", live: false })
    const text = formatMcpToolResponse(r, { kind: "ares_engagement_slice", maxLen: 400 })
    assert.ok(text.length <= 400, `got ${text.length}B`)
    const p = JSON.parse(text)
    assert.ok(p.rt)
    assert.ok(p.aid)
    assert.ok(Array.isArray(p.na))
  })

  test("formatMcpToolResponse uses delta for engagement continue", async () => {
    process.env.OURMINE_MCP_EFFICIENT = "1"
    const { runEngagementSlice, runEngagementContinue } = await import("../src/engagement_slice.ts")
    const r1 = await runEngagementSlice({ target: "127.0.0.1", live: false })
    const sliceText = formatMcpToolResponse(r1, { kind: "ares_engagement_slice", maxLen: 400 })
    const r2 = await runEngagementContinue({ resumeToken: r1.resumeToken })
    const contText = formatMcpToolResponse(r2, { kind: "ares_engagement_continue", maxLen: 280 })
    assert.ok(contText.length <= 280, `continue ${contText.length}B`)
    const p = JSON.parse(contText)
    assert.equal(p.d, true)
    assert.ok(p.rt)
    assert.ok(contText.length <= sliceText.length || p.im === true)
  })
})
