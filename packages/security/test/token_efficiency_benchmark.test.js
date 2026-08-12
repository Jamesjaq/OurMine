/**
 * Token efficiency benchmark — corp.example.com engagement vs hypothetical 20-tool OpenCode run
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { runEngagementSlice, runEngagementContinue } from "../src/engagement_slice.ts"
import {
  compactEngagementResponse,
  compactEngagementContinueResponse,
  formatMcpToolResponse,
} from "../src/mcp_response.ts"
import { compactToolOutput } from "../src/mcp_efficiency.ts"

const TARGET = "corp.example.com"
const HYPOTHETICAL_TOOLS = [
  "ares_threat_intel", "ares_pentest_plan", "ares_recon", "ares_bountyhunter",
  "ares_vuln_research", "ares_net_device_audit", "ares_cred_access_auto",
  "ares_kerberos_advanced", "ares_ad_exploit", "ares_strix_web",
  "ares_auto_chain", "ares_exfil", "ares_impact_assess", "ares_evasion_engine",
  "ares_lateral_scale", "ares_cloud_native", "ares_iot_scada", "ares_dispatch",
  "ares_phase", "ares_orchestrator",
]

function estimateOpenCodeBytes(tools, avgPayload = 1400) {
  const toolSchemas = tools.length * 450
  const toolResults = tools.length * avgPayload
  const planningTurn = 800
  return toolSchemas + toolResults + planningTurn
}

describe("token_efficiency_benchmark", () => {
  test("corp.example.com slice+continue measured byte savings", async () => {
    process.env.OURMINE_MCP_EFFICIENT = "1"

    const slice = await runEngagementSlice({
      target: TARGET,
      live: false,
      objective: "identity_first",
    })
    const sliceCompact = formatMcpToolResponse(slice, { kind: "ares_engagement_slice", maxLen: 400 })
    const sliceFull = JSON.stringify(slice)

    const cont = await runEngagementContinue({ resumeToken: slice.resumeToken })
    const contCompact = formatMcpToolResponse(cont, { kind: "ares_engagement_continue", maxLen: 280 })
    const contFull = JSON.stringify(cont)

    const cont2 = await runEngagementContinue({ resumeToken: slice.resumeToken })
    const cont2Compact = formatMcpToolResponse(cont2, { kind: "ares_engagement_continue", maxLen: 280 })

    const aresTurns = 3
    const aresBytes = sliceCompact.length + contCompact.length + cont2Compact.length
    const aresFullBytes = sliceFull.length + contFull.length + JSON.stringify(cont2).length

    const opencodeTurns = 20
    const opencodeBytes = estimateOpenCodeBytes(HYPOTHETICAL_TOOLS)

    const savingsVsOpenCode = opencodeBytes - aresBytes
    const savingsPct = Math.round((savingsVsOpenCode / opencodeBytes) * 100)
    const compressionRatio = Math.round((aresFullBytes / aresBytes) * 10) / 10

    console.log("\n=== OurMine ARES Token Efficiency Benchmark ===")
    console.log(`Target: ${TARGET} (enterprise AD / identity_first)`)
    console.log(`ARES: ${aresTurns} MCP turns, ${aresBytes}B compact (${aresFullBytes}B full → ${compressionRatio}x compression)`)
    console.log(`OpenCode (hypothetical): ${opencodeTurns} tool calls, ~${opencodeBytes}B estimated`)
    console.log(`Savings vs 20-tool run: ${savingsVsOpenCode}B (${savingsPct}%)`)
    console.log(`Continue delta turn 2: ${cont2Compact.length}B (intel skipped: ${cont2.intelFromMemory})`)
    console.log(`Parallel recon probes (turn 1): ${slice.parallelProbes ?? 0}`)
    console.log(`Playbook cache hit (turn 2+): ${cont.cacheHit}`)
    console.log("===============================================\n")

    assert.ok(sliceCompact.length <= 400, `slice ${sliceCompact.length}B`)
    assert.ok(contCompact.length <= 280, `continue ${contCompact.length}B`)
    assert.ok(cont2Compact.length <= 280, `continue2 ${cont2Compact.length}B`)
    assert.ok(savingsVsOpenCode > 20_000, "expected >20KB savings vs 20-tool OpenCode")
    assert.equal(cont2.intelFromMemory, true)
  })

  test("compact continue smaller than full re-emit when delta applies", async () => {
    const slice = await runEngagementSlice({ target: "192.168.1.1", live: false })
    const full = compactEngagementResponse(slice)
    const cont = await runEngagementContinue({ resumeToken: slice.resumeToken })
    const delta = compactEngagementContinueResponse(cont)
    assert.ok(delta.length <= full.length, `delta ${delta.length} should be ≤ full ${full.length}`)
    const parsed = JSON.parse(delta)
    assert.equal(parsed.d, true)
  })
})
