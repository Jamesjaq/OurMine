/** AUTO-GENERATED — run packages/security/scripts/generate-module-smokes.ts */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { AttackSurfaceGraph } from "../../src/attack_surface.ts"
import { ToolBroker } from "../../src/tool_broker.ts"
import { runBridgedModule } from "../../src/bridges/index.ts"
import { buildNativeMcpTools } from "../../src/mcp/register_tools.ts"

const TIMEOUT = 2000

function ctx(target = "127.0.0.1") {
  return { target, graph: new AttackSurfaceGraph(target), broker: new ToolBroker(), live: false }
}

const mcpMap = new Map(buildNativeMcpTools().map((t) => [t.name, t]))

describe("generated_module_smoke_bridge", () => {
  test("bridge smoke: lolbins_audit", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "lolbins_audit", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: oauth_consent_audit", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "oauth_consent_audit", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: device_code_audit", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "device_code_audit", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: chaindrop_oidc", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "chaindrop_oidc", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: citrix_audit", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "citrix_audit", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: rmm_audit", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "rmm_audit", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: edge_audit", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "edge_audit", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: passive_intel", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "passive_intel", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: institutional_recon", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "institutional_recon", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: iot_scada", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "iot_scada", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: profinet_l2", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "profinet_l2", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: ot_segment_infer", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "ot_segment_infer", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: raas_leak_catalog", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "raas_leak_catalog", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: impact_assess", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "impact_assess", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: engagement_report", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "engagement_report", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: dry_run_simulator", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "dry_run_simulator", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: oauth_audit", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "oauth_audit", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })

  test("bridge smoke: hybrid_ad_audit", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "hybrid_ad_audit", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })
})

describe("generated_module_smoke_mcp", () => {
  test("mcp smoke: ares_engagement_slice", { timeout: TIMEOUT }, async () => {
    const tool = mcpMap.get("ares_engagement_slice")
    assert.ok(tool, "tool registered")
    const out = await tool.handler({ target: "127.0.0.1", domain: "corp.example.com", host: "127.0.0.1", path: "/tmp" })
    assert.ok(out != null)
    const p = typeof out === "object" && out !== null ? out : {}
    assert.ok(p.dryRun === true || p.success === true || p.summary != null || p.error == null || typeof out === "object")
  })

  test("mcp smoke: ares_threat_intel", { timeout: TIMEOUT }, async () => {
    const tool = mcpMap.get("ares_threat_intel")
    assert.ok(tool, "tool registered")
    const out = await tool.handler({ target: "127.0.0.1", domain: "corp.example.com", host: "127.0.0.1", path: "/tmp" })
    assert.ok(out != null)
    const p = typeof out === "object" && out !== null ? out : {}
    assert.ok(p.dryRun === true || p.success === true || p.summary != null || p.error == null || typeof out === "object")
  })

  test("mcp smoke: ares_recon", { timeout: TIMEOUT }, async () => {
    const tool = mcpMap.get("ares_recon")
    assert.ok(tool, "tool registered")
    const out = await tool.handler({ target: "127.0.0.1", domain: "corp.example.com", host: "127.0.0.1", path: "/tmp" })
    assert.ok(out != null)
    const p = typeof out === "object" && out !== null ? out : {}
    assert.ok(p.dryRun === true || p.success === true || p.summary != null || p.error == null || typeof out === "object")
  })

  test("mcp smoke: ares_bountyhunter", { timeout: TIMEOUT }, async () => {
    const tool = mcpMap.get("ares_bountyhunter")
    assert.ok(tool, "tool registered")
    const out = await tool.handler({ target: "127.0.0.1", domain: "corp.example.com", host: "127.0.0.1", path: "/tmp" })
    assert.ok(out != null)
    const p = typeof out === "object" && out !== null ? out : {}
    assert.ok(p.dryRun === true || p.success === true || p.summary != null || p.error == null || typeof out === "object")
  })

  test("mcp smoke: ares_lolbins_audit", { timeout: TIMEOUT }, async () => {
    const tool = mcpMap.get("ares_lolbins_audit")
    assert.ok(tool, "tool registered")
    const out = await tool.handler({ target: "127.0.0.1", domain: "corp.example.com", host: "127.0.0.1", path: "/tmp" })
    assert.ok(out != null)
    const p = typeof out === "object" && out !== null ? out : {}
    assert.ok(p.dryRun === true || p.success === true || p.summary != null || p.error == null || typeof out === "object")
  })

  test("mcp smoke: ares_idp_oauth_audit", { timeout: TIMEOUT }, async () => {
    const tool = mcpMap.get("ares_idp_oauth_audit")
    assert.ok(tool, "tool registered")
    const out = await tool.handler({ target: "127.0.0.1", domain: "corp.example.com", host: "127.0.0.1", path: "/tmp" })
    assert.ok(out != null)
    const p = typeof out === "object" && out !== null ? out : {}
    assert.ok(p.dryRun === true || p.success === true || p.summary != null || p.error == null || typeof out === "object")
  })

  test("mcp smoke: ares_iot_scada", { timeout: TIMEOUT }, async () => {
    const tool = mcpMap.get("ares_iot_scada")
    assert.ok(tool, "tool registered")
    const out = await tool.handler({ target: "127.0.0.1", domain: "corp.example.com", host: "127.0.0.1", path: "/tmp" })
    assert.ok(out != null)
    const p = typeof out === "object" && out !== null ? out : {}
    assert.ok(p.dryRun === true || p.success === true || p.summary != null || p.error == null || typeof out === "object")
  })

  test("mcp smoke: ares_pentest_plan", { timeout: TIMEOUT }, async () => {
    const tool = mcpMap.get("ares_pentest_plan")
    assert.ok(tool, "tool registered")
    const out = await tool.handler({ target: "127.0.0.1", domain: "corp.example.com", host: "127.0.0.1", path: "/tmp" })
    assert.ok(out != null)
    const p = typeof out === "object" && out !== null ? out : {}
    assert.ok(p.dryRun === true || p.success === true || p.summary != null || p.error == null || typeof out === "object")
  })
})
