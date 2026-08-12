/**
 * Target flow routing tests — adversarial persona matrix
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  buildFlowProfile,
  inferFlowObjective,
  modulesForPhase,
  skipAdAutoChain,
} from "../src/target_flow.ts"
import { buildActionablePlan } from "../src/pentest_plan_builder.ts"

describe("target_flow", () => {
  test("PLC hostname routes to ot_ics", () => {
    const flow = buildFlowProfile("plc-line3.factory.local")
    assert.equal(flow.persona, "ot_plc")
    assert.equal(inferFlowObjective(flow), "ot_ics")
  })

  test("private IP without OT hints stays generic (not ot_ics)", () => {
    const flow = buildFlowProfile("192.168.10.50")
    assert.equal(flow.isOtLikely, false)
    assert.equal(flow.persona, "generic_ip")
    assert.equal(inferFlowObjective(flow), "standard")
  })

  test("private IP with modbus hint routes ot_ics", () => {
    const flow = buildFlowProfile("192.168.10.50", undefined, "modbus plc")
    assert.ok(flow.isOtLikely)
    assert.equal(inferFlowObjective(flow, "scada"), "ot_ics")
  })

  test("modbus hint on IP forces ot modules in exploit phase", () => {
    const flow = buildFlowProfile("10.0.0.50", undefined, "modbus plc scada")
    const mods = modulesForPhase("exploit", flow, "ot_ics")
    assert.ok(mods.includes("iot_scada"))
    assert.ok(mods.includes("telecom_audit"))
  })

  test("telecom carrier persona gets SS7 path", () => {
    const flow = buildFlowProfile("10.20.30.40", undefined, "ss7 carrier sip")
    assert.equal(flow.persona, "telecom_carrier")
    const mods = modulesForPhase("exploit", flow, "telecom")
    assert.ok(mods.includes("ares_ss7_exploit"))
    assert.ok(mods.includes("telecom_audit"))
    assert.ok(mods.includes("ares_network_exploit"))
  })

  test("web URL skips AD exploit modules", () => {
    const flow = buildFlowProfile("https://portal.example.com")
    const mods = modulesForPhase("exploit", flow, "ai_agent")
    assert.ok(mods.includes("app_security_engine"))
    assert.ok(!mods.includes("ares_ad_exploit"))
  })

  test("enterprise AD keeps auto chain in post_ex", () => {
    const flow = buildFlowProfile("corp.example.com")
    const mods = modulesForPhase("post_ex", flow, "identity_first")
    assert.ok(mods.includes("ares_auto_chain"))
  })

  test("skipAdAutoChain for bare OT target", () => {
    const flow = buildFlowProfile("192.168.1.100")
    assert.equal(skipAdAutoChain(flow, "ot_ics"), true)
  })

  test("enterprise AD domain keeps auto chain", () => {
    const flow = buildFlowProfile("corp.example.com")
    assert.equal(skipAdAutoChain(flow, "identity_first"), false)
  })

  test("esxi hint routes cloud_ransom plan", () => {
    const plan = buildActionablePlan("10.0.0.5", { objective: "esxi vcenter" })
    assert.equal(plan.objective, "cloud_ransom")
  })

  test("OT plan uses engagement_slice not separate phase tools", () => {
    const plan = buildActionablePlan("192.168.50.10", { objective: "scada" })
    assert.equal(plan.objective, "ot_ics")
    assert.ok(plan.nextActions.some((a) => a.tool === "ares_engagement_slice"))
    assert.ok(plan.nextActions.some((a) => a.tool === "ares_engagement_continue"))
    assert.ok(!plan.nextActions.some((a) => a.tool === "ares_phase"))
    assert.ok(!plan.nextActions.some((a) => a.args.phase === "identity"))
    assert.ok(plan.gaps?.some((g) => g.includes("OURMINE_OT_WRITE_LAB")))
  })

  test("ransomware plan includes post_ex via engagement_continue", () => {
    const plan = buildActionablePlan("10.10.10.10", { objective: "ransomware" })
    assert.equal(plan.objective, "ransomware_impact")
    assert.ok(plan.nextActions.some((a) => a.args.phase === "post_ex" || a.args.phase === "apt"))
    assert.ok(plan.nextActions.every((a) => a.tool.startsWith("ares_engagement") || a.tool === "ares_threat_intel"))
  })
})
