/**
 * OT vertical definitions — critical infrastructure sectors, APT playbooks, hybrid pivot
 */
import { describe, test, before } from "node:test"
import assert from "node:assert/strict"
import {
  detectOtVertical,
  modulesForVertical,
  personaForVertical,
  portsForVertical,
  isInfraCidrTarget,
  aptPlaybookForVertical,
  READ_ONLY_SAFETY_NOTE,
  XENOTIME_SAFETY_NOTE,
} from "../src/ot_verticals.ts"
import {
  buildFlowProfile,
  inferFlowObjective,
  modulesForPhase,
} from "../src/target_flow.ts"
import { applyPolicyToModules } from "../src/engagement_policy.ts"
import { reconInstitutionalSector } from "../src/institutional_hints.ts"
import { runHybridItOtPivot } from "../src/hybrid_pivot.ts"
import {
  resolveAptProfile,
  objectiveFromAptName,
  getThreatIntel,
} from "../src/apt_intel_feed.ts"

describe("ot_verticals", () => {
  before(() => {
    process.env.OURMINE_ALLOW_DRY_RUN = "1"
    process.env.OURMINE_LIVE = "0"
  })

  test("detectOtVertical maps all user-specified verticals", () => {
    assert.equal(detectOtVertical("power plant iec61850"), "power_generation")
    assert.equal(detectOtVertical("substation goose relay"), "power_grid")
    assert.equal(detectOtVertical("wastewater bacnet bms"), "water_wastewater")
    assert.equal(detectOtVertical("chemical plant opc-ua triconex"), "chemical_process")
    assert.equal(detectOtVertical("rail signal etcs modbus rtu"), "rail_transport")
    assert.equal(detectOtVertical("oil gas pipeline hart"), "oil_gas_pipeline")
    assert.equal(detectOtVertical("dam flood control dnp3"), "dam_flood_control")
    assert.equal(detectOtVertical("airport terminal scada"), "transport_port")
    assert.equal(detectOtVertical("telecom backbone sigtran"), "telecom_backbone")
  })

  test("vertical modules match spec — read-only probes only", () => {
    assert.ok(modulesForVertical("power_generation").includes("ot_batch_scan"))
    assert.ok(modulesForVertical("power_generation").includes("iot_scada"))
    assert.ok(modulesForVertical("power_grid").includes("profinet_l2"))
    assert.ok(modulesForVertical("water_wastewater").includes("ot_scan"))
    assert.ok(modulesForVertical("chemical_process").includes("ics_impact_proof"))
    assert.ok(modulesForVertical("rail_transport").includes("institutional_recon"))
    assert.ok(modulesForVertical("oil_gas_pipeline").includes("ot_batch_scan"))
    assert.ok(modulesForVertical("dam_flood_control").includes("ot_scan"))
    assert.ok(!modulesForVertical("chemical_process").some((m) => m.includes("write")))
  })

  test("vertical personas — ot_plc vs ot_scada_plant", () => {
    assert.equal(personaForVertical("chemical_process"), "ot_plc")
    assert.equal(personaForVertical("dam_flood_control"), "ot_plc")
    assert.equal(personaForVertical("power_generation"), "ot_scada_plant")
    assert.equal(personaForVertical("power_grid"), "ot_scada_plant")
  })

  test("power_grid includes port 102 IEC61850", () => {
    const ports = portsForVertical("power_grid")
    assert.ok(ports.some((p) => p.port === 102 && p.service.includes("IEC61850")))
  })

  test("chemical_process includes OPC-UA port 4840", () => {
    const ports = portsForVertical("chemical_process")
    assert.ok(ports.some((p) => p.port === 4840))
  })

  test("isInfraCidrTarget detects CIDR + vertical hints", () => {
    assert.equal(isInfraCidrTarget("10.50.0.0/24", "substation goose"), true)
    assert.equal(isInfraCidrTarget("10.50.0.0/24"), false)
    assert.equal(isInfraCidrTarget("10.50.0.5", "power plant"), false)
  })

  test("buildFlowProfile attaches otVertical for substation CIDR", () => {
    const flow = buildFlowProfile("10.50.0.0/24", undefined, "substation goose mms")
    assert.equal(flow.institutionalSector, "critical_infra")
    assert.equal(flow.otVertical, "power_grid")
    assert.equal(flow.persona, "ot_scada_plant")
    assert.equal(inferFlowObjective(flow), "ot_ics")
  })

  test("chemical plant routes ot_plc persona + ics modules", () => {
    const flow = buildFlowProfile("10.60.0.5", undefined, "chemical plant opc-ua")
    assert.equal(flow.otVertical, "chemical_process")
    assert.equal(flow.persona, "ot_plc")
    const recon = modulesForPhase("recon", flow, "ot_ics")
    assert.ok(recon.includes("ics_impact_proof"))
    assert.ok(recon.includes("institutional_recon"))
  })

  test("policy prioritizes hybrid_pivot for infra CIDR", () => {
    const flow = buildFlowProfile("10.50.0.0/24", undefined, "substation scada")
    const policy = applyPolicyToModules("recon", flow, "ot_ics", undefined, false)
    assert.ok(policy.includes("hybrid_pivot"))
    assert.ok(policy.includes("ot_batch_scan"))
    assert.ok(policy.includes("profinet_l2"))
  })

  test("reconInstitutionalSector returns vertical ports for water/wastewater", async () => {
    const r = await reconInstitutionalSector("critical_infra", "wastewater.local", {
      live: false,
    })
    assert.equal(r.otVertical, "water_wastewater")
    assert.ok(r.portHints.some((p) => p.port === 47808))
    assert.equal(r.safetyNote, READ_ONLY_SAFETY_NOTE)
  })

  test("hybrid_pivot skips IT recon for infra CIDR target", async () => {
    const r = await runHybridItOtPivot({
      target: "10.50.0.0/24",
      hint: "substation goose scada",
      live: false,
    })
    assert.equal(r.otVertical, "power_grid")
    assert.ok(r.pivotPath.some((p) => p.includes("IT recon skipped")))
    assert.ok(r.pivotPath.some((p) => p.includes("read-only")))
    assert.equal(r.safetyNote, READ_ONLY_SAFETY_NOTE)
    assert.ok(r.verticalModules?.includes("profinet_l2"))
  })

  test("Sandworm APT resolves to ot_ics with grid playbook", () => {
    const p = resolveAptProfile("Sandworm")
    assert.ok(p)
    assert.equal(p.id, "sandworm")
    assert.equal(objectiveFromAptName("Sandworm"), "ot_ics")
    assert.ok(p.focus.some((f) => f.includes("grid") || f.includes("substation")))
  })

  test("XENOTIME APT resolves with safety-aware playbook", async () => {
    const p = resolveAptProfile("XENOTIME")
    assert.ok(p)
    assert.equal(p.id, "xenotime")
    assert.ok(p.aliases.some((a) => a.toLowerCase().includes("trisis")))
    assert.equal(objectiveFromAptName("TRISIS"), "ot_ics")
    assert.equal(aptPlaybookForVertical("chemical_process"), "xenotime")

    const r = await getThreatIntel({
      target: "10.60.0.5",
      aptHint: "XENOTIME triconex",
      live: false,
      refresh: true,
    })
    assert.ok(r)
    assert.equal(r.profileId, "xenotime")
    assert.ok(
      r.intelSnippet.includes("read-only") || r.intelSnippet.includes("NO SIS") || r.intelSnippet.includes("TRISIS"),
    )
    assert.ok(XENOTIME_SAFETY_NOTE.includes("read-only"))
  })

  test("Volt Typhoon still routes hybrid_it_ot", () => {
    assert.equal(objectiveFromAptName("Volt Typhoon"), "hybrid_it_ot")
    const p = resolveAptProfile("Volt Typhoon")
    assert.equal(p?.id, "volt_typhoon")
  })
})
