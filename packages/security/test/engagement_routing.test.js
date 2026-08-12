/**
 * Engagement routing — newly wired policy/graph/bridge paths
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  applyPolicyToModules,
  supplementalModulesForPhase,
  evaluateEngagementPolicy,
} from "../src/engagement_policy.ts"
import { buildFlowProfile } from "../src/target_flow.ts"
import { getNextActions, buildEngagementGraph } from "../src/engagement_graph.ts"
import { buildActionablePlan } from "../src/pentest_plan_builder.ts"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { CredentialGraph } from "../src/credential_graph.ts"
import { bridgedToolNames } from "../src/module_bridge.ts"

describe("engagement_routing wiring", () => {
  test("supply_chain persona routes supply_chain_exec in recon", () => {
    const flow = buildFlowProfile("github.com/npm/lodash", undefined, "supply npm ci/cd")
    assert.equal(flow.persona, "supply_chain_repo")
    const mods = applyPolicyToModules("recon", flow, "supply_chain", undefined, true)
    assert.ok(mods.includes("supply_chain_exec"), `expected supply_chain_exec in ${mods.join(",")}`)
    assert.ok(mods.includes("ares_supply_chain_implant"))
    assert.ok(mods.includes("cicd_audit") || mods.includes("lockfile_scan"))
  })

  test("supplementalModulesForPhase adds campaign_loop for AD post_ex", () => {
    const flow = buildFlowProfile("corp.example.com")
    const sup = supplementalModulesForPhase("post_ex", flow, "identity_first")
    assert.ok(sup.includes("campaign_loop"))
    assert.ok(sup.includes("segment_tunnel"))
    assert.ok(sup.includes("autonomous_pivot"))
  })

  test("telecom persona prioritizes ares_ss7_exploit", () => {
    const flow = buildFlowProfile("carrier-ss7.lab", undefined, "telecom ss7")
    const pol = evaluateEngagementPolicy({ profile: flow, objective: "telecom", live: true })
    assert.ok(pol.prioritizeModules.includes("ares_ss7_exploit"))
    const exploit = applyPolicyToModules("exploit", flow, "telecom", undefined, true)
    assert.ok(exploit.includes("ares_ss7_exploit"))
  })

  test("cloud persona routes multi_cloud_asm and ares_cloud_native", () => {
    const flow = buildFlowProfile("api.cloudsvc.io", undefined, "cloud k8s")
    flow.persona = "container_k8s"
    const recon = applyPolicyToModules("recon", flow, "cloud_ransom", undefined, true)
    assert.ok(recon.includes("ares_cloud_native") || recon.includes("cloud_enum"))
    assert.ok(recon.includes("multi_cloud_asm"))
  })

  test("OT supplemental includes profinet_l2 and ot_segment_infer", () => {
    const flow = buildFlowProfile("10.0.0.0/24", undefined, "modbus scada")
    const sup = supplementalModulesForPhase("recon", flow, "ot_ics")
    assert.ok(sup.includes("profinet_l2"))
    assert.ok(sup.includes("ot_segment_infer"))
  })

  test("getNextActions dispatches supply_chain_exec for supply_chain objective", () => {
    const graph = new AttackSurfaceGraph("registry.npmjs.org")
    const cred = new CredentialGraph()
    const eg = buildEngagementGraph({
      target: "registry.npmjs.org",
      graph,
      credGraph: cred,
      objective: "supply_chain",
      live: false,
      personaOverride: "supply_chain_repo",
    })
    const actions = getNextActions(eg, { engagementResumeToken: "eng_test", completedPhases: ["recon"] })
    const modules = actions.filter((a) => a.tool === "ares_dispatch").map((a) => a.args.module)
    assert.ok(modules.includes("supply_chain_exec"), `dispatch modules: ${modules.join(",")}`)
    assert.ok(modules.includes("ares_supply_chain_implant"))
  })

  test("getNextActions dispatches campaign_loop when AD creds+pivot confirmed", () => {
    const graph = new AttackSurfaceGraph("corp.example.com")
    const cred = new CredentialGraph()
    cred.addCredential({ type: "password", source: "t", username: "admin", domain: "corp.local", value: "x", used: true })
    const eg = buildEngagementGraph({
      target: "corp.example.com",
      graph,
      credGraph: cred,
      objective: "identity_first",
      live: false,
      personaOverride: "enterprise_ad",
    })
    eg.confirmed.push({ kind: "pivot", label: "a→b", detail: "winrm" })
    const actions = getNextActions(eg, {
      engagementResumeToken: "eng_test",
      completedPhases: ["recon", "identity", "exploit"],
      credGraph: cred,
    })
    const modules = actions.filter((a) => a.tool === "ares_dispatch").map((a) => a.args.module)
    assert.ok(modules.includes("campaign_loop"), `expected campaign_loop in ${modules.join(",")}`)
  })

  test("getNextActions dispatches ares_cloud_native for cloud persona", () => {
    const graph = new AttackSurfaceGraph("api.cloud.io")
    const cred = new CredentialGraph()
    const eg = buildEngagementGraph({
      target: "api.cloud.io",
      graph,
      credGraph: cred,
      objective: "cloud_ransom",
      live: false,
      personaOverride: "cloud_saas",
    })
    const actions = getNextActions(eg, { engagementResumeToken: "eng_test" })
    const modules = actions.filter((a) => a.tool === "ares_dispatch").map((a) => a.args.module)
    assert.ok(modules.includes("ares_cloud_native"))
    assert.ok(modules.includes("multi_cloud_asm"))
  })

  test("getNextActions dispatches ares_ss7_exploit for telecom", () => {
    const graph = new AttackSurfaceGraph("carrier.lab")
    const cred = new CredentialGraph()
    const eg = buildEngagementGraph({
      target: "carrier.lab",
      graph,
      credGraph: cred,
      objective: "telecom",
      live: false,
      personaOverride: "telecom_carrier",
    })
    const actions = getNextActions(eg, { engagementResumeToken: "eng_test" })
    const modules = actions.filter((a) => a.tool === "ares_dispatch").map((a) => a.args.module)
    assert.ok(modules.includes("ares_ss7_exploit"))
  })

  test("pentest plan includes supply_chain dispatch action", () => {
    const plan = buildActionablePlan("github.com/org/pkg", { objective: "supply_chain" })
    assert.ok(plan.nextActions.some((a) => a.args.module === "supply_chain_exec"))
  })

  test("bridge includes agent-tool aliases for routed modules", () => {
    const keys = bridgedToolNames()
    for (const k of [
      "impact_assess", "ares_exfil", "ares_ad_exploit", "edge_audit", "esxi_audit",
      "supply_chain_audit", "lockfile_scan", "cicd_audit", "profinet_l2", "ot_segment_infer",
    ]) {
      assert.ok(keys.includes(k), `missing bridge key: ${k}`)
    }
  })
})
