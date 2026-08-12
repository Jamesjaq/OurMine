/**
 * Engagement slice dry-run tests
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  runEngagementSlice,
  runEngagementContinue,
  saveEngagementState,
  loadEngagementState,
  buildEngagementResumeToken,
} from "../src/engagement_slice.ts"
import { applyPolicyToModules, getModulesForPersona } from "../src/engagement_policy.ts"
import { buildFlowProfile } from "../src/target_flow.ts"
import { getNextActions, buildEngagementGraph } from "../src/engagement_graph.ts"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { CredentialGraph } from "../src/credential_graph.ts"
import { compactEngagementResponse } from "../src/mcp_response.ts"

describe("engagement_slice", () => {
  test("dry-run returns compact graph snapshot with resumeToken", async () => {
    const r = await runEngagementSlice({
      target: "10.10.10.5",
      live: false,
      objective: "standard",
    })
    assert.ok(r.summary.includes("Slice"))
    assert.equal(r.dryRun, true)
    assert.ok(r.resumeToken.startsWith("eng_"))
    assert.ok(Array.isArray(r.confirmed))
    assert.ok(Array.isArray(r.candidates))
    assert.ok(Array.isArray(r.blockers))
    assert.ok(r.blockers.some((b) => b.includes("dry-run")))
    assert.ok(r.planNextActions.length >= 2)
    assert.equal(typeof r.phaseResult.stepCount, "number")
    assert.ok(Array.isArray(r.graphNextActions))
    assert.ok(r.graphNextActions.length >= 1)
    assert.ok(r.graphNextActions.some((a) => a.tool === "ares_engagement_continue"))
  })

  test("resume token round-trip and continue without re-plan", async () => {
    const r1 = await runEngagementSlice({
      target: "192.168.1.10",
      live: false,
      objective: "standard",
    })
    const loaded = loadEngagementState(r1.resumeToken)
    assert.ok(loaded)
    assert.equal(loaded.target, "192.168.1.10")
    assert.deepEqual(loaded.completedPhases, [r1.phaseResult.phase])

    const r2 = await runEngagementContinue({ resumeToken: r1.resumeToken })
    assert.equal(r2.resumeToken, r1.resumeToken)
    assert.notEqual(r2.phaseResult.phase, r1.phaseResult.phase)
    const state2 = loadEngagementState(r1.resumeToken)
    assert.ok(state2.completedPhases.length >= 2)
  })

  test("compact engagement response ≤400 bytes", async () => {
    const r = await runEngagementSlice({
      target: "10.0.0.1",
      live: false,
      objective: "standard",
    })
    const text = compactEngagementResponse(r, 400)
    assert.ok(text.length <= 400, `compact response ${text.length}B > 400B: ${text}`)
    const p = JSON.parse(text)
    assert.ok(p.rt)
    assert.ok(p.aid)
    assert.ok(Array.isArray(p.na))
    assert.equal(typeof p.cf, "number")
  })

  test("graphNextActions deterministic and includes continue", () => {
    const graph = new AttackSurfaceGraph("10.0.0.0/24")
    const credGraph = new CredentialGraph()
    const eg = buildEngagementGraph({
      target: "10.0.0.0/24",
      graph,
      credGraph,
      objective: "ot_ics",
      live: false,
    })
    const token = buildEngagementResumeToken("10.0.0.0/24", "ot_ics", ["recon"])
    const a1 = getNextActions(eg, { engagementResumeToken: token, completedPhases: ["recon"] })
    const a2 = getNextActions(eg, { engagementResumeToken: token, completedPhases: ["recon"] })
    assert.deepEqual(a1.map((x) => x.tool), a2.map((x) => x.tool))
    assert.equal(a1[0].tool, "ares_engagement_continue")
    assert.ok(a1.some((a) => a.tool === "ares_dispatch" || a.tool === "ares_engagement_continue"))
  })

  test("OT CIDR plans recon without identity modules in policy", () => {
    const flow = buildFlowProfile("10.0.0.0/24", undefined, "modbus scada")
    const mods = applyPolicyToModules("identity", flow, "ot_ics", undefined, true)
    assert.equal(mods.length, 0)
    const recon = applyPolicyToModules("recon", flow, "ot_ics", undefined, true)
    assert.ok(recon.includes("ot_batch_scan"))
  })

  test("web_app persona skips AD identity modules", () => {
    const flow = buildFlowProfile("https://app.example.com")
    assert.equal(flow.persona, "web_app")
    const identity = getModulesForPersona("identity", flow, "ai_agent", undefined, true)
    assert.equal(identity.length, 0)
    const exploit = getModulesForPersona("exploit", flow, "ai_agent", undefined, true)
    assert.ok(exploit.includes("strix_web"))
    assert.ok(exploit.includes("app_security_engine"))
    assert.ok(!exploit.includes("ares_ad_exploit"))
  })

  test("enterprise AD domain gets identity + net_device recon", () => {
    const flow = buildFlowProfile("corp.example.com")
    const recon = getModulesForPersona("recon", flow, "identity_first", undefined, true)
    assert.ok(recon.includes("net_device_audit"))
    const identity = getModulesForPersona("identity", flow, "identity_first", undefined, true)
    assert.ok(identity.includes("cred_access_auto"))
    assert.ok(identity.includes("ares_kerberos_advanced"))
  })

  test("cloud/k8s persona gets cloud_enum in recon", () => {
    const flow = buildFlowProfile("api.cloudsvc.io", undefined, "kubernetes k8s")
    assert.equal(flow.persona, "container_k8s")
    const recon = getModulesForPersona("recon", flow, "ai_agent", undefined, true)
    assert.ok(recon.includes("cloud_enum") || recon.includes("ares_cloud_native"))
  })

  test("saveEngagementState persists state", () => {
    const token = buildEngagementResumeToken("test.local", "identity_first", ["recon"])
    saveEngagementState(token, {
      target: "test.local",
      objective: "identity_first",
      persona: "enterprise_ad",
      completedPhases: ["recon"],
      lastPhase: "recon",
      live: false,
      updatedAt: new Date().toISOString(),
    })
    const loaded = loadEngagementState(token)
    assert.equal(loaded?.target, "test.local")
    assert.deepEqual(loaded?.completedPhases, ["recon"])
  })

  test("dry-run preloads APT intel snippet when actor hinted", async () => {
    const r = await runEngagementSlice({
      target: "10.0.0.0/24",
      live: false,
      aptHint: "Volt Typhoon",
    })
    assert.ok(r.intelDigest ?? r.intelSnippet)
    assert.ok((r.intelDigest ?? r.intelSnippet).length <= 120)
    assert.ok(r.aptTechniques?.length >= 3)
    assert.equal(r.objective, "hybrid_it_ot")
    assert.ok(r.intelArtifactId?.startsWith("intel_prefetch_"))
  })
})
