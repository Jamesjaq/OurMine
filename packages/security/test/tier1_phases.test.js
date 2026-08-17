/**
 * Tier-1 phased capability tests — live execution against lab HTTP harness.
 */
import { describe, test, before, after } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"

import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { ToolBroker } from "../src/tool_broker.ts"
import { ValidationPlanner } from "../src/validation_planner.ts"
import { ValidationEngine } from "../src/validation_engine.ts"
import { runStateMachineFlow, defaultSessionFlow, defaultL4CanaryFlow } from "../src/http_state_fuzzer.ts"
import { runAutonomousPivot, isAutonomousPivotEnabled } from "../src/autonomous_pivot.ts"
import { CredentialGraph } from "../src/credential_graph.ts"
import { loadPlaybook, nextPlaybookNode, buildPlaybookFromProfile, loadPlaybookInfra } from "../src/apt_playbook.ts"
import { loadAptProfiles } from "../src/apt_tradecraft.ts"
import { listExploitModules, getTelemetryStats } from "../src/exploit_adapter.ts"
import { runIdentityChain } from "../src/identity_chain.ts"
import { assessOperationalDepth } from "../src/operational_depth_score.ts"
import { assessRuntimeCapabilities, resolveScanCommand } from "../src/runtime_capability.ts"
import { selectC2Channel } from "../src/c2_rotation.ts"
import { executeSupplyChainChain } from "../src/supply_chain_exec.ts"
import { EngagementMemory } from "../src/engagement_memory.ts"
import { executeAgentTool } from "../src/agent_tools.ts"
import { bridgedToolNames } from "../src/module_bridge.ts"
import { startTier1LabServer } from "./fixtures/lab_http_harness.ts"

/** @type {import("./fixtures/lab_http_harness.ts").LabHttpHarness} */
let lab

before(async () => {
  process.env.OURMINE_LIVE = "1"
  process.env.OURMINE_TIER1 = "1"
  process.env.OURMINE_AUTONOMOUS = "1"
  lab = await startTier1LabServer(18100)
})

after(async () => {
  await lab.close()
  delete process.env.OURMINE_ALLOW_DRY_RUN
  await new Promise((r) => setTimeout(r, 100))
})

describe("P0: HTTP state fuzzer + L3/L4 validation (live)", () => {
  test("ValidationPlanner registers full L3/L4 strategies", () => {
    const caps = ValidationPlanner.listCapabilities()
    for (const s of ["HTTP_STATE_FUZZ", "L3_BYPASS", "L4_CONTROLLED_IMPACT", "IDOR_BOLA", "PRIVESC_PROOF", "EXPLOIT_REPLAY"]) {
      assert.ok(caps.some((c) => c.strategy === s), `missing ${s}`)
    }
  })

  test("L4 canary flow live against lab server", async () => {
    const result = await runStateMachineFlow(defaultL4CanaryFlow(lab.baseUrl), { live: true })
    assert.ok(result.steps.length >= 2)
    assert.ok(result.l4ImpactProven || result.validationLevel === "L4" || result.steps.some((s) => s.status === 200))
  })

  test("state machine flow live completes", async () => {
    const flow = defaultSessionFlow(lab.baseUrl)
    const result = await runStateMachineFlow(flow, { live: true })
    assert.ok(result.steps.length >= 2)
  })

  test("ValidationEngine live L4 on lab critical finding", async () => {
    const graph = new AttackSurfaceGraph("127.0.0.1")
    const ev = graph.makeEvidence("test", "manual", "critical impact", 1)
    graph.ingestNmap("127.0.0.1", [{ port: lab.port, protocol: "tcp", state: "open", service: "http" }], ev)
    const asset = graph.upsertAsset("127.0.0.1")
    const svc = asset.services.get(lab.port)
    assert.ok(svc)
    const vuln = {
      id: "lab-critical",
      title: "Critical data exposure",
      severity: "critical",
      confidence: "suspected",
      state: "SUSPECTED",
      capLevel: 2,
      evidence: [ev],
      cve: "critical-data-exposure",
    }
    svc.vulns.push(vuln)
    const engineResult = await ValidationEngine.validate({
      vuln, ip: "127.0.0.1", port: lab.port, service: "http critical impact", graph,
    })
    assert.ok(engineResult.plan?.strategy === "L4_CONTROLLED_IMPACT" || engineResult.validated || engineResult.result)
  })
})

describe("P0: Autonomous pivot (live lab)", () => {
  test("autonomous pivot enabled with OURMINE_AUTONOMOUS", async () => {
    assert.equal(isAutonomousPivotEnabled(), true)
    const graph = new AttackSurfaceGraph("127.0.0.1")
    const credGraph = new CredentialGraph()
    credGraph.addCredential({ type: "password", source: "test", username: "admin", value: "pass" })
    const r = await runAutonomousPivot({ graph, credGraph, live: true })
    assert.ok(r.summary.length > 0)
  })
})

describe("P1: APT playbook + credential persistence", () => {
  test("build playbook from APT profile with infra", () => {
    const profile = loadAptProfiles()[0]
    assert.ok(profile)
    const pb = buildPlaybookFromProfile(profile)
    assert.ok(pb.nodes.length > 0)
    assert.ok(pb.infra || pb.vertical)
  })

  test("apt playbook infra loaded", () => {
    const infra = loadPlaybookInfra("scattered_spider")
    assert.ok(infra)
    assert.ok(infra.fallbackChain.length > 0)
  })

  test("CredentialGraph save/load roundtrip", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-cred-"))
    const fp = path.join(tmp, "cred.json")
    const g = new CredentialGraph()
    g.addCredential({ type: "password", source: "test", username: "u", value: "p" })
    g.save(fp)
    const loaded = CredentialGraph.load(fp)
    assert.equal(loaded.listCredentials().length, 1)
  })
})

describe("P2: Exploit adapter + identity + runtime + depth", () => {
  test("identity chain live", async () => {
    const state = await runIdentityChain(lab.baseUrl.replace("http://", ""), { live: true })
    assert.ok(state.steps.length > 0)
  })

  test("operational depth tier1_ready", { timeout: 60_000 }, async () => {
    const report = await assessOperationalDepth()
    assert.ok(report.overall >= 8.5, `depth ${report.overall}`)
    assert.equal(report.tier, "tier1_ready")
  })
})

describe("Round-2: live tier1 modules", () => {
  test("tier1 validation live IDOR/L4", async () => {
    const { runTier1ValidationSuite } = await import("../src/tier1_validation.ts")
    const r = await runTier1ValidationSuite(lab.baseUrl, { live: true })
    assert.ok(r.fuzz.steps.every((s) => s.detail !== "live execution required — no simulation"))
    assert.ok(r.idor.proven || r.fuzz.l4ImpactProven || r.fuzz.steps.some((s) => s.status === 200))
  })

  test("campaign loop live", async () => {
    const { runCampaignLoop } = await import("../src/campaign_loop.ts")
    const graph = new AttackSurfaceGraph("127.0.0.1")
    graph.upsertAsset("127.0.0.2")
    const credGraph = new CredentialGraph()
    credGraph.addCredential({ type: "password", source: "t", username: "a", value: "p" })
    const r = await runCampaignLoop({ graph, credGraph, target: "127.0.0.1", live: true })
    assert.ok(!r.summary.includes("simulation"))
  })

  test("segment tunnel orchestration live", async () => {
    const { orchestrateSegmentTunnels } = await import("../src/segment_tunnel_orchestrator.ts")
    const graph = new AttackSurfaceGraph("127.0.0.1")
    graph.upsertAsset("127.0.0.2")
    graph.upsertAsset("127.0.0.3")
    const r = await orchestrateSegmentTunnels(graph, { live: true, basePort: 12080 })
    assert.ok(r.tunnels.length >= 1)
  })

  test("edr feedback loop live", async () => {
    const { runEdrFeedbackLoop } = await import("../src/edr_feedback_loop.ts")
    const r = await runEdrFeedbackLoop({ live: true })
    assert.ok(r.iterations.length >= 1)
  })

  test("privesc chains live", async () => {
    const { runPrivescChains } = await import("../src/privesc_chains.ts")
    const r = await runPrivescChains({ live: true })
    assert.ok(r.steps.length > 0)
  })

  test("esxi lab encrypt recovery", async () => {
    const { runLabEsxiEncryptWithRecovery } = await import("../src/raas_advanced.ts")
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-esxi-"))
    const r = runLabEsxiEncryptWithRecovery(tmp)
    assert.equal(r.recovered, true)
  })

  test("tier1 orchestrator live", { timeout: 120_000 }, async () => {
    const { runTier1Orchestrator } = await import("../src/tier1_orchestrator.ts")
    const graph = new AttackSurfaceGraph("127.0.0.1")
    graph.ingestNmap("127.0.0.1", [{ port: lab.port, protocol: "tcp", state: "open", service: "http" }], graph.makeEvidence("t", "t", "t", 1))
    graph.upsertAsset("127.0.0.2")
    const r = await runTier1Orchestrator({ target: lab.baseUrl, graph, live: true })
    assert.equal(r.live, true)
    assert.ok(r.validation.fuzz.l4ImpactProven || r.validation.idor.proven || r.validation.fuzz.steps.some((s) => s.status === 200))
  })
})

describe("Wiring: bridged tools", () => {
  test("new tier-1 tools registered", () => {
    const names = bridgedToolNames()
    for (const t of ["segment_tunnel", "edr_feedback_loop", "privesc_chains", "multi_cloud_asm", "c2_dwell_scheduler", "esxi_lab_encrypt"]) {
      assert.ok(names.includes(t), `missing ${t}`)
    }
  })
})
