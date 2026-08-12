/**
 * OT batch scan + ICS validation tests
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { expandCidr, expandCidrPaginated, classifyOtHost, buildRankedResumeToken, scanRankedOtSubnets } from "../src/ot_batch_scan.ts"
import { scoreOtSubnets } from "../src/pivot_scorer.ts"
import { proveIcsImpact, assessOtRansomReadiness, icsImpactToEngineProof, evaluateWriteLabResult } from "../src/ics_impact_proof.ts"
import { buildSemanticProcessState } from "../src/ics_semantics.ts"
import { inferPlantSubnets } from "../src/ot_segment_infer.ts"
import { CredentialGraph } from "../src/credential_graph.ts"
import { buildActionablePlan } from "../src/pentest_plan_builder.ts"

describe("ot_batch_scan", () => {
  test("expandCidr /24 yields bounded host list", () => {
    const hosts = expandCidr("10.0.1.0/24", 10)
    assert.equal(hosts.length, 10)
    assert.equal(hosts[0], "10.0.1.1")
  })

  test("expandCidrPaginated /16 supports chunking", () => {
    const page = expandCidrPaginated("10.0.0.0/16", { maxHosts: 100, offset: 0 })
    assert.equal(page.hosts.length, 100)
    assert.ok(page.total > 60000)
    assert.equal(page.hasMore, true)
    assert.equal(page.nextOffset, 100)
  })

  test("classifyOtHost dry-run uses flow profile", async () => {
    const r = await classifyOtHost("192.168.1.100", false)
    assert.equal(r.host, "192.168.1.100")
    assert.equal(r.probeSummary, "dry-run")
  })

  test("scanRankedOtSubnets dry-run ranks subnets", async () => {
    const g = new CredentialGraph()
    g.addCredential({ type: "password", source: "test", host: "192.168.50.10", value: "x" })
    const r = await scanRankedOtSubnets(["10.0.0.0/24", "192.168.50.0/24"], { live: false, maxHosts: 4, credGraph: g })
    assert.equal(r.dryRun, true)
    assert.ok(r.subnetScores.length >= 2)
    assert.ok(r.subnetScores[0].subnet.includes("192.168.50"))
    assert.ok(r.resumeToken)
  })

  test("buildRankedResumeToken is deterministic length", () => {
    const t = buildRankedResumeToken(["10.0.0.0/24"], 0, 0, 32)
    assert.equal(t.length, 16)
  })
})

describe("ics_impact_proof", () => {
  test("proveIcsImpact dry-run is safe", async () => {
    const r = await proveIcsImpact({ host: "10.0.0.5", live: false })
    assert.equal(r.dryRun, true)
    assert.equal(r.proofType, "REGISTER_READ")
  })

  test("semantic process state maps valve/interlock", () => {
    const state = buildSemanticProcessState("10.0.0.5", [
      { address: 100, value: 1 },
      { address: 102, value: 0 },
    ])
    assert.ok(state.valveStates.length >= 1)
    assert.ok(state.safetyInterlocks.length >= 1)
    assert.ok(state.impactNarrative.includes("10.0.0.5"))
  })

  test("icsImpactToEngineProof promotes semantic proof", () => {
    const ics = {
      host: "10.0.0.5",
      protocol: "modbus",
      proofType: "SEMANTIC_PROCESS_IMPACT",
      success: true,
      dryRun: false,
      safetyNote: "ok",
      mitre: "T0827",
      semantic: buildSemanticProcessState("10.0.0.5", [{ address: 102, value: 0 }]),
    }
    const proof = icsImpactToEngineProof("v1", ics)
    assert.ok(proof)
    assert.equal(proof.safeProofMarker, "PROOF_ICS_SEMANTIC_STATE")
  })

  test("assessOtRansomReadiness never claims PLC encrypt", async () => {
    const r = await assessOtRansomReadiness("10.0.0.5", false)
    assert.ok(!r.recommendation.toLowerCase().includes("encrypt plc"))
    assert.ok(r.recommendation.includes("perimeter") || r.recommendation.includes("engineering") || r.recommendation.includes("HMI"))
  })

  test("write lab marks restoreFailed when verify value mismatches", () => {
    const bad = evaluateWriteLabResult({ writeOk: true, restoreOk: true, verifyValue: 99, original: 42 })
    assert.equal(bad.restoreFailed, true)
    assert.equal(bad.success, false)
    assert.ok(bad.safetyNote.includes("restore FAILED"))
    const good = evaluateWriteLabResult({ writeOk: true, restoreOk: true, verifyValue: 42, original: 42 })
    assert.equal(good.restoreVerified, true)
    assert.equal(good.success, true)
  })
})

describe("hybrid planning", () => {
  test("hybrid objective plans IT-OT pivot", () => {
    const plan = buildActionablePlan("corp.example.com", { objective: "hybrid it-ot pivot" })
    assert.equal(plan.objective, "hybrid_it_ot")
    assert.ok(plan.nextActions.some((a) =>
      a.tool === "ares_engagement_slice"
      || a.args.module === "hybrid_pivot"
      || a.tool === "ares_dispatch",
    ))
  })

  test("cidr target notes batch scan chunking gap", () => {
    const plan = buildActionablePlan("10.0.0.0/24", { objective: "scada" })
    assert.ok(plan.gaps?.some((g) => g.includes("resumeToken") || g.includes("OURMINE_OT_SCAN_MAX")))
  })

  test("inferPlantSubnets uses cred graph private hosts", () => {
    const g = new CredentialGraph()
    g.addCredential({ type: "password", source: "test", host: "192.168.50.10", value: "x" })
    const subnets = inferPlantSubnets({ target: "corp.example.com", credGraph: g })
    assert.ok(subnets.includes("192.168.50.0/24"))
  })
})
