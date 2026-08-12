/**
 * Artifact indirection + pivot scorer + resume token tests
 */
import { describe, test, before, after } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"
import { writeArtifact, readArtifact, shouldStoreAsArtifact } from "../src/mcp_artifacts.ts"
import { formatMcpToolResponse } from "../src/mcp_response.ts"
import {
  buildResumeToken,
  buildRankedResumeToken,
  saveScanState,
  loadScanState,
  scanOtSubnet,
  scanRankedOtSubnets,
} from "../src/ot_batch_scan.ts"
import { scoreOtSubnets } from "../src/pivot_scorer.ts"
import { buildEngagementGraph } from "../src/engagement_graph.ts"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { CredentialGraph } from "../src/credential_graph.ts"
import { clearProbeCache } from "../src/probe_dedupe.ts"

describe("mcp_artifacts", () => {
  test("write/read round-trip", () => {
    const id = writeArtifact("test", { summary: "hello", steps: [1, 2, 3] })
    const payload = readArtifact(id)
    assert.deepEqual(payload, { summary: "hello", steps: [1, 2, 3] })
  })

  test("shouldStoreAsArtifact on large steps array", () => {
    assert.equal(
      shouldStoreAsArtifact({ summary: "x", steps: Array.from({ length: 10 }, (_, i) => ({ i })) }),
      true,
    )
  })

  test("formatMcpToolResponse indirection", () => {
    process.env.OURMINE_MCP_EFFICIENT = "1"
    const text = formatMcpToolResponse({
      summary: "big",
      steps: Array.from({ length: 12 }, (_, i) => ({ module: `m${i}`, success: true })),
    })
    const p = JSON.parse(text)
    assert.ok(p.artifactId)
    assert.ok(p.preview)
    const full = readArtifact(p.artifactId)
    assert.ok(full && typeof full === "object")
  })
})

describe("ot_batch_scan resume", () => {
  test("resume token round-trip", async () => {
    const token = buildResumeToken("10.0.0.0/16", 64, 32)
    saveScanState(token, {
      cidr: "10.0.0.0/16",
      offset: 64,
      maxHosts: 32,
      nextOffset: 96,
      totalHosts: 65534,
      hasMore: true,
      updatedAt: new Date().toISOString(),
    })
    const loaded = loadScanState(token)
    assert.equal(loaded?.offset, 64)
    assert.equal(loaded?.maxHosts, 32)

    const r = await scanOtSubnet("10.0.0.0/16", { live: false, maxHosts: 8, offset: 0 })
    assert.equal(r.dryRun, true)
    assert.ok(r.resumeToken)
  })
})

describe("pivot_scorer", () => {
  test("cred-graph subnet ranks higher", () => {
    const g = new CredentialGraph()
    g.addCredential({ type: "password", source: "test", host: "192.168.50.10", value: "x" })
    const scores = scoreOtSubnets(["10.0.0.0/24", "192.168.50.0/24"], g, [])
    assert.ok(scores[0].subnet.includes("192.168.50"))
    assert.ok(scores[0].confidence >= scores[1].confidence)
  })

  test("engagement graph includes pivot candidates with confidence", () => {
    const graph = new AttackSurfaceGraph("corp.local")
    const cred = new CredentialGraph()
    cred.addCredential({ type: "password", source: "test", host: "192.168.50.10", value: "x" })
    const scores = scoreOtSubnets(["192.168.50.0/24"], cred, [])
    const eg = buildEngagementGraph({
      target: "corp.local",
      graph,
      credGraph: cred,
      objective: "hybrid_it_ot",
      live: false,
      pivotScores: scores,
    })
    assert.ok(eg.candidates.some((c) => c.kind === "ot_pivot"))
    assert.ok(eg.pivotScores?.[0]?.confidence >= 0.35)
  })
})

before(() => clearProbeCache())
after(() => clearProbeCache())
