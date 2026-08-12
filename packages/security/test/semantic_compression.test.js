/**
 * Semantic compression — host refs + delta-only continue payloads
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  compressHostList,
  compressEngagementPayload,
  snapshotFromPayload,
  buildEngagementDelta,
  compressIntelMeta,
} from "../src/semantic_compression.ts"

describe("semantic_compression", () => {
  test("compressHostList replaces repeated hosts with refs", () => {
    const hosts = [
      { host: "10.0.0.1", openPorts: [445, 88] },
      { host: "10.0.0.2", openPorts: [502] },
      { host: "10.0.0.1", openPorts: [445, 88] },
    ]
    const { refs, registry, savedBytes } = compressHostList("10.0.0.0/24", hosts)
    assert.deepEqual(refs, ["@h1", "@h2", "@h1"])
    assert.equal(registry.entries.length, 2)
    assert.ok(savedBytes > 0)
  })

  test("buildEngagementDelta omits unchanged fields", () => {
    const prev = snapshotFromPayload({
      confirmed: [{ kind: "svc", label: "ldap" }],
      candidates: [],
      blockers: ["dry-run"],
      phaseResult: { phase: "recon", stepsOk: 4, stepCount: 6 },
    })
    const delta = buildEngagementDelta(prev, {
      summary: "Slice identity on corp.example.com",
      confirmed: [{ kind: "svc", label: "ldap" }, { kind: "cred", label: "spray" }],
      candidates: [{ kind: "vuln", label: "kerb" }],
      blockers: ["dry-run"],
      phaseResult: { phase: "identity", stepsOk: 2, stepCount: 3 },
      recommendedNextPhase: "exploit",
    })
    assert.equal(delta.d, true)
    assert.equal(delta.ph, "identity")
    assert.equal(delta.ok, "2/3")
    assert.equal(delta.cf, 2)
    assert.equal(delta.cd, 1)
    assert.equal(delta.nxp, "exploit")
    assert.equal(delta.bk, undefined)
  })

  test("compressIntelMeta packs 2-char keys", () => {
    const meta = compressIntelMeta({
      iabStage: "initial_access",
      extortionOnly: true,
      deviceCodeFindings: [{ severity: "high" }, { severity: "info" }],
      staleWarning: "INTEL_STALE: ransomwatch cache 9d old (TTL 7d)",
    })
    assert.equal(meta.ib, "ia")
    assert.equal(meta.eo, true)
    assert.equal(meta.dc, "2h1")
    assert.equal(meta.st, "9")
  })

  test("compressEngagementPayload shrinks large otHosts arrays", () => {
    const otHosts = Array.from({ length: 8 }, (_, i) => ({
      host: `10.0.1.${i + 1}`,
      openPorts: [502, 44818],
    }))
    const { compressed, savedBytes } = compressEngagementPayload({
      target: "plant.local",
      otHosts,
    })
    assert.ok(Array.isArray(compressed.otHostRefs))
    assert.equal(compressed.otHosts, undefined)
    assert.ok(savedBytes > 0)
  })
})
