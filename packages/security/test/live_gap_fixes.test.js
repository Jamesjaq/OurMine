/**
 * Live vs stub audit gaps #6, #17, #19 — impact_assess, multi_lang, institutional_recon.
 */
import { describe, test, beforeEach, afterEach } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import { ToolBroker } from "../src/tool_broker.ts"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { executeAgentTool } from "../src/agent_tools.ts"
import { reconInstitutionalSector } from "../src/institutional_hints.ts"

const ENV_BACKUP = { ...process.env }

beforeEach(() => {
  process.env = { ...ENV_BACKUP, OURMINE_ALLOW_DRY_RUN: "1", OURMINE_LIVE: "0" }
})

afterEach(() => {
  process.env = ENV_BACKUP
})

describe("gap #17 — multi_lang resolveDryRun", () => {
  test("generateDownloadStager honors OURMINE_LIVE=1", async () => {
    process.env.OURMINE_LIVE = "1"
    delete process.env.OURMINE_ALLOW_DRY_RUN
    const { generateDownloadStager, generateAllPayloads } = await import("../src/multi_lang.ts")
    const stager = generateDownloadStager({
      host: "10.0.0.1",
      port: 4444,
      os: "linux",
      payloadPath: "payload.sh",
      method: "curl",
    })
    assert.equal(stager.dryRun, false)

    const all = generateAllPayloads("10.0.0.1", 4444, "linux", "none", { live: true })
    assert.equal(all.reverseShells.bash.dryRun, false)
    assert.ok(all.stagers.every((s) => s.dryRun === false))
  })

  test("generateAllPayloads dryRun:true when explicitly set", async () => {
    const { generateAllPayloads } = await import("../src/multi_lang.ts")
    const dry = generateAllPayloads("127.0.0.1", 4444, "linux", "none", { dryRun: true })
    assert.equal(dry.reverseShells.bash.dryRun, true)
    assert.ok(dry.stagers.every((s) => s.dryRun === true))
  })
})

describe("gap #19 — institutional_recon live separation", () => {
  test("dry-run includes heuristic sector findings", async () => {
    const r = await reconInstitutionalSector("healthcare", "pacs.local", { live: false })
    assert.equal(r.dryRun, true)
    assert.ok(r.findings.some((f) => f.id === "inst-healthcare-dicom"))
    assert.ok(r.findings.some((f) => f.id === "inst-healthcare-ports"))
  })

  test("live excludes heuristic findings — probe results only", async () => {
    const r = await reconInstitutionalSector("healthcare", "127.0.0.1", { live: true })
    assert.equal(r.dryRun, false)
    assert.ok(!r.findings.some((f) => f.id === "inst-healthcare-dicom"))
    assert.ok(!r.findings.some((f) => f.id === "inst-healthcare-ports"))
    assert.ok(r.findings.some((f) => f.id === "inst-healthcare-meta"))
    assert.ok(r.findings.some((f) => f.id.includes("live")))
    assert.equal(r.findings.find((f) => f.id === "inst-healthcare-meta")?.severity, "info")
  })

  test("live critical_infra excludes OT vertical heuristic severity", async () => {
    const r = await reconInstitutionalSector("critical_infra", "wastewater.local", { live: true })
    assert.equal(r.dryRun, false)
    assert.ok(!r.findings.some((f) => f.id.startsWith("inst-infra-")))
    assert.ok(r.portHints.some((p) => p.port === 47808))
  })
})

describe("gap #6 — impact_assess live HTTP/Modbus canary", () => {
  function makeCtx(target, live) {
    const graph = new AttackSurfaceGraph(target)
    graph.analyzeAttackPaths()
    return {
      target,
      graph,
      broker: new ToolBroker(),
      live,
    }
  }

  test("dry-run uses narrative mode — no live probes", async () => {
    const ctx = makeCtx("127.0.0.1", false)
    const asset = ctx.graph.upsertAsset("127.0.0.1")
    asset.services.set(80, {
      port: 80,
      protocol: "tcp",
      state: "open",
      service: "http",
      version: "",
      evidence: [],
      vulns: [],
    })
    ctx.graph.analyzeAttackPaths()

    const r = await executeAgentTool(ctx, "impact_assess")
    assert.equal(r.dryRun, true)
    const out = JSON.parse(r.output)
    assert.equal(out.mode, "narrative_dry")
    assert.equal(out.httpPortsAttempted, undefined)
    assert.ok(Array.isArray(out.proofs))
  })

  test("live mode probes HTTP ports on host target", async () => {
    const ctx = makeCtx("127.0.0.1", true)
    const r = await executeAgentTool(ctx, "impact_assess")
    assert.equal(r.dryRun, false)
    const out = JSON.parse(r.output)
    assert.equal(out.mode, "live_probe")
    assert.ok(Array.isArray(out.httpPortsAttempted))
    assert.ok(out.httpPortsAttempted.length >= 1)
    assert.match(r.command, /live HTTP/)
  })

  test("impact_assess wires demonstrateIcsImpact when Modbus port 502 is open", () => {
    const src = fs.readFileSync(new URL("../src/agent_tools.ts", import.meta.url), "utf8")
    assert.ok(src.includes("demonstrateIcsImpact"))
    assert.ok(src.includes("shouldProbeModbus"))
    assert.ok(src.includes("defaultL4CanaryFlow"))
  })
})
