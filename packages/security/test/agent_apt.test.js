import test from "node:test"
import assert from "node:assert"
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const tmpDir = path.join(__dirname, ".tmp_agent_apt")

test("PentestAgent APT loop (dry-run)", async () => {
  fs.rmSync(tmpDir, { recursive: true, force: true })
  fs.mkdirSync(tmpDir, { recursive: true })

  const { PentestAgent } = await import("../src/pentestgpt_agent.ts")
  const agent = new PentestAgent({
    target: "127.0.0.1:8080",
    scope: ["127.0.0.1"],
    storageDir: tmpDir,
    live: false,
    maxSteps: 8,
  })

  const result = await agent.runAutonomous()

  assert.ok(result.summary)
  assert.ok(result.steps.length > 0, "agent should execute at least one step")
  assert.ok(result.summary.graph, "summary should include attack surface graph")
  assert.ok(result.summary.graph.services >= 1, "nmap seed should populate services")
  assert.ok(result.summary.ptt, "summary should include PTT progress")

  const graph = agent.getGraph()
  const gs = graph.summary()
  assert.ok(gs.toolCalls >= 1 || gs.services >= 1)

  const asmFiles = fs.readdirSync(tmpDir).filter((f) => f.startsWith("asm_"))
  assert.ok(asmFiles.length >= 1, "graph session should persist to disk")

  fs.rmSync(tmpDir, { recursive: true, force: true })
})

test("APT tradecraft maps to agent tools", async () => {
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const { recommendFromTradecraft, shouldEscalatePostExploit, APT_PROFILES } = await import("../src/apt_tradecraft.ts")

  assert.ok(APT_PROFILES.length >= 5)
  const graph = new AttackSurfaceGraph("127.0.0.1")
  graph.upsertAsset("127.0.0.1")
  const recs = recommendFromTradecraft(graph, "127.0.0.1", "recon")
  assert.ok(recs.some((r) => r.tool === "cloud_enum"))
  assert.ok(recs.some((r) => r.tool === "lockfile_scan"))

  const escalation = shouldEscalatePostExploit(graph)
  assert.strictEqual(escalation.escalate, false)

  const scanRecs = recommendFromTradecraft(graph, "127.0.0.1", "scan")
  assert.ok(scanRecs.some((r) => r.tool === "postex_pivot") || scanRecs.some((r) => r.tool === "evilginx_lab"))
})

test("executeAgentTool dispatches full registry", async () => {
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const { ToolBroker } = await import("../src/tool_broker.ts")
  const { executeAgentTool } = await import("../src/agent_tools.ts")

  const ctx = { target: "127.0.0.1", graph: new AttackSurfaceGraph("127.0.0.1"), broker: new ToolBroker(), live: false }
  const res = await executeAgentTool(ctx, "recon", { domain: "example.com" })
  assert.strictEqual(res.tool, "recon")
  assert.strictEqual(res.success, true)
})

test("supply_chain scanLockfile detects poison indicators", async () => {
  const tmp = path.join(__dirname, ".tmp_lockfile.json")
  fs.writeFileSync(tmp, JSON.stringify({
    packages: {
      "node_modules/lodash": { version: "4.17.21" },
      "node_modules/easy-day-js": { version: "1.0.0" },
      "node_modules/reqeusts": { version: "2.0.0" },
    },
  }))
  const { scanLockfile } = await import("../src/supply_chain.ts")
  const result = await scanLockfile(tmp, { live: false, maxAudit: 5 })
  assert.ok(result.poisonHits.some((p) => p.name === "easy-day-js"))
  assert.ok(result.packageCount >= 3)
  fs.unlinkSync(tmp)
})

test("evilginx_lab generates phishlet config", async () => {
  const { generatePhishletYaml, runLabSession, isEvilginxAvailable } = await import("../src/evilginx_lab.ts")
  const yaml = generatePhishletYaml({ targetUrl: "https://login.microsoftonline.com/", phishlet: "o365" })
  assert.ok(yaml.includes("proxy_hosts"))
  assert.ok(yaml.includes("login.microsoftonline.com"))
  const session = await runLabSession({ targetUrl: "https://login.microsoftonline.com/", live: false })
  assert.strictEqual(session.dryRun, true)
  assert.ok(session.phishletPath)
  assert.strictEqual(typeof isEvilginxAvailable(), "boolean")
})

test("LivePivotEngine loads and reports tool availability", async () => {
  const { LivePivotEngine } = await import("../src/live_pivot.ts")
  const engine = new LivePivotEngine()
  const findings = await engine.smbEnum("127.0.0.1")
  assert.ok(Array.isArray(findings))
})

test("agent_tools graph ingestion (dry-run nmap)", async () => {
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const { ToolBroker } = await import("../src/tool_broker.ts")
  const { nmapScan, graphFindingsToAgentFindings } = await import("../src/agent_tools.ts")

  const graph = new AttackSurfaceGraph("127.0.0.1")
  graph.upsertAsset("127.0.0.1")
  const ctx = { target: "127.0.0.1:8080", graph, broker: new ToolBroker(), live: false }

  const res = await nmapScan(ctx)
  assert.strictEqual(res.success, true)
  assert.ok(graph.summary().services >= 1)

  graph.analyzeAttackPaths()
  const findings = graphFindingsToAgentFindings(graph, "127.0.0.1:8080")
  assert.ok(Array.isArray(findings))
})
