import test from "node:test"
import assert from "node:assert"

test("iot_scada dry-run returns no fabricated modbus data", async () => {
  const { readModbusCoils, executeScadaAction } = await import("../src/iot_scada.ts")
  const r = await readModbusCoils("127.0.0.1", 502, 1, 0, 5, false)
  assert.strictEqual(r.dryRun, true)
  assert.strictEqual(r.data.length, 0)
  assert.ok(r.error?.includes("live"))
  const action = await executeScadaAction({ host: "127.0.0.1", protocol: "modbus" }, { dryRun: true })
  assert.strictEqual(action.dryRun, true)
  assert.strictEqual(action.success, false)
})

test("telecom_audit dry-run returns empty findings", async () => {
  const { auditTelecom } = await import("../src/telecom_audit.ts")
  const r = await auditTelecom("127.0.0.1", { dryRun: true })
  assert.strictEqual(r.dryRun, true)
  assert.strictEqual(r.findings.length, 0)
  assert.strictEqual(r.openTelecomPorts.length, 0)
})

test("auto_research does not return simulated CVE on dry-run fetch path", async () => {
  const { researchCve } = await import("../src/auto_research.ts")
  const src = await import("node:fs/promises").then((fs) => fs.readFile(new URL("../src/auto_research.ts", import.meta.url), "utf8"))
  assert.ok(!src.includes("[DRY RUN] Simulated CVE record"))
})

test("persistence install dry-run does not execute", async () => {
  const { PersistenceEngine } = await import("../src/persistence.ts")
  const engine = new PersistenceEngine()
  const r = await engine.installPersistence("cron job", { live: false })
  assert.strictEqual(r.installed, false)
  assert.strictEqual(r.dryRun, true)
})

test("bridged ot_scan and telecom_audit dispatch", async () => {
  const { executeAgentTool } = await import("../src/agent_tools.ts")
  const { ToolBroker } = await import("../src/tool_broker.ts")
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const graph = new AttackSurfaceGraph("ot.local")
  const ctx = { target: "ot.local", graph, broker: new ToolBroker(), live: false }
  for (const t of ["ot_scan", "telecom_audit", "iot_scada", "persistence_install", "auto_research"]) {
    const r = await executeAgentTool(ctx, t, {})
    assert.ok(!r.error?.includes("unknown tool"), `${t}: ${r.error}`)
  }
})
