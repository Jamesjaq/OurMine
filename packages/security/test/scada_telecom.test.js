import test from "node:test"
import assert from "node:assert"

test("iot_scada dry-run returns no fabricated modbus data", async () => {
  const {
    readModbusCoils, readModbusHoldingRegisters, executeScadaAction,
    probeCoap, probeProfinet, probeMqtt, probeS7, exploitMqtt, exploitCoap, exploitS7,
  } = await import("../src/iot_scada.ts")
  const coil = await readModbusCoils("127.0.0.1", 502, 1, 0, 5, false)
  assert.strictEqual(coil.dryRun, true)
  assert.strictEqual(coil.data.length, 0)
  assert.strictEqual(coil.success, false)
  assert.ok(coil.error?.includes("live"))
  const holding = await readModbusHoldingRegisters("127.0.0.1", 502, 1, 0, 4, false)
  assert.strictEqual(holding.dryRun, true)
  assert.strictEqual(holding.data.length, 0)
  assert.strictEqual(holding.success, false)
  assert.ok(holding.error?.includes("live"))
  const action = await executeScadaAction({ host: "127.0.0.1", protocol: "modbus" }, { dryRun: true })
  assert.strictEqual(action.dryRun, true)
  assert.strictEqual(action.success, false)
  assert.ok(action.error?.includes("live"))
  const coap = await probeCoap("127.0.0.1", 5683, false)
  assert.strictEqual(coap.dryRun, true)
  assert.strictEqual(coap.success, false)
  const pn = await probeProfinet("127.0.0.1", 34964, false)
  assert.strictEqual(pn.dryRun, true)
  assert.strictEqual(pn.success, false)
  const mqtt = await probeMqtt("127.0.0.1", 1883, "ourmine_probe", false)
  assert.strictEqual(mqtt.dryRun, true)
  assert.strictEqual(mqtt.success, false)
  const s7 = await probeS7("127.0.0.1", 102, false)
  assert.strictEqual(s7.dryRun, true)
  assert.strictEqual(s7.success, false)
  const mqttExploit = await exploitMqtt("127.0.0.1", 1883, false)
  assert.strictEqual(mqttExploit.dryRun, true)
  assert.ok(!mqttExploit.error?.includes("not implemented"))
  const coapExploit = await exploitCoap("127.0.0.1", 5683, false)
  assert.strictEqual(coapExploit.dryRun, true)
  assert.ok(!coapExploit.error?.includes("not implemented"))
  const s7Exploit = await exploitS7("127.0.0.1", 102, false)
  assert.strictEqual(s7Exploit.dryRun, true)
  assert.ok(s7Exploit.error?.includes("live"))
})

test("executeScadaAction exploit paths wired for mqtt coap s7 (dry-run)", async () => {
  const { executeScadaAction } = await import("../src/iot_scada.ts")
  for (const protocol of ["mqtt", "coap", "s7"]) {
    const r = await executeScadaAction(
      { host: "127.0.0.1", protocol, action: "exploit" },
      { dryRun: true },
    )
    assert.strictEqual(r.dryRun, true, `${protocol} exploit dry-run`)
    assert.strictEqual(r.success, false)
    assert.ok(r.error?.includes("live"), `${protocol}: ${r.error}`)
    assert.ok(!r.error?.includes("not implemented"), `${protocol} exploit must be wired`)
  }
  for (const [protocol, action] of [["mqtt", "fuzz"], ["coap", "fuzz"], ["s7", "fuzz"]]) {
    const r = await executeScadaAction(
      { host: "127.0.0.1", protocol, action },
      { dryRun: true },
    )
    assert.strictEqual(r.dryRun, true, `${protocol} ${action} dry-run gate`)
    assert.ok(!r.error?.includes("not implemented"))
  }
})

test("ics_validation dry-run returns VALIDATION_UNAVAILABLE not fake success", async () => {
  const prev = process.env.OURMINE_ALLOW_DRY_RUN
  process.env.OURMINE_ALLOW_DRY_RUN = "1"
  try {
    const {
      modbusValidationProbe, dnp3ValidationProbe, bacnetValidationProbe,
      mqttValidationProbe, coapValidationProbe, s7ValidationProbe, icsValidationProbe,
    } = await import("../src/ics_validation.ts")
    const { buildDnp3ReadIinFrame, parseBacnetDeviceInstance } = await import("../src/iot_scada.ts")
    const plan = { planId: "p1", findingId: "f1" }
    const t0 = Date.now()
    for (const probe of [
      () => modbusValidationProbe(plan, "10.0.0.1", 502, t0),
      () => dnp3ValidationProbe(plan, "10.0.0.1", 20000, t0),
      () => bacnetValidationProbe(plan, "10.0.0.1", 47808, t0),
      () => mqttValidationProbe(plan, "10.0.0.1", 1883, t0),
      () => coapValidationProbe(plan, "10.0.0.1", 5683, t0),
      () => s7ValidationProbe(plan, "10.0.0.1", 102, t0),
    ]) {
      const r = await probe()
      assert.strictEqual(r.outcome, "VALIDATION_UNAVAILABLE")
      assert.ok(r.evidence.includes("live required"))
    }
    for (const [hint, port] of [["mqtt", 1883], ["coap", 5683], ["s7", 102]]) {
      const r = await icsValidationProbe({ ...plan, serviceHint: hint }, "10.0.0.1", port, t0)
      assert.strictEqual(r.outcome, "VALIDATION_UNAVAILABLE", `icsValidationProbe ${hint}`)
      assert.ok(r.evidence.includes("live required"))
    }
    assert.ok(buildDnp3ReadIinFrame().length > 10)
    assert.equal(parseBacnetDeviceInstance(Buffer.alloc(0)), null)
  } finally {
    if (prev === undefined) delete process.env.OURMINE_ALLOW_DRY_RUN
    else process.env.OURMINE_ALLOW_DRY_RUN = prev
  }
})

test("ValidationPlanner registers MQTT COAP S7 ICS probe strategies", async () => {
  const { ValidationPlanner } = await import("../src/validation_planner.ts")
  const cases = [
    ["mqtt broker 1883", 1883, "MQTT_PROBE"],
    ["coap lwm2m 5683", 5683, "COAP_PROBE"],
    ["siemens s7comm 102", 102, "S7_PROBE"],
  ]
  for (const [service, port, strategy] of cases) {
    const planned = ValidationPlanner.plan({
      findingId: `ics-${strategy}`,
      templateId: "ot-exposure",
      service,
      target: `10.0.0.50:${port}`,
      authorizedScope: "10.0.0.50",
    })
    assert.ok(planned.plan, `expected plan for ${service}`)
    assert.equal(planned.plan.strategy, strategy)
    assert.equal(planned.plan.serviceHint, service)
    assert.ok(planned.plan.command?.includes("ics_validation.ts"))
  }
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
