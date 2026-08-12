/**
 * ARES APT-parity module tests — live execution against local harness.
 */
import { describe, test, before } from "node:test"
import assert from "node:assert/strict"

import { ARES_MODULE_NAMES } from "../src/ares/index.ts"
import { bridgedToolNames, runBridgedModule } from "../src/module_bridge.ts"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { CredentialGraph } from "../src/credential_graph.ts"

const ctx = () => ({
  target: "127.0.0.1",
  live: true,
  graph: new AttackSurfaceGraph("127.0.0.1"),
  credGraph: CredentialGraph.load(),
})

before(() => {
  process.env.OURMINE_LIVE = "1"
  process.env.OURMINE_TIER1 = "1"
})

describe("ARES: module registry", () => {
  test("all 18 ARES modules registered in bridge", () => {
    const bridged = bridgedToolNames()
    for (const name of ARES_MODULE_NAMES) {
      assert.ok(bridged.includes(name), `missing bridge entry: ${name}`)
    }
  })
})

describe("ARES: live execution smoke", () => {
  test("ares_zero_day_fuzzer runs live", async () => {
    const r = await runBridgedModule(ctx(), "ares_zero_day_fuzzer", { target: "echo", rounds: 8 })
    assert.ok(r)
    assert.equal(r.success, true)
    assert.match(r.output, /Zero-day fuzzer/)
  })

  test("ares_fileless_implant builds artifacts", async () => {
    const r = await runBridgedModule(ctx(), "ares_fileless_implant", {})
    assert.ok(r?.success)
    assert.match(r.output, /Fileless implant/)
  })

  test("ares_evasion_engine generates techniques", async () => {
    const r = await runBridgedModule(ctx(), "ares_evasion_engine", {})
    assert.ok(r?.success)
    assert.match(r.output, /Evasion engine/)
  })

  test("ares_rat_builder generates RAT scaffold", async () => {
    const r = await runBridgedModule(ctx(), "ares_rat_builder", { c2_host: "127.0.0.1" })
    assert.ok(r?.success)
    assert.match(r.output, /RAT builder/)
  })

  test("ares_airgap_bridge compiles USB channel", async () => {
    const r = await runBridgedModule(ctx(), "ares_airgap_bridge", { channel: "usb" })
    assert.ok(r?.success)
    assert.match(r.output, /Air-gap bridge/)
  })

  test("ares_firmware_implant writes scaffolds", async () => {
    const r = await runBridgedModule(ctx(), "ares_firmware_implant", {})
    assert.ok(r?.success)
    assert.match(r.output, /Firmware implant/)
  })

  test("ares_cloud_native probes platforms", async () => {
    const r = await runBridgedModule(ctx(), "ares_cloud_native", {})
    assert.ok(r?.success)
    assert.match(r.output, /Cloud-native/)
  })

  test("ares_ai_ml_attacks generates capabilities", async () => {
    const r = await runBridgedModule(ctx(), "ares_ai_ml_attacks", { target_url: "http://127.0.0.1:18100" })
    assert.ok(r?.success)
    assert.match(r.output, /AI\/ML attacks/)
  })

  test("ares_orchestrator runs all modules", async () => {
    const r = await runBridgedModule(ctx(), "ares_orchestrator", { target: "127.0.0.1", project_dir: process.cwd() })
    assert.ok(r?.success)
    assert.match(r.output, /ARES orchestrator/)
  })
})
