/**
 * Firmware analysis — MCP action coverage and core primitives
 */
import { describe, test, before, after } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import {
  analyzeFirmware,
  executeFirmwareAction,
  firmwareCredentials,
  firmwareEntropy,
  firmwarePatchPlan,
  firmwareStrings,
  firmwareUartDetect,
  FIRMWARE_ACTIONS as MCP_FIRMWARE_ACTIONS,
} from "../src/firmware.ts"
import { firmwareAnalyze } from "../src/mcp_dispatch.ts"
import { firmwareActionImplemented, MCP_FIRMWARE_ACTIONS as REG_FIRMWARE_ACTIONS } from "../src/module_registry.ts"
import { runBridgedModule } from "../src/module_bridge.ts"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { CredentialGraph } from "../src/credential_graph.ts"

const savedLive = process.env.OURMINE_LIVE

before(() => {
  process.env.OURMINE_LIVE = "1"
})

after(() => {
  if (savedLive === undefined) delete process.env.OURMINE_LIVE
  else process.env.OURMINE_LIVE = savedLive
})

function bridgeCtx(live = true) {
  return {
    target: "127.0.0.1",
    live,
    graph: new AttackSurfaceGraph("127.0.0.1"),
    credGraph: CredentialGraph.load(),
  }
}

function writeSampleFirmware() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-fw-"))
  const file = path.join(tmp, "sample.bin")
  const parts = [
    Buffer.from([0x1f, 0x8b, 0x08, 0x00]), // GZIP magic
    Buffer.from("console=ttyS0,115200 UART debug port TX=pin3\n"),
    Buffer.from("password=admin123\napi_key=deadbeefcafebabe\n"),
    Buffer.from("root:$6$salt$hashedvaluehere\n"),
    Buffer.from("authentication required login verify_password\n"),
    Buffer.from([0xd0, 0x0d, 0xfe, 0xed, 0x00, 0x00, 0x00, 0x00]), // DTB magic
    Buffer.from(Array.from({ length: 512 }, () => Math.floor(Math.random() * 256))),
  ]
  fs.writeFileSync(file, Buffer.concat(parts))
  return file
}

describe("firmware", () => {
  test("ares_firmware MCP actions are implemented", () => {
    for (const action of REG_FIRMWARE_ACTIONS) {
      assert.ok(firmwareActionImplemented(action), `firmware action not implemented: ${action}`)
    }
    assert.deepEqual([...REG_FIRMWARE_ACTIONS].sort(), [...MCP_FIRMWARE_ACTIONS].sort())
  })

  test("analyzeFirmware detects magic sections", () => {
    const file = writeSampleFirmware()
    const sections = analyzeFirmware(file)
    assert.ok(sections.some((s) => s.type.includes("GZIP")))
    assert.ok(sections.some((s) => s.type.includes("Device Tree")))
  })

  test("executeFirmwareAction covers all advertised actions", () => {
    const file = writeSampleFirmware()
    for (const action of MCP_FIRMWARE_ACTIONS) {
      const r = executeFirmwareAction(file, action, { live: true })
      assert.equal(r.action, action)
      assert.ok(!r.error, `${action} failed: ${r.error}`)
    }
  })

  test("firmwareEntropy reports high-entropy windows", () => {
    const file = writeSampleFirmware()
    const r = firmwareEntropy(file, 128)
    assert.ok(r.globalEntropy > 0)
    assert.ok(r.size > 0)
    assert.ok(Array.isArray(r.highEntropyWindows))
  })

  test("firmwareStrings extracts printable strings", () => {
    const file = writeSampleFirmware()
    const strings = firmwareStrings(file)
    assert.ok(strings.some((s) => s.includes("console=ttyS0")))
    assert.ok(strings.some((s) => s.includes("password=admin123")))
  })

  test("firmwareCredentials finds hardcoded secrets", () => {
    const file = writeSampleFirmware()
    const hits = firmwareCredentials(file)
    assert.ok(hits.some((h) => h.kind === "password_kv"))
    assert.ok(hits.some((h) => h.kind === "api_secret" || h.kind === "shadow_entry"))
  })

  test("firmwareUartDetect finds console and DTB hints", () => {
    const file = writeSampleFirmware()
    const hints = firmwareUartDetect(file)
    assert.ok(hints.some((h) => h.kind === "console_tty" || h.kind === "tty_device"))
    assert.ok(hints.some((h) => h.kind === "dtb_header"))
  })

  test("firmwarePatchPlan is read-only and finds auth gates", () => {
    const file = writeSampleFirmware()
    const candidates = firmwarePatchPlan(file)
    assert.ok(candidates.length > 0)
    assert.ok(candidates.some((c) => c.kind === "auth_check"))
  })

  test("firmwareAnalyze dispatch returns module envelope when live", async () => {
    const file = writeSampleFirmware()
    const r = await firmwareAnalyze({ path: file, action: "strings" }, { live: true })
    assert.equal(r.dryRun, false)
    assert.equal(r.data.action, "strings")
    assert.ok(r.data.count > 0)
  })

  test("firmwareAnalyze dry-run rejects live-only path", async () => {
    const file = writeSampleFirmware()
    const r = await firmwareAnalyze({ path: file, action: "extract" }, { live: false })
    assert.equal(r.dryRun, true)
    assert.ok(r.data.error?.includes("live"))
  })

  test("firmware_audit bridge uses executeFirmwareAction for all actions", async () => {
    const file = writeSampleFirmware()
    for (const action of MCP_FIRMWARE_ACTIONS) {
      const r = await runBridgedModule(bridgeCtx(true), "firmware_audit", { path: file, action })
      assert.equal(r.tool, "firmware_audit")
      assert.equal(r.command, "executeFirmwareAction")
      assert.equal(r.dryRun, false)
      assert.equal(r.success, true, `${action} bridge failed: ${r.output}`)
      const payload = JSON.parse(r.output)
      assert.equal(payload.action, action)
      assert.ok(!payload.error, `${action}: ${payload.error}`)
    }
  })

  test("firmware_audit bridge dry-run skips file read", async () => {
    const file = writeSampleFirmware()
    const r = await runBridgedModule(bridgeCtx(false), "firmware_audit", { path: file, action: "strings" })
    assert.equal(r.dryRun, true)
    assert.equal(r.success, false)
    const payload = JSON.parse(r.output)
    assert.ok(payload.error?.includes("live"))
  })

  test("firmwareAnalyze rejects missing path", async () => {
    const r = await firmwareAnalyze({ path: "", action: "extract" }, { live: false })
    assert.ok(r.data.error?.includes("path required"))
  })
})
