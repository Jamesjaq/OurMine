/**
 * Assert live code paths exist — no network required (OURMINE_ALLOW_DRY_RUN=1 safe).
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"

describe("live_paths", () => {
  test("iot_scada exports live socket probe functions", async () => {
    const scada = await import("../src/iot_scada.ts")
    for (const fn of [
      "probeMqtt", "probeCoap", "probeS7", "exploitMqtt", "exploitCoap", "exploitS7",
      "probeDnp3", "executeScadaAction",
    ]) {
      assert.equal(typeof scada[fn], "function", `missing ${fn}`)
    }
    const src = fs.readFileSync(new URL("../src/iot_scada.ts", import.meta.url), "utf8")
    assert.ok(src.includes("tcpExchange"), "modbus live tcp I/O")
    assert.ok(src.includes("udpExchange"), "coap live udp I/O")
    assert.ok(src.includes("buildS7ReadSzl"), "s7 live SZL exploit path")
  })

  test("identity live AD helpers are wired", async () => {
    const id = await import("../src/identity.ts")
    assert.equal(typeof id.kerberoast, "function")
    assert.equal(typeof id.ldapEnumerate, "function")
    assert.equal(typeof id.ntlmRelayProbe, "function")
    const src = fs.readFileSync(new URL("../src/identity.ts", import.meta.url), "utf8")
    assert.ok(src.includes("impacket-GetUserSPNs"))
    assert.ok(src.includes("ldapsearch"))
    assert.ok(src.includes("impacket-ntlmrelayx"))
  })

  test("toolkit meterpreter bytes generator exists", async () => {
    const { generateMeterpreterBytes, reverseShellMachineCode, PayloadGenerator } = await import("../src/toolkit.ts")
    assert.equal(typeof generateMeterpreterBytes, "function")
    const bytes = reverseShellMachineCode("127.0.0.1", 4444)
    assert.ok(bytes.length > 16)
    const dry = generateMeterpreterBytes({ format: "raw", lhost: "127.0.0.1", lport: 4444 }, { dryRun: true })
    assert.equal(dry.dryRun, true)
    assert.equal(dry.bytes, null)
    const gen = new PayloadGenerator("10.0.0.1", 4444)
    const p = gen.generate("reverse_shell", "bash")
    assert.ok(p.code.includes("/dev/tcp/"))
    assert.ok(!p.code.includes("template not implemented"))
  })

  test("meterpreter live TLV dispatch over TCP", async () => {
    const mp = await import("../src/meterpreter.ts")
    assert.equal(typeof mp.dispatchCommand, "function")
    assert.equal(typeof mp.bindSessionEndpoint, "function")
    const src = fs.readFileSync(new URL("../src/meterpreter.ts", import.meta.url), "utf8")
    assert.ok(src.includes("sendTlvOverTcp"))
    const shot = await mp.screenshot(1, { dryRun: true })
    assert.equal(shot.dryRun, true)
    assert.equal(shot.data, "")
  })

  test("firmware all six MCP actions perform file I/O when live", async () => {
    const { executeFirmwareAction, FIRMWARE_ACTIONS } = await import("../src/firmware.ts")
    const { MCP_FIRMWARE_ACTIONS: regActions } = await import("../src/module_registry.ts")
    assert.deepEqual([...regActions].sort(), [...FIRMWARE_ACTIONS].sort())

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-live-fw-"))
    const file = path.join(tmp, "sample.bin")
    fs.writeFileSync(file, Buffer.concat([
      Buffer.from([0x1f, 0x8b, 0x08]),
      Buffer.from("password=secret\nconsole=ttyS0\n"),
    ]))

    for (const action of FIRMWARE_ACTIONS) {
      const r = executeFirmwareAction(file, action, { live: true })
      assert.equal(r.action, action)
      assert.ok(!r.error, `${action}: ${r.error}`)
    }
  })

  test("multi_lang payloads honor dryRun flag", async () => {
    const { generateAllPayloads } = await import("../src/multi_lang.ts")
    const dry = generateAllPayloads("127.0.0.1", 4444, "linux", "none", { dryRun: true })
    assert.equal(dry.reverseShells.bash.dryRun, true)
    assert.ok(dry.reverseShells.bash.raw.length > 10)
  })
})
