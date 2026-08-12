/**
 * Offensive module gap coverage — meterpreter socket, identity AD paths, toolkit templates.
 */
import { describe, test, before, after } from "node:test"
import assert from "node:assert/strict"
import * as net from "node:net"

const PREV_ALLOW = process.env.OURMINE_ALLOW_DRY_RUN
const PREV_LIVE = process.env.OURMINE_LIVE

before(() => {
  process.env.OURMINE_ALLOW_DRY_RUN = "1"
  process.env.OURMINE_LIVE = "0"
})

after(() => {
  if (PREV_ALLOW === undefined) delete process.env.OURMINE_ALLOW_DRY_RUN
  else process.env.OURMINE_ALLOW_DRY_RUN = PREV_ALLOW
  if (PREV_LIVE === undefined) delete process.env.OURMINE_LIVE
  else process.env.OURMINE_LIVE = PREV_LIVE
})

describe("meterpreter live socket path", () => {
  test("dispatchCommand dry-run returns simulated TLV per command", async () => {
    const { dispatchCommand, parseTlvPackets, decodeTlvValue } = await import("../src/meterpreter.ts")
    const buf = await dispatchCommand(0x00000100, 1, { dryRun: true })
    const parsed = parseTlvPackets(buf)
    assert.ok(parsed.length > 0)
    const val = decodeTlvValue(parsed[0])
    assert.match(String(val), /DRY-RUN|Computer/)
  })

  test("dispatchCommand live sends TLV over bound session socket", async () => {
    const {
      dispatchCommand,
      parseTlvPackets,
      decodeTlvValue,
      bindSessionEndpoint,
      unbindSessionEndpoint,
    } = await import("../src/meterpreter.ts")

    const sysinfoJson = JSON.stringify({
      Computer: "LAB-WS",
      OS: "Windows 10",
      Architecture: "x64",
      SystemLanguage: "en-US",
      Domain: "LAB.LOCAL",
      LoggedOnUsers: "admin",
    })

    const server = net.createServer((socket) => {
      socket.on("data", () => {
        const body = Buffer.from(sysinfoJson, "utf8")
        const packet = Buffer.alloc(8 + body.length)
        packet.writeUInt32LE(0x51000001, 0)
        packet.writeUInt32LE(8 + body.length, 4)
        body.copy(packet, 8)
        socket.write(packet)
        socket.end()
      })
    })

    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
    const addr = server.address()
    const port = typeof addr === "object" && addr ? addr.port : 0

    bindSessionEndpoint(42, "127.0.0.1", port)
    try {
      const buf = await dispatchCommand(0x00000100, 42, { live: true, dryRun: false })
      const parsed = parseTlvPackets(buf)
      assert.ok(parsed.length > 0)
      const data = JSON.parse(String(decodeTlvValue(parsed[0])))
      assert.equal(data.Computer, "LAB-WS")
      assert.equal(data.OS, "Windows 10")
    } finally {
      unbindSessionEndpoint(42)
      await new Promise((resolve) => server.close(resolve))
    }
  })

  test("dispatchCommand live without socket returns structured error TLV", async () => {
    const { dispatchCommand, parseTlvPackets, decodeTlvValue } = await import("../src/meterpreter.ts")
    const buf = await dispatchCommand(0x00000101, 99, { live: true, dryRun: false })
    const parsed = parseTlvPackets(buf)
    const data = JSON.parse(String(decodeTlvValue(parsed[0])))
    assert.equal(data.error, "no_session_socket")
  })

  test("sysinfo live parses socket response", async () => {
    const { sysinfo, bindSessionEndpoint, unbindSessionEndpoint } = await import("../src/meterpreter.ts")
    const payload = JSON.stringify({
      Computer: "TARGET-01",
      OS: "Linux",
      Architecture: "x64",
      SystemLanguage: "C",
      Domain: "corp.local",
      LoggedOnUsers: "root",
    })

    const server = net.createServer((socket) => {
      socket.on("data", () => {
        const body = Buffer.from(payload, "utf8")
        const packet = Buffer.alloc(8 + body.length)
        packet.writeUInt32LE(0x51000001, 0)
        packet.writeUInt32LE(8 + body.length, 4)
        body.copy(packet, 8)
        socket.write(packet)
        socket.end()
      })
    })

    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
    const port = server.address().port
    bindSessionEndpoint(7, "127.0.0.1", port)
    try {
      const info = await sysinfo(7, { live: true, dryRun: false })
      assert.equal(info.computer, "TARGET-01")
      assert.equal(info.dryRun, false)
    } finally {
      unbindSessionEndpoint(7)
      await new Promise((resolve) => server.close(resolve))
    }
  })
})

describe("identity technique paths", () => {
  test("kerberoast dry-run returns empty with command in execute envelope", async () => {
    const { kerberoast, execute } = await import("../src/identity.ts")
    const entries = await kerberoast({ live: false })
    assert.deepEqual(entries, [])
    const plan = await execute({ domain: "corp.local", attack: "kerberoast", dc: "10.0.0.1" }, { live: false })
    assert.equal(plan.dryRun, true)
    assert.match(plan.command ?? "", /impacket-GetUserSPNs/)
  })

  test("asrep_roast execute includes impacket command", async () => {
    const { execute } = await import("../src/identity.ts")
    const plan = await execute({ domain: "corp.local", attack: "asrep_roast", dc: "10.0.0.10" }, { live: false })
    assert.equal(plan.dryRun, true)
    assert.match(plan.command ?? "", /impacket-GetNPUsers/)
  })

  test("bypassMFA dry-run documents push_fatigue technique", async () => {
    const { bypassMFA, MFA_TECHNIQUES } = await import("../src/identity.ts")
    assert.ok(MFA_TECHNIQUES.includes("push_fatigue"))
    const r = bypassMFA("push_fatigue", "user@corp.local", { live: false })
    assert.equal(r.dryRun, true)
    assert.match(r.evidence, /DRY-RUN/)
    assert.match(r.evidence, /push/i)
  })

  test("execute mfa_bypass uses push_fatigue not invalid technique key", async () => {
    const { execute } = await import("../src/identity.ts")
    const r = await execute({ domain: "corp.local", attack: "mfa_bypass" }, { live: false })
    assert.equal(r.mfa?.method, "push_fatigue")
  })

  test("stuffCredentials dry-run never hits network", async () => {
    const { stuffCredentials } = await import("../src/identity.ts")
    const r = await stuffCredentials("http://127.0.0.1:1/nope", [{ username: "u", password: "p" }], { live: false })
    assert.equal(r.length, 1)
    assert.equal(r[0].dryRun, true)
    assert.match(r[0].result, /DRY-RUN/)
  })
})

describe("toolkit payload templates", () => {
  test("reverse_shell has all core language templates", async () => {
    const { PayloadGenerator } = await import("../src/toolkit.ts")
    const gen = new PayloadGenerator("10.0.0.5", 4444)
    for (const lang of ["bash", "python", "powershell", "node", "go", "c", "csharp"]) {
      assert.ok(gen.hasTemplate("reverse_shell", lang), `missing reverse_shell/${lang}`)
      const p = gen.generate("reverse_shell", lang)
      assert.match(p.code, /10\.0\.0\.5/)
      assert.doesNotMatch(p.code, /template not implemented/)
    }
  })

  test("meterpreter templates include msfvenom commands not comment stubs", async () => {
    const { PayloadGenerator } = await import("../src/toolkit.ts")
    const gen = new PayloadGenerator("192.168.1.10", 8080)
    for (const lang of ["bash", "powershell", "python"]) {
      const p = gen.generate("meterpreter", lang)
      assert.match(p.code, /msfvenom/)
      assert.doesNotMatch(p.code, /template not implemented/)
    }
  })

  test("listImplementedTemplates covers full matrix minus intentional msf-only langs", async () => {
    const { PayloadGenerator } = await import("../src/toolkit.ts")
    const gen = new PayloadGenerator()
    const impl = gen.listImplementedTemplates()
    assert.ok(impl.length >= 36, `expected broad coverage, got ${impl.length}`)
    assert.ok(impl.some((t) => t.type === "stager" && t.language === "go"))
    assert.ok(impl.some((t) => t.type === "webshell" && t.language === "node"))
  })

  test("toolkitGeneratePayload MCP dispatch uses PayloadGenerator", async () => {
    const { toolkitGeneratePayload } = await import("../src/mcp_dispatch.ts")
    const r = await toolkitGeneratePayload(
      { type: "reverse_shell", language: "bash", lhost: "127.0.0.1", lport: 4444 },
      { live: false },
    )
    assert.equal(r.dryRun, true)
    assert.ok(r.data.payload?.code)
    assert.match(r.data.payload.code, /dev\/tcp/)
  })
})
