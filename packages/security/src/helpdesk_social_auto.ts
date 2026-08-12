/**
 * @module helpdesk_social_auto
 * Helpdesk social engineering automation — Scattered Spider, ALPHV, FIN7 vishing/smishing playbooks.
 * Generates verification-bypass scripts, MFA reset lures, and multi-channel attack timelines.
 */
import * as crypto from "node:crypto"
import { resolveDryRun } from "./exec_options.ts"
import { httpProbe, probeEmailSecurity, probeWhois } from "./domain_probe.ts"

export interface HelpdeskScenario {
  id: string
  actor: string
  technique: string
  channel: "vishing" | "smishing" | "chat" | "email"
  targetRole: string
  script: string
  verificationBypass: string[]
  mfaBypassMethod?: string
  rmmFollowUp?: string
}

export interface HelpdeskAuditResult {
  target: string
  dryRun: boolean
  scenarios: HelpdeskScenario[]
  findings: Array<{ id: string; severity: string; title: string; detail: string; mitre?: string }>
  recommendations: string[]
  summary: string
  liveRecon?: {
    mx: string[]
    spf: string | null
    dmarc: string | null
    dmarcPolicy: string | null
    whoisOrg: string | null
    whoisRegistrar: string | null
    webProbes: Array<{ url: string; status: number; ok: boolean }>
  }
}

const ACTOR_SCENARIOS: Omit<HelpdeskScenario, "id">[] = [
  {
    actor: "Scattered Spider",
    technique: "T1566.002",
    channel: "vishing",
    targetRole: "IT Helpdesk",
    script: `Caller impersonates employee on PTO. Claims locked out of Okta/Entra. Provides partial employee ID from LinkedIn. Requests SSPR + MFA re-enrollment to attacker-controlled Authenticator.`,
    verificationBypass: ["Knows manager name from org chart", "References recent company event", "Spoofs internal caller ID"],
    mfaBypassMethod: "MFA fatigue / push bombing (T1621) or helpdesk MFA reset (T1556.006)",
    rmmFollowUp: "Deploy AnyDesk/TeamViewer for 'remote troubleshooting' (T1219)",
  },
  {
    actor: "ALPHV/BlackCat",
    technique: "T1598",
    channel: "vishing",
    targetRole: "IT Helpdesk",
    script: `Poses as corporate IT. SMS + live chat follow-up. Requests credentials for 'VPN maintenance window'. Uses Evilginx AiTM if password alone insufficient.`,
    verificationBypass: ["Multi-channel urgency (SMS then call)", "References ticket number", "Native English speaker"],
    mfaBypassMethod: "Evilginx2 AiTM session cookie theft (T1557)",
    rmmFollowUp: "Splashtop/AnyDesk persistence (T1219)",
  },
  {
    actor: "FIN7",
    technique: "T1566.001",
    channel: "email",
    targetRole: "Restaurant/Hospitality staff",
    script: `Spear-phish with malicious DOC/XLS. Follow-up vishing call 'to help open the document'. Backdoor via COM/VBA then RMM.`,
    verificationBypass: ["Industry-specific lure (POS vendor)", "Callback within 30 minutes"],
    rmmFollowUp: "ScreenConnect deployment post-compromise",
  },
  {
    actor: "Scattered Spider",
    technique: "T1621",
    channel: "smishing",
    targetRole: "Privileged user",
    script: `Repeated Okta/Entra push notifications. SMS: 'IT Security: approve the login prompt to prevent account lockout'.`,
    verificationBypass: ["Push fatigue after 20-50 prompts"],
    mfaBypassMethod: "MFA fatigue — user accepts push (T1621)",
  },
]

function buildScenarios(target: string): HelpdeskScenario[] {
  return ACTOR_SCENARIOS.map((s, i) => ({
    ...s,
    id: `helpdesk-${i + 1}`,
    script: s.script.replace("employee", `employee@${target}`),
  }))
}

async function probeHelpdeskRecon(domain: string): Promise<HelpdeskAuditResult["liveRecon"]> {
  const [emailSec, whois] = await Promise.all([
    probeEmailSecurity(domain),
    probeWhois(domain),
  ])

  const webUrls = [
    `https://${domain}/`,
    `https://mail.${domain}/`,
    `https://autodiscover.${domain}/`,
  ]
  const webProbes = await Promise.all(webUrls.map((url) => httpProbe(url)))
  return {
    mx: emailSec.mx,
    spf: emailSec.spf,
    dmarc: emailSec.dmarc,
    dmarcPolicy: emailSec.dmarcPolicy,
    whoisOrg: whois.org,
    whoisRegistrar: whois.registrar,
    webProbes: webProbes.map((p) => ({ url: p.url, status: p.status, ok: p.ok })),
  }
}

function liveReconFindings(domain: string, recon: NonNullable<HelpdeskAuditResult["liveRecon"]>): HelpdeskAuditResult["findings"] {
  const out: HelpdeskAuditResult["findings"] = []

  if (recon.mx.length > 0) {
    out.push({
      id: "live-mx",
      severity: "info",
      title: "MX records resolved",
      detail: recon.mx.slice(0, 5).join(", "),
      mitre: "T1598",
    })
  }

  if (recon.spf) {
    out.push({
      id: "live-spf",
      severity: recon.spf.includes("-all") || recon.spf.includes("~all") ? "low" : "medium",
      title: "SPF record present",
      detail: recon.spf.slice(0, 200),
      mitre: "T1566",
    })
  } else {
    out.push({
      id: "live-spf-missing",
      severity: "medium",
      title: "No SPF record found",
      detail: `No v=spf1 TXT on ${domain} — spoofing risk for vishing/smishing lures`,
      mitre: "T1566",
    })
  }

  if (recon.dmarc) {
    out.push({
      id: "live-dmarc",
      severity: recon.dmarcPolicy === "reject" ? "low" : recon.dmarcPolicy === "quarantine" ? "medium" : "high",
      title: `DMARC policy: ${recon.dmarcPolicy ?? "unknown"}`,
      detail: recon.dmarc.slice(0, 200),
      mitre: "T1566",
    })
  } else {
    out.push({
      id: "live-dmarc-missing",
      severity: "high",
      title: "No DMARC record at _dmarc",
      detail: `Missing DMARC on ${domain} — external sender impersonation easier for helpdesk lures`,
      mitre: "T1566",
    })
  }

  if (recon.whoisOrg || recon.whoisRegistrar) {
    out.push({
      id: "live-whois",
      severity: "info",
      title: "WHOIS registrant data",
      detail: `Org=${recon.whoisOrg ?? "N/A"}, Registrar=${recon.whoisRegistrar ?? "N/A"}`,
      mitre: "T1598",
    })
  }

  for (const p of recon.webProbes.filter((w) => w.ok)) {
    out.push({
      id: `live-web-${p.url.replace(/[^a-z0-9]/gi, "-")}`,
      severity: "info",
      title: `Web/mail endpoint reachable: ${p.url}`,
      detail: `HTTP ${p.status}`,
      mitre: "T1598",
    })
  }

  return out
}

export async function auditHelpdeskSocial(
  target: string,
  opts: { live?: boolean; dryRun?: boolean; actor?: string } = {},
): Promise<HelpdeskAuditResult> {
  const dryRun = resolveDryRun(opts)
  const domain = target.replace(/^https?:\/\//, "").split("/")[0] ?? target
  let scenarios = buildScenarios(domain)

  if (opts.actor) {
    const q = opts.actor.toLowerCase()
    scenarios = scenarios.filter((s) => s.actor.toLowerCase().includes(q))
  }

  let findings = scenarios.map((s) => ({
    id: s.id,
    severity: s.mfaBypassMethod?.includes("T1621") ? "critical" : "high",
    title: `${s.actor} ${s.channel} → ${s.targetRole}`,
    detail: s.script.slice(0, 180),
    mitre: s.technique,
  }))

  let liveRecon: HelpdeskAuditResult["liveRecon"]
  if (!dryRun) {
    liveRecon = await probeHelpdeskRecon(domain)
    findings = [...findings, ...liveReconFindings(domain, liveRecon)]
  }

  const recommendations = [
    "Multi-channel verification for password/MFA resets (no single-channel SSPR)",
    "FIDO2/WebAuthn — resistant to push bombing and AiTM",
    "Helpdesk callback to known employee number on file",
    "RMM tool allowlist + alert on AnyDesk/TeamViewer/ScreenConnect install",
    "Rate-limit MFA push notifications (max 3-5 per session)",
    "Separate break-glass accounts with hardware keys only",
  ]

  const liveNote = liveRecon
    ? `, ${liveRecon.webProbes.filter((p) => p.ok).length} web probe(s), SPF=${liveRecon.spf ? "yes" : "no"}, DMARC=${liveRecon.dmarcPolicy ?? "none"}`
    : ""

  return {
    target: domain,
    dryRun,
    scenarios,
    findings,
    recommendations,
    liveRecon,
    summary: dryRun
      ? `dry-run: ${scenarios.length} helpdesk social-eng scenarios for ${domain}`
      : `${scenarios.length} helpdesk attack scenarios assessed for ${domain}${liveNote}`,
  }
}

/** Generate a campaign-ready vishing script bundle. */
export function generateVishingBundle(target: string, scenarioId?: string): {
  campaignId: string
  scenario: HelpdeskScenario
  checklist: string[]
} {
  const scenarios = buildScenarios(target)
  const scenario = scenarios.find((s) => s.id === scenarioId) ?? scenarios[0]!
  return {
    campaignId: crypto.randomBytes(6).toString("hex"),
    scenario,
    checklist: [
      "Pre-call OSINT: LinkedIn, org chart, recent press releases",
      "Spoof caller ID or use anonymous VoIP",
      scenario.verificationBypass.map((v) => `Bypass: ${v}`).join("\n"),
      scenario.mfaBypassMethod ? `MFA: ${scenario.mfaBypassMethod}` : "",
      scenario.rmmFollowUp ? `Persistence: ${scenario.rmmFollowUp}` : "",
    ].filter(Boolean),
  }
}

export default { auditHelpdeskSocial, generateVishingBundle, ACTOR_SCENARIOS }
