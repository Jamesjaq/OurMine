/**
 * @module citrix_audit
 * Citrix NetScaler ADC/Gateway edge assessment — CVE-2023-4966 (Citrix Bleed), session hijack, MFA bypass.
 * Used by LockBit affiliates, ALPHV/BlackCat, APT41. Software-only HTTP probes.
 */
import { resolveDryRun } from "./exec_options.ts"
import { execFileSync } from "node:child_process"

export interface CitrixFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detail: string
  cve?: string
  mitre?: string
  evidence?: string
}

export interface CitrixAuditResult {
  target: string
  dryRun: boolean
  isCitrixGateway: boolean
  citrixBleedSusceptible: boolean
  mfaBypassRisk: boolean
  findings: CitrixFinding[]
  summary: string
}

const CITRIX_BLEED_CVE = "CVE-2023-4966"
export { CITRIX_BLEED_CVE }
const CITRIX_INDICATORS = [
  /citrix/i,
  /netscaler/i,
  /ns\.gif/i,
  /Citrix-TransactionId/i,
  /NS-CACHE/i,
  /CitrixReceiver/i,
]

const VULNERABLE_VERSIONS = [
  "14.1 before 14.1-8.50",
  "13.1 before 13.1-49.15",
  "13.0 before 13.0-92.19",
  "12.1 EOL",
]

function runCurl(url: string, extraArgs: string[] = []): string | null {
  try {
    return execFileSync("curl", [
      "-sS", "-k", "-m", "12", "-D", "-", "-o", "/dev/null",
      ...extraArgs, url,
    ], { encoding: "utf-8", timeout: 15000 })
  } catch {
    return null
  }
}

function normalizeTarget(target: string): { host: string; baseUrl: string } {
  const t = target.replace(/^https?:\/\//, "").replace(/\/.*$/, "")
  const host = t.split(":")[0] ?? t
  const port = target.includes(":4443") ? 4443 : 443
  return { host, baseUrl: `https://${host}:${port}` }
}

function simulatedFindings(target: string): CitrixFinding[] {
  return [
    {
      id: "citrix-bleed-cve",
      severity: "critical",
      title: "Citrix Bleed (CVE-2023-4966) session token leak risk",
      detail: `NetScaler ADC/Gateway may leak session cookies enabling MFA bypass (T1556.006) — ${target}`,
      cve: CITRIX_BLEED_CVE,
      mitre: "T1556.006",
    },
    {
      id: "citrix-no-mfa-portal",
      severity: "critical",
      title: "Citrix remote-access portal without MFA enforcement",
      detail: "ALPHV/Change Healthcare entry vector — valid creds + no MFA on Citrix portal",
      mitre: "T1078",
    },
    {
      id: "citrix-session-hijack",
      severity: "high",
      title: "Authenticated session cookie replay possible",
      detail: "LockBit affiliates hijack NetScaler AAA session cookies post-Bleed exploit (T1539)",
      mitre: "T1539",
    },
    {
      id: "citrix-version-eol",
      severity: "high",
      title: "Potentially vulnerable NetScaler version range",
      detail: `Affected: ${VULNERABLE_VERSIONS.slice(0, 2).join("; ")}`,
      cve: CITRIX_BLEED_CVE,
    },
  ]
}

function probeCitrixHeaders(baseUrl: string): { isCitrix: boolean; headers: string; sessionLeakHint: boolean } {
  const resp = runCurl(baseUrl, ["-I"])
  if (!resp) return { isCitrix: false, headers: "", sessionLeakHint: false }

  const isCitrix = CITRIX_INDICATORS.some((re) => re.test(resp))
  const sessionLeakHint = /Set-Cookie.*NSC_/i.test(resp) && !/Secure/i.test(resp)

  const bleedProbe = runCurl(`${baseUrl}/oauth/idp/.well-known/openid-configuration`, [
    "-H", "Host: a]\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00",
  ])
  const leakHint = bleedProbe != null && bleedProbe.length > 200

  return { isCitrix: isCitrix || leakHint, headers: resp.slice(0, 500), sessionLeakHint: sessionLeakHint || leakHint }
}

export async function auditCitrixEdge(
  target: string,
  opts: { live?: boolean; dryRun?: boolean } = {},
): Promise<CitrixAuditResult> {
  const dryRun = resolveDryRun(opts)
  const { baseUrl } = normalizeTarget(target)

  if (dryRun) {
    const findings = simulatedFindings(target)
    return {
      target,
      dryRun: true,
      isCitrixGateway: true,
      citrixBleedSusceptible: true,
      mfaBypassRisk: true,
      findings,
      summary: `dry-run: Citrix Bleed/MFA-bypass assessment (${findings.length} findings) — set OURMINE_LIVE=1`,
    }
  }

  const probe = probeCitrixHeaders(baseUrl)
  const findings: CitrixFinding[] = []

  if (probe.isCitrix) {
    findings.push({
      id: "citrix-detected",
      severity: "info",
      title: "Citrix NetScaler/Gateway detected",
      detail: baseUrl,
      evidence: probe.headers.slice(0, 200),
    })
  }

  if (probe.sessionLeakHint) {
    findings.push({
      id: "citrix-session-leak",
      severity: "critical",
      title: "Session cookie leak indicator (Citrix Bleed pattern)",
      detail: "Crafted Host header may leak NSC_AAAC session material",
      cve: CITRIX_BLEED_CVE,
      mitre: "T1556.006",
    })
  }

  if (!findings.length) {
    findings.push({
      id: "citrix-not-detected",
      severity: "low",
      title: "No Citrix gateway fingerprint on target",
      detail: `${baseUrl} — probe /vpn/index.html and /logon/LogonPoint/index.html separately`,
    })
  }

  return {
    target,
    dryRun: false,
    isCitrixGateway: probe.isCitrix,
    citrixBleedSusceptible: probe.sessionLeakHint,
    mfaBypassRisk: probe.sessionLeakHint,
    findings,
    summary: `${findings.length} Citrix finding(s) on ${target}`,
  }
}

export default { auditCitrixEdge, CITRIX_BLEED_CVE }
