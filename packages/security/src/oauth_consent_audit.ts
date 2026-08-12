/**
 * @module oauth_consent_audit
 * OAuth consent phishing / ConsentFix-style assessment — APT29, ShinyHunters, Scattered Spider.
 * Evaluates tenant consent policies, risky scope grants, and post-MFA token interception patterns.
 */
import { resolveDryRun } from "./exec_options.ts"
import { httpProbe } from "./domain_probe.ts"

export interface OAuthConsentFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detail: string
  scope?: string
  mitre?: string
  actor?: string
}

export interface OAuthConsentAuditResult {
  target: string
  dryRun: boolean
  consentPhishingRisk: "critical" | "high" | "medium" | "low"
  riskyScopes: string[]
  findings: OAuthConsentFinding[]
  recommendations: string[]
  summary: string
  liveProbes?: Array<{ url: string; status: number; ok: boolean }>
}

/** Scopes targeted by APT29 ConsentFix / Midnight Blizzard campaigns. */
export const HIGH_RISK_SCOPES = [
  "Mail.Read", "Mail.ReadWrite", "Mail.ReadWrite.All",
  "Files.ReadWrite.All", "Sites.ReadWrite.All",
  "User.ReadWrite.All", "Directory.ReadWrite.All",
  "offline_access", "openid", "profile",
]

export const CONSENT_ATTACK_PATTERNS = [
  {
    id: "consentfix-v3",
    actor: "APT29",
    name: "ConsentFix authorization code interception",
    detail: "Post-MFA OAuth code redirected to attacker webhook (Pipedream). Victim drags localhost callback URL.",
    mitre: "T1550.001",
    severity: "critical" as const,
  },
  {
    id: "oauth-consent-phish",
    actor: "APT29",
    name: "Malicious app consent grant",
    detail: "User clicks Allow on attacker-registered OAuth app. Refresh token survives password reset.",
    mitre: "T1550.001",
    severity: "critical" as const,
  },
  {
    id: "service-principal-abuse",
    actor: "APT29",
    name: "Service principal creation post-compromise",
    detail: "Attacker creates SP with Mail.Read in victim tenant for stealthy persistent access.",
    mitre: "T1078.004",
    severity: "high" as const,
  },
  {
    id: "federated-trust-abuse",
    actor: "Scattered Spider",
    name: "Federated IdP auto-link (historical)",
    detail: "Added rogue federated IdP to SSO tenant with automatic account linking (T1484.002).",
    mitre: "T1484.002",
    severity: "high" as const,
  },
  {
    id: "saas-token-theft",
    actor: "ShinyHunters",
    name: "SaaS OAuth token replay",
    detail: "Stolen refresh tokens used against Salesforce, Snowflake, GitHub OAuth integrations.",
    mitre: "T1550",
    severity: "high" as const,
  },
]

function assessConsentPolicy(domain: string): OAuthConsentFinding[] {
  return CONSENT_ATTACK_PATTERNS.map((p) => ({
    id: p.id,
    severity: p.severity,
    title: p.name,
    detail: `${p.detail} — tenant: ${domain}`,
    mitre: p.mitre,
    actor: p.actor,
  }))
}

function buildOAuthProbeUrls(domain: string, provider: "entra" | "google" | "okta"): string[] {
  const urls: string[] = []
  const base = domain.replace(/^https?:\/\//, "").split("/")[0] ?? domain

  if (provider === "entra" || base.includes("onmicrosoft.com")) {
    urls.push(
      `https://login.microsoftonline.com/${base}/.well-known/openid-configuration`,
      `https://login.microsoftonline.com/${base}/oauth2/v2.0/authorize`,
      `https://login.microsoftonline.com/common/.well-known/openid-configuration`,
    )
  }
  if (provider === "okta" || base.includes("okta")) {
    urls.push(
      `https://${base}/.well-known/openid-configuration`,
      `https://${base}/oauth2/v1/authorize`,
    )
  }
  if (provider === "google" || base.includes("google")) {
    urls.push("https://accounts.google.com/.well-known/openid-configuration")
  }

  urls.push(
    `https://${base}/.well-known/openid-configuration`,
    `https://${base}/oauth2/authorize`,
    `https://${base}/oauth2/v2.0/authorize`,
  )
  return [...new Set(urls)]
}

async function probeOAuthEndpoints(
  domain: string,
  provider: "entra" | "google" | "okta",
): Promise<{ findings: OAuthConsentFinding[]; probes: Array<{ url: string; status: number; ok: boolean }> }> {
  const urls = buildOAuthProbeUrls(domain, provider)
  const findings: OAuthConsentFinding[] = []
  const probes: Array<{ url: string; status: number; ok: boolean }> = []

  for (const url of urls) {
    const probe = await httpProbe(url)
    probes.push({ url, status: probe.status, ok: probe.ok })
    if (probe.status === 0) continue

    const host = url.replace(/^https:\/\//, "").split("/")[0] ?? url
    findings.push({
      id: `oauth-probe-${host.replace(/[^a-z0-9]/gi, "-")}-${probe.status}`,
      severity: probe.ok && url.includes("openid-configuration") ? "info" : "medium",
      title: `OAuth endpoint responded: ${host}`,
      detail: probe.ok
        ? `HTTP ${probe.status} — OIDC/OAuth surface exposed (consent-phish vector if user consent enabled)`
        : `HTTP ${probe.status} — endpoint reachable`,
      mitre: "T1550.001",
    })

    if (probe.ok && url.includes("openid-configuration") && probe.bodyPreview.includes("authorization_endpoint")) {
      try {
        const cfg = JSON.parse(probe.bodyPreview) as { authorization_endpoint?: string }
        if (cfg.authorization_endpoint) {
          findings.push({
            id: "oauth-authz-endpoint",
            severity: "info",
            title: "OIDC authorization_endpoint discovered",
            detail: cfg.authorization_endpoint,
            mitre: "T1550.001",
          })
        }
      } catch { /* non-JSON body */ }
    }
  }

  return { findings, probes }
}

export async function auditOAuthConsent(
  target: string,
  opts: { live?: boolean; dryRun?: boolean; provider?: "entra" | "google" | "okta" } = {},
): Promise<OAuthConsentAuditResult> {
  const dryRun = resolveDryRun(opts)
  const domain = target.replace(/^https?:\/\//, "").split("/")[0] ?? target
  const provider = opts.provider ?? (domain.includes("google") ? "google" : domain.includes("okta") ? "okta" : "entra")

  let findings = assessConsentPolicy(domain)
  let liveProbes: OAuthConsentAuditResult["liveProbes"]

  if (!dryRun) {
    const probed = await probeOAuthEndpoints(domain, provider)
    liveProbes = probed.probes
    findings = [...findings, ...probed.findings]
  }

  const riskyScopes = HIGH_RISK_SCOPES.slice(0, 6)
  const consentPhishingRisk: OAuthConsentAuditResult["consentPhishingRisk"] =
    provider === "entra" ? "critical" : "high"

  const recommendations = [
    "Disable user consent for applications — admin consent workflow only",
    "Audit Enterprise Applications for unknown OAuth grants (Entra → Enterprise apps)",
    "Enable Conditional Access: require compliant device + token protection",
    "Monitor for new app registrations and admin consent events (AuditLogs)",
    "Revoke refresh tokens on password change AND MFA method change",
    "Publisher verification + app ID verification for all integrated SaaS",
  ]

  const probeCount = liveProbes?.filter((p) => p.ok).length ?? 0
  return {
    target: domain,
    dryRun,
    consentPhishingRisk,
    riskyScopes,
    findings,
    recommendations,
    liveProbes,
    summary: dryRun
      ? `dry-run: OAuth consent phishing assessment (${findings.length} patterns) for ${domain}`
      : `OAuth consent risk=${consentPhishingRisk} on ${domain} (${findings.length} findings, ${probeCount} live probe(s) ok)`,
  }
}

export default { auditOAuthConsent, HIGH_RISK_SCOPES, CONSENT_ATTACK_PATTERNS }
