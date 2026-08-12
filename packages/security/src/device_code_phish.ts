/**
 * @module device_code_phish
 * Device-code OAuth flow assessment — Entra/Okta/Google (dry-run default).
 */
import { resolveDryRun } from "./exec_options.ts"
import { httpProbe } from "./domain_probe.ts"

export interface DeviceCodeFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  mitre: string
}

export interface DeviceCodePhishResult {
  target: string
  dryRun: boolean
  provider: "entra" | "okta" | "google"
  findings: DeviceCodeFinding[]
  userCodeSimulation?: { verificationUri: string; userCode: string; pollEndpoint: string }
  recommendations: string[]
  summary: string
}

const PROVIDER_ENDPOINTS: Record<string, { device: string; poll: string; verify: string }> = {
  entra: {
    device: "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
    poll: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    verify: "https://microsoft.com/devicelogin",
  },
  okta: {
    device: "https://{domain}/oauth2/v1/device/authorize",
    poll: "https://{domain}/oauth2/v1/token",
    verify: "https://{domain}/activate",
  },
  google: {
    device: "https://oauth2.googleapis.com/device/code",
    poll: "https://oauth2.googleapis.com/token",
    verify: "https://google.com/device",
  },
}

function detectProvider(domain: string): "entra" | "okta" | "google" {
  const d = domain.toLowerCase()
  if (d.includes("google") || d.includes("gmail")) return "google"
  if (d.includes("okta")) return "okta"
  return "entra"
}

export function auditDeviceCodeFlow(
  domain: string,
  opts: { dryRun?: boolean; provider?: "entra" | "okta" | "google"; live?: boolean } = {},
): DeviceCodePhishResult {
  const dryRun = resolveDryRun(opts)
  const provider = opts.provider ?? detectProvider(domain)
  const endpoints = PROVIDER_ENDPOINTS[provider]!
  const findings: DeviceCodeFinding[] = []

  findings.push({
    id: "device-code-flow-enabled",
    severity: "high",
    title: "Device code grant may be enabled for tenant",
    mitre: "T1528",
  })
  findings.push({
    id: "user-consent-device",
    severity: "medium",
    title: "Users can complete auth on secondary device — phishing vector",
    mitre: "T1550.001",
  })

  const userCode = "ABCD-EFGH"
  const userCodeSimulation = {
    verificationUri: endpoints.verify.replace("{domain}", domain),
    userCode,
    pollEndpoint: endpoints.poll.replace("{domain}", domain),
  }

  const recommendations = [
    "Block device code flow via Conditional Access for unmanaged devices",
    "Require phishing-resistant MFA (FIDO2/WebAuthn) for privileged roles",
    "Monitor for device-code token grants in IdP sign-in logs",
  ]

  return {
    target: domain,
    dryRun,
    provider,
    findings,
    userCodeSimulation,
    recommendations,
    summary: `${provider} device-code assessment (${dryRun ? "dry-run" : "live"}) — ${findings.length} findings`,
  }
}

/** Live probe — OIDC device endpoint reachability only (no token acquisition). */
export async function auditDeviceCodeFlowAsync(
  domain: string,
  opts: { dryRun?: boolean; provider?: "entra" | "okta" | "google"; live?: boolean } = {},
): Promise<DeviceCodePhishResult> {
  const base = auditDeviceCodeFlow(domain, opts)
  if (resolveDryRun(opts)) return base

  const provider = opts.provider ?? detectProvider(domain)
  const ep = PROVIDER_ENDPOINTS[provider]!.device.replace("{domain}", domain)
  const probe = await httpProbe(ep, { method: "POST", timeoutMs: 8000 })
  base.findings.push({
    id: "device-endpoint-reachable",
    severity: probe.ok ? "high" : "info",
    title: probe.ok ? "Device-code endpoint responded" : "Device-code endpoint unreachable",
    mitre: "T1528",
  })
  return base
}

export default { auditDeviceCodeFlow, auditDeviceCodeFlowAsync }
