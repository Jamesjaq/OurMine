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

export async function initiateDeviceCodeFlow(
  provider: "entra" | "okta" | "google",
  clientId = "00000003-0000-0ff1-ce00-000000000000", // Default Microsoft Graph client ID
  scope = "User.Read",
  live = false,
): Promise<{ success: boolean; verificationUri?: string; userCode?: string; deviceCode?: string; error?: string }> {
  const endpoints = PROVIDER_ENDPOINTS[provider]
  if (!endpoints) return { success: false, error: "Unknown provider" }
  
  if (!live) {
    return {
      success: true,
      verificationUri: endpoints.verify,
      userCode: "DRY-CODE-1234",
      deviceCode: "dry-run-device-code-token"
    }
  }

  try {
    const body = new URLSearchParams({
      client_id: clientId,
      scope: scope
    })
    const res = await fetch(endpoints.device, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    })
    if (!res.ok) return { success: false, error: `HTTP ${res.status}: ${await res.text()}` }
    const data = await res.json() as { verification_uri?: string; user_code?: string; device_code?: string }
    return {
      success: true,
      verificationUri: data.verification_uri ?? endpoints.verify,
      userCode: data.user_code,
      deviceCode: data.device_code
    }
  } catch (e) {
    return { success: false, error: String(e) }
  }
}

export async function pollDeviceCodeToken(
  provider: "entra" | "okta" | "google",
  deviceCode: string,
  clientId = "00000003-0000-0ff1-ce00-000000000000",
  live = false,
): Promise<{ status: "pending" | "success" | "expired" | "error"; accessToken?: string; error?: string }> {
  const endpoints = PROVIDER_ENDPOINTS[provider]
  if (!endpoints) return { status: "error", error: "Unknown provider" }

  if (!live) {
    return { status: "success", accessToken: "dry-run-oauth-bearer-token-xyz" }
  }

  try {
    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: clientId,
      device_code: deviceCode
    })
    const res = await fetch(endpoints.poll, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    })
    const data = await res.json() as { access_token?: string; error?: string }
    if (res.ok && data.access_token) {
      return { status: "success", accessToken: data.access_token }
    }
    if (data.error === "authorization_pending" || data.error === "slow_down") {
      return { status: "pending" }
    }
    if (data.error === "expired_token") {
      return { status: "expired" }
    }
    return { status: "error", error: data.error ?? "Unknown error" }
  } catch (e) {
    return { status: "error", error: String(e) }
  }
}

export default { auditDeviceCodeFlow, auditDeviceCodeFlowAsync, initiateDeviceCodeFlow, pollDeviceCodeToken }
