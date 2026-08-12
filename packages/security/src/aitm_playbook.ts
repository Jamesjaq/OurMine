/**
 * @module aitm_playbook
 * AiTM assessment chain — Citrix + OAuth + session cookie modules (assessment only).
 */
import { resolveDryRun } from "./exec_options.ts"

export interface AitmPlaybookStep {
  module: string
  phase: "recon" | "exploit" | "post_ex"
  mitre: string
  rationale: string
}

export interface AitmPlaybookResult {
  target: string
  dryRun: boolean
  steps: AitmPlaybookStep[]
  stackSignals: string[]
  recommendations: string[]
  summary: string
}

const AITM_MODULES = [
  { module: "citrix_audit", phase: "recon" as const, mitre: "T1539", rationale: "Session cookie replay on Citrix/VPN edge" },
  { module: "oauth_consent_audit", phase: "recon" as const, mitre: "T1550.001", rationale: "OAuth consent + token interception paths" },
  { module: "evilginx_lab", phase: "exploit" as const, mitre: "T1557", rationale: "AiTM proxy lab assessment (no live proxy)" },
  { module: "cloud_token", phase: "exploit" as const, mitre: "T1528", rationale: "Stolen session/token abuse simulation" },
  { module: "idp_audit", phase: "post_ex" as const, mitre: "T1078", rationale: "IdP session policy + CA bypass review" },
]

export function buildAitmPlaybook(
  target: string,
  opts: { dryRun?: boolean; stackSignals?: string[] } = {},
): AitmPlaybookResult {
  const dryRun = resolveDryRun(opts)
  const signals = opts.stackSignals ?? detectAitmSignals(target)
  const steps = AITM_MODULES.filter((s) => {
    if (signals.includes("citrix") && s.module === "citrix_audit") return true
    if (signals.includes("vpn") && (s.module === "citrix_audit" || s.module === "oauth_consent_audit")) return true
    return signals.length === 0 || signals.includes("oauth") || signals.includes("idp")
  })
  const finalSteps = steps.length >= 3 ? steps : AITM_MODULES

  return {
    target,
    dryRun,
    steps: finalSteps,
    stackSignals: signals,
    recommendations: [
      "Enforce CA policies blocking token replay from untrusted networks",
      "Require compliant device + phishing-resistant MFA for VPN/Citrix",
      "Monitor for session cookie theft indicators (T1539)",
    ],
    summary: `AiTM playbook — ${finalSteps.length} steps (${dryRun ? "dry-run" : "live"})`,
  }
}

export function detectAitmSignals(text: string): string[] {
  const t = text.toLowerCase()
  const out: string[] = []
  if (/citrix|netscaler|aaacookie/i.test(t)) out.push("citrix")
  if (/vpn|pulse|fortinet|zscaler/i.test(t)) out.push("vpn")
  if (/oauth|entra|okta|idp|sso/i.test(t)) out.push("oauth", "idp")
  return out
}

export function aitmAwarenessForStack(stackSignals: string[]): string[] {
  if (!stackSignals.some((s) => /citrix|vpn|oauth/i.test(s))) return []
  return [
    "AiTM chain: citrix_audit → oauth_consent_audit → evilginx_lab (HITL only for live proxy)",
    "Session cookie replay (T1539) — prioritize edge_audit + citrix_audit",
  ]
}

export default { buildAitmPlaybook, detectAitmSignals, aitmAwarenessForStack }
