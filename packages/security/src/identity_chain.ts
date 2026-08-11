/**
 * @module identity_chain
 * Identity chain executor — OAuth/MFA/Entra→AD sequences as state machines.
 */
import { ToolBroker } from "./tool_broker.ts"

export type IdentityChainPhase =
  | "discover_idp"
  | "oauth_enum"
  | "oauth_state_abuse"
  | "pkce_probe"
  | "token_acquire"
  | "refresh_rotation"
  | "mfa_probe"
  | "federation_map"
  | "ad_bridge"
  | "adcs_bridge"
  | "complete"

export interface IdentityChainStep {
  phase: IdentityChainPhase
  action: string
  command?: string
  expect?: { bodyContains?: string; status?: number }
  extract?: Record<string, string>
}

export interface IdentityChainState {
  target: string
  vars: Record<string, string>
  currentPhase: IdentityChainPhase
  steps: Array<{ phase: IdentityChainPhase; success: boolean; detail: string; finding?: string }>
  completed: boolean
  findings: string[]
}

const DEFAULT_CHAIN: IdentityChainStep[] = [
  {
    phase: "discover_idp",
    action: "fetch_well_known",
    command: "curl -sS {{base}}/.well-known/openid-configuration",
    extract: { authorization_endpoint: "\"authorization_endpoint\"\\s*:\\s*\"([^\"]+)\"" },
  },
  {
    phase: "oauth_enum",
    action: "oauth_metadata",
    command: "curl -sS \"{{base}}/oauth2/v2.0/authorize?client_id={{client_id}}&response_type=code&redirect_uri={{redirect}}&scope=openid\"",
  },
  {
    phase: "oauth_state_abuse",
    action: "state_reuse_probe",
    command: "curl -sS \"{{base}}/oauth2/v2.0/authorize?client_id={{client_id}}&response_type=code&redirect_uri={{redirect}}&state=fixedstate123&state=fixedstate123\"",
    expect: { bodyContains: "state" },
  },
  {
    phase: "pkce_probe",
    action: "pkce_downgrade",
    command: "curl -sS \"{{base}}/oauth2/v2.0/authorize?client_id={{client_id}}&response_type=code&redirect_uri={{redirect}}&code_challenge=&code_challenge_method=plain\"",
  },
  {
    phase: "token_acquire",
    action: "token_endpoint_probe",
    command: "curl -sS -X POST {{base}}/oauth2/v2.0/token -d grant_type=client_credentials",
  },
  {
    phase: "refresh_rotation",
    action: "refresh_token_probe",
    command: "curl -sS -X POST {{base}}/oauth2/v2.0/token -d grant_type=refresh_token&refresh_token=invalid_probe",
  },
  {
    phase: "mfa_probe",
    action: "mfa_methods",
    command: "curl -sS {{base}}/api/v1/users/me/mfa",
  },
  {
    phase: "federation_map",
    action: "federation_domains",
    command: "curl -sS {{base}}/.well-known/openid-configuration",
    extract: { issuer: "\"issuer\"\\s*:\\s*\"([^\"]+)\"" },
  },
  {
    phase: "ad_bridge",
    action: "hybrid_signin",
    command: "curl -sS \"{{base}}/common/oauth2/authorize?client_id={{client_id}}&response_type=id_token&scope=openid\"",
  },
  {
    phase: "adcs_bridge",
    action: "adcs_web_enroll_probe",
    command: "curl -sSk {{adcs_url}}/certsrv/",
  },
]

function interpolate(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, k: string) => vars[k] ?? "")
}

export function initIdentityChain(target: string): IdentityChainState {
  const base = target.startsWith("http") ? target.replace(/\/$/, "") : `https://${target}`
  return {
    target,
    vars: {
      base,
      client_id: "00000003-0000-0000-c000-000000000000",
      redirect: "https://localhost/callback",
      adcs_url: `https://adcs.${target.replace(/^https?:\/\//, "").split("/")[0]}`,
    },
    currentPhase: "discover_idp",
    steps: [],
    completed: false,
    findings: [],
  }
}

function detectFinding(phase: IdentityChainPhase, out: string): string | undefined {
  const lower = out.toLowerCase()
  if (phase === "oauth_state_abuse" && (lower.includes("state") || lower.includes("csrf"))) {
    return "OAuth state parameter handling observable — test for reuse"
  }
  if (phase === "pkce_probe" && !lower.includes("invalid") && lower.includes("code")) {
    return "PKCE downgrade may be accepted"
  }
  if (phase === "refresh_rotation" && lower.includes("refresh")) {
    return "Refresh token endpoint responds — test rotation/reuse"
  }
  if (phase === "federation_map" && lower.includes("sts.windows.net")) {
    return "Entra ID federation path detected — hybrid AD bridge possible"
  }
  if (phase === "adcs_bridge" && (lower.includes("certsrv") || lower.includes("certificate"))) {
    return "AD CS web enrollment exposed — ESC template chain candidate"
  }
  return undefined
}

export async function advanceIdentityChain(
  state: IdentityChainState,
  opts: { broker?: ToolBroker; live?: boolean; maxSteps?: number } = {},
): Promise<IdentityChainState> {
  const broker = opts.broker ?? new ToolBroker()
  const max = opts.maxSteps ?? DEFAULT_CHAIN.length
  let executed = 0

  for (const step of DEFAULT_CHAIN) {
    if (executed >= max) break
    if (phaseIndex(step.phase) < phaseIndex(state.currentPhase)) continue

    let success = false
    let detail = ""
    let finding: string | undefined

    if (opts.live === false) {
      detail = "dry-run"
      success = true
    } else if (step.command) {
      const cmd = interpolate(step.command, state.vars)
      try {
        const exec = await broker.executeSafe(cmd, process.cwd())
        const out = exec.stdout + exec.stderr
        detail = out.slice(0, 300)
        success = exec.exitCode === 0 || out.length > 20
        if (step.extract) {
          for (const [k, pat] of Object.entries(step.extract)) {
            const m = out.match(new RegExp(pat))
            if (m?.[1]) state.vars[k] = m[1]
          }
        }
        if (step.expect?.bodyContains && !out.includes(step.expect.bodyContains)) success = false
        finding = detectFinding(step.phase, out)
        if (finding) state.findings.push(finding)
      } catch (err) {
        detail = String((err as Error).message).slice(0, 200)
      }
    }

    state.steps.push({ phase: step.phase, success, detail, finding })
    state.currentPhase = step.phase
    executed++
    if (!success && !["mfa_probe", "adcs_bridge"].includes(step.phase)) break
  }

  state.completed = state.steps.length >= DEFAULT_CHAIN.length || state.currentPhase === "complete"
  if (state.steps.filter((s) => s.success).length >= 6) state.completed = true
  return state
}

function phaseIndex(p: IdentityChainPhase): number {
  const order: IdentityChainPhase[] = [
    "discover_idp", "oauth_enum", "oauth_state_abuse", "pkce_probe", "token_acquire",
    "refresh_rotation", "mfa_probe", "federation_map", "ad_bridge", "adcs_bridge", "complete",
  ]
  return order.indexOf(p)
}

export async function runIdentityChain(
  target: string,
  opts: { live?: boolean; broker?: ToolBroker } = {},
): Promise<IdentityChainState> {
  const state = initIdentityChain(target)
  return advanceIdentityChain(state, opts)
}

export default { initIdentityChain, advanceIdentityChain, runIdentityChain }
