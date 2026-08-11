/**
 * @module http_state_fuzzer
 * Structured HTTP API state machine fuzzer — session-aware multi-step flows,
 * parameter discovery, and L3 control-bypass proofs within a safety envelope.
 */
import * as crypto from "node:crypto"
import { ToolBroker } from "./tool_broker.ts"
import { resolveLiveMode } from "./exec_options.ts"

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE"

export interface HttpStep {
  name: string
  method: HttpMethod
  path: string
  headers?: Record<string, string>
  body?: string
  /** Extract session values from response via regex: { varName: "pattern" } */
  extract?: Record<string, string>
  /** Assert response characteristics */
  expect?: {
    status?: number
    bodyContains?: string
    bodyAbsent?: string
    headerPresent?: string
  }
}

export interface FuzzParam {
  name: string
  location: "query" | "body" | "header"
  payloads: string[]
}

export interface StateMachineFlow {
  id: string
  name: string
  baseUrl: string
  steps: HttpStep[]
  fuzzParams?: FuzzParam[]
  /** L3: prove privileged access without destructive action */
  l3Proof?: {
    stepName: string
    indicator: string
    maxImpact: "read_only" | "metadata_only"
  }
  /** L4: bounded canary object access proof */
  l4Proof?: {
    stepName: string
    canaryMarkers: string[]
    maxImpact: "read_only"
  }
}

export interface StepResult {
  step: string
  status: number
  headers: Record<string, string>
  bodySnippet: string
  extracted: Record<string, string>
  passed: boolean
  detail: string
}

export interface FuzzSession {
  cookies: Record<string, string>
  vars: Record<string, string>
  authHeader?: string
}

export interface FuzzRunResult {
  flowId: string
  flowName: string
  steps: StepResult[]
  fuzzHits: Array<{ param: string; payload: string; indicator: string }>
  l3BypassProven: boolean
  l3Evidence?: string
  l4ImpactProven: boolean
  l4Evidence?: string
  validationLevel: "L2" | "L3" | "L4"
  summary: string
}

const DEFAULT_PARAM_PAYLOADS = [
  "' OR '1'='1",
  "../../../etc/passwd",
  "{{7*7}}",
  "<script>alert(1)</script>",
  "admin",
  "true",
  "-1",
  "null",
]

function interpolate(template: string, session: FuzzSession): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => {
    if (session.vars[key] !== undefined) return session.vars[key]!
    if (session.cookies[key] !== undefined) return session.cookies[key]!
    return `{{${key}}}`
  })
}

function extractFromBody(body: string, patterns: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, pattern] of Object.entries(patterns)) {
    try {
      const m = body.match(new RegExp(pattern))
      if (m?.[1]) out[key] = m[1]
      else if (m?.[0]) out[key] = m[0]
    } catch { /* invalid pattern */ }
  }
  return out
}

function mergeCookies(existing: Record<string, string>, setCookie: string): Record<string, string> {
  const next = { ...existing }
  const parts = setCookie.split(";")[0]?.trim()
  if (!parts) return next
  const eq = parts.indexOf("=")
  if (eq > 0) next[parts.slice(0, eq)] = parts.slice(eq + 1)
  return next
}

export function buildCurlCommand(
  baseUrl: string,
  step: HttpStep,
  session: FuzzSession,
  broker: ToolBroker,
): string {
  const url = `${baseUrl.replace(/\/$/, "")}${interpolate(step.path, session)}`
  const headers: Record<string, string> = { ...(step.headers ?? {}) }
  if (session.authHeader) headers["Authorization"] = session.authHeader
  const cookieStr = Object.entries(session.cookies).map(([k, v]) => `${k}=${v}`).join("; ")
  if (cookieStr) headers["Cookie"] = cookieStr

  const parts = [`curl -sS -D - -o /tmp/ourmine_fuzz_body --max-time 10 -X ${step.method}`]
  for (const [k, v] of Object.entries(headers)) {
    parts.push(`-H ${JSON.stringify(`${k}: ${interpolate(v, session)}`)}`)
  }
  if (step.body) {
    parts.push(`-d ${JSON.stringify(interpolate(step.body, session))}`)
  }
  parts.push(JSON.stringify(url))
  return parts.join(" ")
}

export function parseCurlResponse(raw: string, bodyFromFile?: string): {
  status: number
  headers: Record<string, string>
  body: string
  setCookies: string[]
} {
  const headerEnd = raw.indexOf("\r\n\r\n")
  const headerBlock = headerEnd >= 0 ? raw.slice(0, headerEnd) : raw
  const lines = headerBlock.split(/\r?\n/)
  let status = 0
  const headers: Record<string, string> = {}
  const setCookies: string[] = []
  for (const line of lines) {
    if (line.startsWith("HTTP/")) {
      const m = line.match(/HTTP\/[\d.]+\s+(\d+)/)
      if (m) status = parseInt(m[1]!, 10)
    } else {
      const idx = line.indexOf(":")
      if (idx > 0) {
        const k = line.slice(0, idx).trim().toLowerCase()
        const v = line.slice(idx + 1).trim()
        headers[k] = v
        if (k === "set-cookie") setCookies.push(v)
      }
    }
  }
  const body = bodyFromFile ?? (headerEnd >= 0 ? raw.slice(headerEnd + 4) : "")
  return { status, headers, body, setCookies }
}

export async function runStateMachineFlow(
  flow: StateMachineFlow,
  opts: { broker?: ToolBroker; live?: boolean } = {},
): Promise<FuzzRunResult> {
  const broker = opts.broker ?? new ToolBroker()
  const live = resolveLiveMode(opts)
  const session: FuzzSession = { cookies: {}, vars: {} }
  const stepResults: StepResult[] = []
  const fuzzHits: FuzzRunResult["fuzzHits"] = []
  let l3BypassProven = false
  let l3Evidence: string | undefined
  let l4ImpactProven = false
  let l4Evidence: string | undefined
  let validationLevel: FuzzRunResult["validationLevel"] = "L2"

  for (const step of flow.steps) {
    const cmd = buildCurlCommand(flow.baseUrl, step, session, broker)
    let status = 0
    let body = ""
    let headers: Record<string, string> = {}
    let setCookies: string[] = []

    if (live) {
      try {
        const exec = await broker.executeSafe(cmd, process.cwd())
        const raw = exec.stdout + exec.stderr
        try {
          const fs = await import("node:fs/promises")
          body = await fs.readFile("/tmp/ourmine_fuzz_body", "utf8").catch(() => "")
        } catch { body = "" }
        const parsed = parseCurlResponse(raw, body)
        status = parsed.status
        headers = parsed.headers
        body = parsed.body || body
        setCookies = parsed.setCookies
      } catch (err) {
        stepResults.push({
          step: step.name,
          status: 0,
          headers: {},
          bodySnippet: String((err as Error).message).slice(0, 300),
          extracted: {},
          passed: false,
          detail: `curl failed: ${(err as Error).message}`,
        })
        continue
      }
    } else {
      stepResults.push({
        step: step.name,
        status: 0,
        headers: {},
        bodySnippet: "",
        extracted: {},
        passed: false,
        detail: "live execution required — no simulation",
      })
      continue
    }

    for (const sc of setCookies) session.cookies = mergeCookies(session.cookies, sc)
    const extracted = step.extract ? extractFromBody(body, step.extract) : {}
    Object.assign(session.vars, extracted)

    let passed = status > 0
    if (step.expect?.status !== undefined && status !== step.expect.status) passed = false
    if (step.expect?.bodyContains && !body.includes(step.expect.bodyContains)) passed = false
    if (step.expect?.bodyAbsent && body.includes(step.expect.bodyAbsent)) passed = false
    if (step.expect?.headerPresent && !headers[step.expect.headerPresent.toLowerCase()]) passed = false

    stepResults.push({
      step: step.name,
      status,
      headers,
      bodySnippet: body.slice(0, 500),
      extracted,
      passed,
      detail: passed ? "step expectations met" : "step expectations not met",
    })

    if (flow.l3Proof?.stepName === step.name && flow.l3Proof.indicator) {
      if (body.includes(flow.l3Proof.indicator) || Object.values(headers).some((v) => v.includes(flow.l3Proof!.indicator))) {
        l3BypassProven = true
        l3Evidence = body.slice(0, 400)
        validationLevel = "L3"
      }
    }

    if (flow.l4Proof?.stepName === step.name) {
      for (const marker of flow.l4Proof.canaryMarkers) {
        if (body.includes(marker) || Object.values(headers).some((v) => v.includes(marker))) {
          l4ImpactProven = true
          l4Evidence = body.slice(0, 400)
          validationLevel = "L4"
          break
        }
      }
    }
  }

  for (const param of flow.fuzzParams ?? []) {
    for (const payload of param.payloads.length ? param.payloads : DEFAULT_PARAM_PAYLOADS.slice(0, 4)) {
      const probeStep: HttpStep = {
        name: `fuzz_${param.name}`,
        method: "GET",
        path: param.location === "query" ? `/?${param.name}=${encodeURIComponent(payload)}` : "/",
        headers: param.location === "header" ? { [param.name]: payload } : {},
      }
      const cmd = buildCurlCommand(flow.baseUrl, probeStep, session, broker)
      if (!live) continue
      try {
        const exec = await broker.executeSafe(cmd, process.cwd())
        const parsed = parseCurlResponse(exec.stdout + exec.stderr)
        const indicators = ["syntax error", "sql", "root:", "admin", "49", "exception", "stack trace"]
        for (const ind of indicators) {
          if (parsed.body.toLowerCase().includes(ind) || (exec.stdout + exec.stderr).toLowerCase().includes(ind)) {
            fuzzHits.push({ param: param.name, payload, indicator: ind })
            validationLevel = "L3"
          }
        }
      } catch { /* skip failed fuzz probe */ }
    }
  }

  const summary = l4ImpactProven
    ? `L4 controlled impact proven for flow '${flow.name}'`
    : l3BypassProven
      ? `L3 bypass proven for flow '${flow.name}'`
      : fuzzHits.length
        ? `L3 indicators from parameter fuzz (${fuzzHits.length} hits)`
        : stepResults.every((s) => s.passed)
          ? `L2 state machine completed for '${flow.name}'`
          : `Partial completion for '${flow.name}'`

  return {
    flowId: flow.id,
    flowName: flow.name,
    steps: stepResults,
    fuzzHits,
    l3BypassProven,
    l3Evidence,
    l4ImpactProven,
    l4Evidence,
    validationLevel,
    summary,
  }
}

/** Pre-built flows for common patterns */
export function defaultAuthBypassFlow(baseUrl: string): StateMachineFlow {
  return {
    id: crypto.randomUUID(),
    name: "auth-bypass-chain",
    baseUrl,
    steps: [
      { name: "login", method: "POST", path: "/login", body: '{"user":"test","pass":"test"}', expect: { status: 401 } },
      { name: "admin_probe", method: "GET", path: "/admin", expect: {} },
      { name: "api_users", method: "GET", path: "/api/v1/users", headers: { Authorization: "Bearer {{token}}" } },
    ],
    fuzzParams: [
      { name: "id", location: "query", payloads: ["1", "2", "0", "admin"] },
      { name: "role", location: "query", payloads: ["admin", "user"] },
    ],
    l3Proof: { stepName: "admin_probe", indicator: "admin", maxImpact: "read_only" },
  }
}

export function defaultL4CanaryFlow(baseUrl: string): StateMachineFlow {
  return {
    id: crypto.randomUUID(),
    name: "l4-canary-chain",
    baseUrl,
    steps: [
      { name: "canary_probe", method: "GET", path: "/api/v1/users", expect: {} },
      { name: "admin_data", method: "GET", path: "/admin", expect: {} },
      { name: "backup_probe", method: "GET", path: "/backup.sql", expect: {} },
    ],
    l4Proof: {
      stepName: "canary_probe",
      canaryMarkers: ["admin", "CONFIDENTIAL", "password", "secret", "Log4j", "root:"],
      maxImpact: "read_only",
    },
  }
}

export function defaultSessionFlow(baseUrl: string, loginPath = "/login"): StateMachineFlow {
  return {
    id: crypto.randomUUID(),
    name: "session-chain",
    baseUrl,
    steps: [
      {
        name: "authenticate",
        method: "POST",
        path: loginPath,
        body: '{"username":"admin","password":"admin"}',
        extract: { token: '"token"\\s*:\\s*"([^"]+)"' },
      },
      {
        name: "authenticated_request",
        method: "GET",
        path: "/api/v1/me",
        headers: { Authorization: "Bearer {{token}}" },
      },
    ],
    fuzzParams: [{ name: "page", location: "query", payloads: ["1", "-1", "9999"] }],
  }
}

export default { runStateMachineFlow, defaultAuthBypassFlow, defaultSessionFlow, defaultL4CanaryFlow, buildCurlCommand }
