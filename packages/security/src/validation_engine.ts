/**
 * @module security/validation_engine
 * ValidationEngine — executes ValidationPlans, writes evidence back to AttackSurfaceGraph,
 * enforces the state machine, and triggers attack-path reanalysis.
 *
 * This is the ONLY path that can promote a finding to CONFIRMED.
 * Evidence must exist before promotion. The LLM has no call path here.
 *
 * All execution goes through ToolBroker → SandboxRunner (same security boundary
 * as every other tool call). No second execution path.
 */

import * as crypto   from "node:crypto"
import * as fs       from "node:fs"
import * as net      from "node:net"
import { AttackSurfaceGraph, type VulnNode, type Evidence }
  from "./attack_surface.ts"
import { FindingStateMachine, type FindingState }
  from "./finding_lifecycle.ts"
import { ValidationPlanner, type ValidationPlan, type ValidationResult, type ValidationOutcome }
  from "./validation_planner.ts"
import { ToolBroker } from "./tool_broker.ts"

// Per-session deduplication: fingerprint → last outcome + timestamp
const VALIDATION_CACHE = new Map<string, { outcome: ValidationOutcome; ts: string; planId: string }>()
const CACHE_TTL_MS     = 5 * 60 * 1_000   // 5 minutes

const broker = new ToolBroker()

// ─── Public API ──────────────────────────────────────────────────────────────

export interface ValidationRequest {
  vuln:    VulnNode
  ip:      string
  port:    number
  service: string
  graph:   AttackSurfaceGraph
}

export interface EngineResult {
  validated:      boolean
  plan?:          ValidationPlan
  result?:        ValidationResult
  skipReason?:    string     // set when validation was skipped / not planned
}

export class ValidationEngine {

  /**
   * Main entry point. Given a suspected VulnNode, determine whether it is
   * eligible for automatic validation, plan it, execute it, update the graph.
   * Returns the outcome without the LLM needing to be involved.
   */
  static async validate(req: ValidationRequest): Promise<EngineResult> {
    const { vuln, ip, port, service, graph } = req

    // ── 1. Eligibility check ─────────────────────────────────────────────────
    if (vuln.state !== "SUSPECTED" && vuln.state !== "VALIDATION_PENDING") {
      return { validated: false, skipReason: `Finding already in terminal state '${vuln.state}'` }
    }

    // ── 2. Plan ──────────────────────────────────────────────────────────────
    const target   = port ? `${ip}:${port}` : ip
    const planned  = ValidationPlanner.plan({
      findingId:       vuln.id,
      templateId:      vuln.cve ?? vuln.id,
      service,
      target,
      authorizedScope: graph.target,
    })

    if (!planned.plan) {
      this.transitionVuln(vuln, "UNVERIFIED", planned.reason)
      graph.invalidatePaths()
      return { validated: false, skipReason: planned.reason }
    }

    const { plan } = planned

    // ── 3. Idempotency check ─────────────────────────────────────────────────
    const cached = VALIDATION_CACHE.get(plan.fingerprint)
    if (cached) {
      const age = Date.now() - new Date(cached.ts).getTime()
      if (age < CACHE_TTL_MS) {
        return { validated: false, skipReason: `Idempotent skip: already validated ${Math.round(age / 1_000)}s ago (${cached.outcome})` }
      }
    }

    // ── 4. State machine: SUSPECTED → VALIDATION_PENDING → VALIDATING ────────
    this.transitionVuln(vuln, "VALIDATION_PENDING", `plan=${plan.planId} cap=${plan.capabilityId}`)
    this.transitionVuln(vuln, "VALIDATING", `executing ${plan.strategy}`)

    // ── 5. Execute ───────────────────────────────────────────────────────────
    const t0  = Date.now()
    let result: ValidationResult

    try {
      result = await this.executeStrategy(plan, ip, port, service)
    } catch (err: any) {
      result = {
        planId:      plan.planId,
        findingId:   vuln.id,
        outcome:     "VALIDATION_FAILED",
        evidence:    String(err?.message ?? err),
        executionMs: Date.now() - t0,
        timestamp:   new Date().toISOString(),
        reasoning:   `Validator threw an exception: ${err?.message}`,
      }
    }

    // ── 6. Update cache ──────────────────────────────────────────────────────
    VALIDATION_CACHE.set(plan.fingerprint, {
      outcome: result.outcome,
      ts:      result.timestamp,
      planId:  plan.planId,
    })

    // ── 7. Build evidence node & attach to vuln ──────────────────────────────
    const evidence: Evidence = graph.makeEvidence(
      plan.capabilityId,
      plan.command ?? `[host-inspect:${plan.capabilityId}]`,
      result.evidence,
      result.executionMs,
    )
    vuln.evidence.push(evidence)

    // ── 8. Final state transition ────────────────────────────────────────────
    if (result.outcome === "VALIDATION_SUCCESS") {
      this.transitionVuln(vuln, "CONFIRMED", result.reasoning)
      vuln.validatedAt = result.timestamp
    } else if (result.outcome === "VALIDATION_NEGATIVE") {
      this.transitionVuln(vuln, "FALSE_POSITIVE", result.reasoning)
      vuln.falsePositiveReason = result.reasoning
    } else {
      // FAILED / TIMEOUT / UNAVAILABLE → UNVERIFIED (not FALSE_POSITIVE)
      this.transitionVuln(vuln, "UNVERIFIED", `${result.outcome}: ${result.reasoning}`)
    }

    // ── 9. Re-run attack-path analysis now that state changed ────────────────
    graph.analyzeAttackPaths()

    return { validated: true, plan, result }
  }

  // ─── Strategy dispatchers ──────────────────────────────────────────────────

  private static async executeStrategy(
    plan: ValidationPlan,
    ip: string,
    port: number,
    service: string,
  ): Promise<ValidationResult> {
    const t0 = Date.now()

    switch (plan.strategy) {
      case "HTTP_PROBE":
        return this.httpProbe(plan, ip, port, t0)
      case "TLS_PROBE":
      case "SERVICE_BANNER":
      case "NMAP_SCRIPT":
        return this.shellProbe(plan, t0)
      case "HOST_INSPECT":
        return this.hostInspect(plan, t0)
      case "DNS_PROBE":
        return this.shellProbe(plan, t0)
      default:
        return {
          planId:      plan.planId,
          findingId:   plan.findingId,
          outcome:     "VALIDATION_UNAVAILABLE",
          evidence:    `No executor for strategy ${plan.strategy}`,
          executionMs: Date.now() - t0,
          timestamp:   new Date().toISOString(),
          reasoning:   `Strategy '${plan.strategy}' has no registered executor.`,
        }
    }
  }

  // ── HTTP probe: real TCP connection, real HTTP response ───────────────────

  private static async httpProbe(
    plan: ValidationPlan,
    ip: string,
    port: number,
    t0: number,
  ): Promise<ValidationResult> {
    const opts     = plan.httpOptions!
    const protocol = port === 443 || port === 8443 ? "https" : "http"
    const url      = `${protocol}://${ip}:${port}${opts.path}`

    // Use ToolBroker to run curl (same security boundary as all other tools)
    if (!plan.command) {
      return {
        planId: plan.planId, findingId: plan.findingId,
        outcome: "VALIDATION_UNAVAILABLE", evidence: "No curl command built",
        executionMs: Date.now() - t0, timestamp: new Date().toISOString(),
        reasoning: "HTTP_PROBE plan missing command.",
      }
    }

    try {
      const execResult = await broker.executeSafe(plan.command, process.cwd())
      const raw        = (execResult.stdout + execResult.stderr).slice(0, 4_000)
      const statusMatch = raw.match(/(\d{3})/)
      const httpStatus  = statusMatch ? parseInt(statusMatch[1]!, 10) : 0

      // Evaluate: did we get a response at all?
      const gotResponse = httpStatus > 0 || raw.includes("HTTP/")

      // Check expected characteristics
      let success = gotResponse

      if (opts.expectedStatus && httpStatus !== opts.expectedStatus) {
        // We got a real response but wrong status — negative not failed
        if (httpStatus > 0) {
          return buildResult(plan, t0, "VALIDATION_NEGATIVE", raw,
            `HTTP ${httpStatus} received; expected ${opts.expectedStatus}. Service exists but status differs.`)
        }
        success = false
      }
      if (opts.expectedBodyContains && !raw.includes(opts.expectedBodyContains)) {
        return buildResult(plan, t0, "VALIDATION_NEGATIVE", raw,
          `Expected '${opts.expectedBodyContains}' not found in response.`)
      }
      if (opts.expectedBodyAbsent && raw.includes(opts.expectedBodyAbsent)) {
        return buildResult(plan, t0, "VALIDATION_SUCCESS", raw,
          `Confirmed: response contains indicator '${opts.expectedBodyAbsent}'.`)
      }

      return buildResult(plan, t0,
        gotResponse ? "VALIDATION_SUCCESS" : "VALIDATION_FAILED",
        raw,
        gotResponse
          ? `HTTP service responded on ${url} (status=${httpStatus}).`
          : `No HTTP response from ${url}.`
      )
    } catch (err: any) {
      if (err?.message?.includes("ECONNREFUSED") || err?.message?.includes("not in allowlist")) {
        return buildResult(plan, t0, "VALIDATION_UNAVAILABLE", err.message,
          `Cannot reach ${url}: ${err.message}`)
      }
      return buildResult(plan, t0, "VALIDATION_FAILED", err.message,
        `curl execution error: ${err.message}`)
    }
  }

  // ── Shell probe: nmap scripts, dig, etc. ──────────────────────────────────

  private static async shellProbe(plan: ValidationPlan, t0: number): Promise<ValidationResult> {
    if (!plan.command) {
      return buildResult(plan, t0, "VALIDATION_UNAVAILABLE", "",
        "Shell probe plan has no command.")
    }
    try {
      const execResult = await broker.executeSafe(plan.command, process.cwd())
      const raw = (execResult.stdout + execResult.stderr).slice(0, 4_000)
      const success = execResult.exitCode === 0 && raw.length > 0
      // For mysql-empty-password: success indicator is presence of "mysql-empty-password"
      const mysqlVuln = plan.capabilityId === "mysql-empty-password" &&
                        raw.toLowerCase().includes("empty-password")
      return buildResult(plan, t0,
        (success || mysqlVuln) ? "VALIDATION_SUCCESS" : "VALIDATION_NEGATIVE",
        raw,
        `${plan.capabilityId} exit=${execResult.exitCode}: ${raw.slice(0, 200)}`
      )
    } catch (err: any) {
      const notInAllowlist = err?.message?.includes("not in allowlist") ||
                             err?.message?.includes("not allowed")
      return buildResult(plan, t0,
        notInAllowlist ? "VALIDATION_UNAVAILABLE" : "VALIDATION_FAILED",
        err.message,
        `${plan.capabilityId} execution error: ${err.message}`)
    }
  }

  // ── Host inspect: read-only local filesystem ──────────────────────────────

  private static hostInspect(plan: ValidationPlan, t0: number): ValidationResult {
    try {
      if (plan.capabilityId === "host-ldpreload") {
        const exists = fs.existsSync("/etc/ld.so.preload")
        const content = exists ? fs.readFileSync("/etc/ld.so.preload", "utf8").trim() : ""
        const vuln = exists && content.length > 0
        return buildResult(plan, t0,
          vuln ? "VALIDATION_SUCCESS" : "VALIDATION_NEGATIVE",
          content || "(empty)",
          vuln
            ? `/etc/ld.so.preload contains: ${content.slice(0, 200)}`
            : "/etc/ld.so.preload does not exist or is empty."
        )
      }
      return buildResult(plan, t0, "VALIDATION_UNAVAILABLE", "",
        `No host-inspect handler for capability '${plan.capabilityId}'`)
    } catch (err: any) {
      return buildResult(plan, t0, "VALIDATION_FAILED", err.message,
        `Host inspect error: ${err.message}`)
    }
  }

  // ─── State-machine helper ─────────────────────────────────────────────────

  private static transitionVuln(vuln: VulnNode, to: FindingState, reason: string): void {
    if (!vuln.stateMachine) {
      vuln.stateMachine = new FindingStateMachine(vuln.state as FindingState)
    }
    if (vuln.stateMachine.canTransitionTo(to)) {
      vuln.stateMachine.transition(to, reason)
      vuln.state = to   // keep VulnNode.state in sync
    }
    // If transition is not legal, silently skip — do not throw in the engine
  }
}

// ─── Result builder ───────────────────────────────────────────────────────────

function buildResult(
  plan:        ValidationPlan,
  t0:          number,
  outcome:     ValidationOutcome,
  evidence:    string,
  reasoning:   string,
): ValidationResult {
  return {
    planId:      plan.planId,
    findingId:   plan.findingId,
    outcome,
    evidence:    evidence.slice(0, 4_000),
    executionMs: Date.now() - t0,
    timestamp:   new Date().toISOString(),
    reasoning,
  }
}

export default ValidationEngine
