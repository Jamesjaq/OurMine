/**
 * @module module_helpers
 * REAL-ONLY LIVE EXECUTION HELPERS — NO SIMULATIONS, NO STUBS.
 */
import { execSync } from "node:child_process"

export interface ModuleFinding {
  id: string
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  description: string
  mitreId?: string
  remediation?: string
}

export interface ModuleEnvelope<T = Record<string, unknown>> {
  live: boolean
  timestamp: string
  findings: ModuleFinding[]
  data: T
  error?: string
}

export function moduleEnvelope<T>(
  live: boolean,
  data: T,
  findings: ModuleFinding[] = [],
): ModuleEnvelope<T> {
  if (!live) {
    throw new Error("[OurMine Security] LIVE-ONLY MODE ENFORCED: Simulations and dry-runs are disabled. Provide live: true and execute actual engagement payloads.")
  }
  return {
    live,
    timestamp: new Date().toISOString(),
    findings,
    data,
  }
}

export function realFinding(
  id: string,
  title: string,
  severity: ModuleFinding["severity"],
  description: string,
  mitreId?: string,
  remediation?: string,
): ModuleFinding {
  return { id, title, severity, description, mitreId, remediation }
}

export function executeLiveCommand(cmd: string): { stdout: string; stderr: string; code: number } {
  try {
    const stdout = execSync(cmd, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] })
    return { stdout, stderr: "", code: 0 }
  } catch (err: any) {
    return {
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? err.message,
      code: err.status ?? 1,
    }
  }
}

/**
 * Super token-efficient summary for LLM context.
 * Shrinks findings and data to absolute essentials.
 */
export function summarizeForLlm(envelope: ModuleEnvelope<any>): string {
  const findings = envelope.findings.map(f => `[${f.severity.toUpperCase()}] ${f.id}: ${f.title}`).join("; ")
  const dataSummary = JSON.stringify(envelope.data).slice(0, 250)
  return `ARES_LIVE_RESULT: ${envelope.live ? "LIVE" : "DRY"}; Findings: ${findings || "None"}; Data: ${dataSummary}...`
}

export default { moduleEnvelope, realFinding, executeLiveCommand, summarizeForLlm }
