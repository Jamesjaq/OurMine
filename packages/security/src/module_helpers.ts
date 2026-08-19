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
/**
 * Smart token-efficient summary for LLM context.
 * Preserves critical technical indicators while compressing boilerplate.
 */
export function summarizeForLlm(envelope: ModuleEnvelope<any>): string {
  const findings = envelope.findings.map(f => `[${f.severity.toUpperCase()}] ${f.id}: ${f.title}`).join("; ")
  
  // Extract key technical indicators from data if they exist
  const data = envelope.data || {}
  const indicators: string[] = []
  
  if (data.target) indicators.push(`target:${data.target}`)
  if (data.ip) indicators.push(`ip:${data.ip}`)
  if (data.domain) indicators.push(`domain:${data.domain}`)
  if (data.port) indicators.push(`port:${data.port}`)
  if (data.user || data.username) indicators.push(`user:${data.user || data.username}`)
  if (data.objective) indicators.push(`objective:"${data.objective}"`)
  
  // Bespoke for Syndicate Prime
  if (data.mission?.missionId) indicators.push(`missionId:${data.mission.missionId}`)
  if (data.succeeded !== undefined) indicators.push(`succeeded:${data.succeeded}/${data.total}`)

  const indicatorStr = indicators.length > 0 ? ` Indicators: ${indicators.join(", ")};` : ""
  const dataStr = JSON.stringify(data).slice(0, 400) // Increased slightly for better context
  
  return `ARES_LIVE_RESULT: ${envelope.live ? "LIVE" : "DRY"};${indicatorStr} Findings: ${findings || "None"}; Summary: ${data.summary || dataStr.slice(0, 200)}... [Full data preserved in local artifact]`
}

export default { moduleEnvelope, realFinding, executeLiveCommand, summarizeForLlm }
