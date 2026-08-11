/**
 * Shared helpers for ARES module authors — dry-run gates, structured results, tool guards.
 */
import { resolveDryRun, resolveLive } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"

export { resolveDryRun, resolveLive }

export interface ModuleFinding {
  id: string
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  description: string
  mitreId?: string
  remediation?: string
}

export interface ModuleEnvelope<T = Record<string, unknown>> {
  dryRun: boolean
  timestamp: string
  findings: ModuleFinding[]
  data: T
  error?: string
}

export function moduleEnvelope<T>(
  dryRun: boolean,
  data: T,
  findings: ModuleFinding[] = [],
): ModuleEnvelope<T> {
  return {
    dryRun,
    timestamp: new Date().toISOString(),
    findings,
    data,
  }
}

export function requireToolOrDryRun(tool: string, dryRun: boolean): { ok: boolean; message?: string } {
  if (dryRun) return { ok: true }
  if (isToolAvailable(tool)) return { ok: true }
  return { ok: false, message: `${tool} not on PATH — install or use dry-run mode` }
}

export function stubFinding(
  id: string,
  title: string,
  severity: ModuleFinding["severity"] = "info",
  mitreId?: string,
): ModuleFinding {
  return {
    id,
    title,
    severity,
    description: `[DRY-RUN] Simulated finding for ${title}`,
    mitreId,
    remediation: "Verify in authorised lab scope with --live",
  }
}
