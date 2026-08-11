/**
 * Shared helpers for ARES module authors — dry-run gates, structured results, tool guards.
 * REAL-ONLY: stubFinding removed from live paths; dry-run returns empty findings, never fakes.
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
  skipped?: boolean
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

/** Real finding from live execution evidence. */
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

/** Dry-run envelope — no fake findings, marks skipped. */
export function dryRunSkipped<T>(data: T, reason = "Pass live:true or run on Kali"): ModuleEnvelope<T> {
  return {
    dryRun: true,
    skipped: true,
    timestamp: new Date().toISOString(),
    findings: [],
    data: { ...data, skippedReason: reason },
  }
}

/** @deprecated Use realFinding in live mode; dryRunSkipped when dry-run. */
export function stubFinding(
  id: string,
  title: string,
  severity: ModuleFinding["severity"] = "info",
  mitreId?: string,
): ModuleFinding {
  return realFinding(id, title, severity, `[skipped dry-run] ${title}`, mitreId, "Pass live:true to execute")
}

export function requireToolOrDryRun(tool: string, dryRun: boolean): { ok: boolean; message?: string } {
  if (dryRun) return { ok: true, message: "dry-run skip" }
  if (isToolAvailable(tool)) return { ok: true }
  return { ok: false, message: `${tool} not on PATH — install or pass live:true on Kali` }
}

export function requireToolOrThrow(tool: string, dryRun: boolean): void {
  const check = requireToolOrDryRun(tool, dryRun)
  if (!check.ok) throw new Error(check.message ?? `${tool} unavailable`)
}
