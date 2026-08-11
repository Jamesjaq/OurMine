/**
 * @module live_executor
 * Unified live execution — no simulated findings. Dry-run skips network; live fails loud.
 */
import { execFileSync } from "node:child_process"
import { resolveDryRun, resolveLiveMode, requireLiveMode } from "./exec_options.ts"
import { isToolAvailable, getToolPath } from "./tool_detection.ts"
import { ToolBroker } from "./tool_broker.ts"
import { gateExecution } from "./opsec_gate.ts"

export type LiveOpts = { live?: boolean; dryRun?: boolean }

const broker = new ToolBroker()

export function isLive(opts: LiveOpts = {}): boolean {
  return resolveLiveMode(opts)
}

export function isDryRun(opts: LiveOpts = {}): boolean {
  return resolveDryRun(opts)
}

/** Throw when live execution required but tool missing. */
export function requireTool(tool: string, opts: LiveOpts = {}): string {
  const dry = isDryRun(opts)
  const path = getToolPath(tool)
  if (path) return path
  if (dry) return ""
  const msg = `${tool} not on PATH — install for live execution (Kali: apt install ${tool})`
  if (requireLiveMode()) throw new Error(msg)
  throw new Error(msg)
}

export interface ExecResult {
  stdout: string
  stderr: string
  exitCode: number
  command: string
  live: boolean
}

/** Run command through OPSEC gate + ToolBroker. Skips when dry-run. */
export async function execLive(
  tool: string,
  command: string,
  opts: LiveOpts & { cwd?: string; profile?: string } = {},
): Promise<ExecResult> {
  if (isDryRun(opts)) {
    return { stdout: "", stderr: "", exitCode: 0, command, live: false }
  }
  requireTool(tool.split(" ")[0] ?? tool, opts)
  const gate = await gateExecution({ tool, command, profile: opts.profile, live: true })
  if (!gate.allowed) {
    return { stdout: "", stderr: gate.review.mitigations.join("; "), exitCode: 1, command, live: true }
  }
  const cmd = gate.mitigatedCommand ?? command
  const res = await broker.executeSafe(cmd, opts.cwd ?? process.cwd())
  return { stdout: res.stdout, stderr: res.stderr, exitCode: res.exitCode, command: cmd, live: true }
}

/** execFileSync wrapper — live only, throws if tool missing when live. */
export function execTool(
  tool: string,
  args: string[],
  opts: LiveOpts & { timeoutMs?: number } = {},
): { stdout: string; stderr: string; success: boolean } {
  if (isDryRun(opts)) {
    return { stdout: "", stderr: "", success: false }
  }
  const toolPath = requireTool(tool, opts)
  try {
    const stdout = execFileSync(toolPath, args, {
      encoding: "utf8",
      timeout: opts.timeoutMs ?? 60000,
      stdio: ["pipe", "pipe", "pipe"],
    })
    return { stdout, stderr: "", success: true }
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; message?: string }
    return {
      stdout: e.stdout ?? "",
      stderr: e.stderr ?? e.message ?? String(err),
      success: false,
    }
  }
}

export function toolReady(tool: string): boolean {
  return isToolAvailable(tool)
}

export default { isLive, isDryRun, requireTool, execLive, execTool, toolReady }
