/**
 * @module ares/_base
 * Shared live execution helpers for ARES APT-parity engines.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { ToolBroker } from "../tool_broker.ts"
import { resolveLiveMode } from "../exec_options.ts"
import { isToolAvailable } from "../tool_detection.ts"

export const ARES_ARTIFACT_DIR = path.resolve(process.cwd(), ".ourmine/ares")

export function ensureAresDir(sub: string): string {
  const dir = path.join(ARES_ARTIFACT_DIR, sub)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

export function liveRequired(module: string, opts: { live?: boolean }): boolean {
  if (!resolveLiveMode(opts)) {
    throw new Error(`${module}: live execution required — set --live or OURMINE_LIVE=1`)
  }
  return true
}

export async function brokerExec(cmd: string, broker = new ToolBroker()): Promise<{ ok: boolean; out: string; exit: number }> {
  try {
    const r = await broker.executeSafe(cmd, process.cwd())
    return { ok: r.exitCode === 0, out: (r.stdout + r.stderr).slice(0, 8000), exit: r.exitCode }
  } catch (err) {
    return { ok: false, out: String((err as Error).message).slice(0, 500), exit: 1 }
  }
}

export function writeArtifact(sub: string, name: string, content: string, mode?: number): string {
  const fp = path.join(ensureAresDir(sub), name)
  fs.writeFileSync(fp, content, mode ? { mode } : undefined)
  return fp
}

export { isToolAvailable, ToolBroker, resolveLiveMode }
