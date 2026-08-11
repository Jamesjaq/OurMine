/**
 * @module live_exec
 * Live execution gate — tier-1 modules refuse simulated/dry-run success paths.
 */
import { resolveLiveMode } from "./exec_options.ts"

export function isLiveExecution(opts: { live?: boolean; dryRun?: boolean } = {}): boolean {
  return resolveLiveMode(opts)
}

export function requireLiveExecution(module: string, opts: { live?: boolean; dryRun?: boolean } = {}): void {
  if (!isLiveExecution(opts)) {
    throw new Error(`${module}: live execution required — set --live, OURMINE_LIVE=1, or OURMINE_TIER1=1`)
  }
}

export function liveOrError<T>(
  module: string,
  opts: { live?: boolean; dryRun?: boolean },
  fn: () => Promise<T> | T,
): Promise<T | { error: string; liveRequired: true }> {
  if (!isLiveExecution(opts)) {
    return Promise.resolve({ error: `${module}: live execution required`, liveRequired: true as const })
  }
  return Promise.resolve(fn())
}

export default { isLiveExecution, requireLiveExecution, liveOrError }
