/**
 * Unified live/dry-run option resolution for ARES modules.
 * CLI passes `{ live: true }`; modules may also accept explicit `dryRun`.
 */
export function resolveDryRun(opts: { live?: boolean; dryRun?: boolean } = {}): boolean {
  if (opts.dryRun !== undefined) return opts.dryRun
  return !(opts.live ?? false)
}

export function resolveLive(opts: { live?: boolean; dryRun?: boolean } = {}): boolean {
  return !resolveDryRun(opts)
}
