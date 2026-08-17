/**
 * Unified live/dry-run option resolution for ARES modules.
 */
import * as fs from "node:fs"

export function isKaliLinux(): boolean {
  try {
    return /kali/i.test(fs.readFileSync("/etc/os-release", "utf8"))
  } catch {
    return false
  }
}

/** True when real execution is required (Kali, OURMINE_LIVE, --live, tier-1, or explicit live). */
export function resolveLiveMode(opts: { live?: boolean; dryRun?: boolean } = {}): boolean {
  if (opts.dryRun === true) return false
  if (opts.live === false) return false
  if (opts.live === true) return true
  if (process.env.OURMINE_ALLOW_DRY_RUN === "1") return false
  const env = process.env.OURMINE_LIVE
  if (env === "1" || env === "true") return true
  if (process.env.OURMINE_TIER1 === "1" || process.env.OURMINE_TIER1 === "true") return true
  if (process.env.OURMINE_AUTONOMOUS === "1") return true
  if (process.argv.includes("--live")) return true
  if (isKaliLinux()) return true
  return false
}

export function resolveDryRun(opts: { live?: boolean; dryRun?: boolean } = {}): boolean {
  if (opts.dryRun !== undefined) return opts.dryRun
  return !resolveLiveMode(opts)
}

export function resolveLive(opts: { live?: boolean; dryRun?: boolean } = {}): boolean {
  return resolveLiveMode(opts)
}

export function requireLiveMode(): boolean {
  return process.env.OURMINE_REQUIRE_LIVE === "1" || isKaliLinux()
}
