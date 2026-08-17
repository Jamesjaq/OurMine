/**
 * @module tier1_config
 * Master tier-1 mode — enables scope-gated autonomous pivot, C2, cred access.
 */

export function isTier1Enabled(): boolean {
  return process.env.OURMINE_TIER1 === "1"
    || process.env.OURMINE_TIER1 === "true"
    || process.env.OURMINE_AUTONOMOUS === "1"
}

/** Enable sub-flags for tier-1 autonomous operations (idempotent). */
export function enableTier1Mode(): void {
  if (!isTier1Enabled()) return
  process.env.OURMINE_AUTONOMOUS_PIVOT = "1"
  process.env.OURMINE_AUTONOMOUS_C2 = "1"
}

export function tier1MaxSteps(defaultSteps = 50): number {
  if (isTier1Enabled()) return Math.max(defaultSteps, 120)
  return defaultSteps
}

export default { isTier1Enabled, enableTier1Mode, tier1MaxSteps }
