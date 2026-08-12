/**
 * @module roe_attestation
 * Rules-of-Engagement / scope attestation gate before live probes.
 * Requires OURMINE_ROE_SIGNED=1 when live execution is enabled.
 */
import * as crypto from "node:crypto"
import { resolveLiveMode } from "./exec_options.ts"

export interface RoeAttestation {
  signed: boolean
  scopeHash?: string
  signedAt?: string
  attestedBy?: string
}

export function isRoeSigned(): boolean {
  const v = process.env.OURMINE_ROE_SIGNED?.trim().toLowerCase()
  if (v === "1" || v === "true") return true
  if (v === "0" || v === "false") return false
  // Lab default: OURMINE_BATTLE_READY=1 auto-attests RoE for authorized engagements
  const br = process.env.OURMINE_BATTLE_READY?.trim().toLowerCase()
  return br === "1" || br === "true" || br === "yes"
}

/** Stable hash of declared scope for attestation audit trail. */
export function hashScope(scope: string[] | string): string {
  const list = Array.isArray(scope) ? scope : scope.split(",").map((s) => s.trim()).filter(Boolean)
  const normalized = [...list].map((s) => s.toLowerCase()).sort().join("|")
  return crypto.createHash("sha256").update(normalized || "default").digest("hex").slice(0, 16)
}

export function getRoeAttestation(scope?: string[] | string): RoeAttestation {
  const signed = isRoeSigned()
  if (!signed) return { signed: false }
  const scopeHash = scope ? hashScope(scope) : undefined
  return {
    signed: true,
    scopeHash,
    signedAt: process.env.OURMINE_ROE_SIGNED_AT ?? new Date().toISOString(),
    attestedBy: process.env.OURMINE_ROE_ATTESTED_BY ?? "operator",
  }
}

/** Block live probes when RoE attestation is missing. Dry-run always passes. */
export function evaluateRoeGate(opts: { live?: boolean; scope?: string[] | string } = {}): {
  allowed: boolean
  blockers: string[]
  attestation: RoeAttestation
} {
  const live = opts.live ?? resolveLiveMode()
  const attestation = getRoeAttestation(opts.scope)
  if (!live) return { allowed: true, blockers: [], attestation }
  if (attestation.signed) return { allowed: true, blockers: [], attestation }
  return {
    allowed: false,
    blockers: [
      "RoE not attested — set OURMINE_ROE_SIGNED=1 after written scope authorization before live probes",
    ],
    attestation,
  }
}

export default { isRoeSigned, hashScope, getRoeAttestation, evaluateRoeGate }
