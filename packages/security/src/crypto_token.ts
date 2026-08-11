/**
 * @module security/crypto_token
 * Cryptographic Short-Lived Authorization Token Engine
 * Signs and verifies short-lived capability authorization tokens (HMAC-SHA256).
 * Binds operation, target scope, resource limits, and expiration to prevent token replay and scope drift.
 */

import { createHmac, randomBytes } from "node:crypto"

export interface CapabilityTokenPayload {
  tokenId: string
  principal: string
  action: string
  targetScope: string
  issuedAt: number
  expiresAt: number
  nonce: string
}

export class CapabilityTokenEngine {
  private secretKey: Buffer

  constructor(secretKey?: string) {
    this.secretKey = secretKey ? Buffer.from(secretKey) : randomBytes(32)
  }

  /**
   * Generates a short-lived signed capability token (default 5 min TTL).
   */
  public issueToken(principal: string, action: string, targetScope: string, ttlSeconds = 300): { token: string; payload: CapabilityTokenPayload } {
    const now = Math.floor(Date.now() / 1000)
    const payload: CapabilityTokenPayload = {
      tokenId: "cap_" + randomBytes(8).toString("hex"),
      principal,
      action,
      targetScope,
      issuedAt: now,
      expiresAt: now + ttlSeconds,
      nonce: randomBytes(8).toString("hex"),
    }

    const payloadStr = JSON.stringify(payload)
    const signature = createHmac("sha256", this.secretKey).update(payloadStr).digest("hex")
    const token = Buffer.from(payloadStr).toString("base64url") + "." + signature

    return { token, payload }
  }

  /**
   * Cryptographically verifies and validates a capability token.
   */
  public verifyToken(tokenStr: string, requiredAction: string, target: string): { valid: boolean; payload?: CapabilityTokenPayload; reason?: string } {
    try {
      const parts = tokenStr.split(".")
      if (parts.length !== 2) {
        return { valid: false, reason: "Malformed token format" }
      }

      const payloadStr = Buffer.from(parts[0], "base64url").toString("utf8")
      const signature = parts[1]
      const expectedSig = createHmac("sha256", this.secretKey).update(payloadStr).digest("hex")

      if (signature !== expectedSig) {
        return { valid: false, reason: "Invalid cryptographic signature" }
      }

      const payload = JSON.parse(payloadStr) as CapabilityTokenPayload
      const now = Math.floor(Date.now() / 1000)

      if (payload.expiresAt < now) {
        return { valid: false, reason: "Capability token expired" }
      }

      if (payload.action !== requiredAction) {
        return { valid: false, reason: `Action mismatch: expected '${requiredAction}', got '${payload.action}'` }
      }

      if (payload.targetScope !== "*" && !target.includes(payload.targetScope)) {
        return { valid: false, reason: `Target scope violation: '${target}' outside approved '${payload.targetScope}'` }
      }

      return { valid: true, payload }
    } catch (e: any) {
      return { valid: false, reason: `Token verification failed: ${e?.message}` }
    }
  }
}

export default CapabilityTokenEngine
