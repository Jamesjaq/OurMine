/**
 * @module security/capability_policy
 * Capability-Based Authorization & Blast-Radius Control Policy Engine
 * Evaluates execution requests based on fine-grained capabilities, target scoping,
 * argument constraints, and short-lived cryptographic authorization tokens.
 */

import { CapabilityTokenEngine } from "./crypto_token.ts"

export type CapabilityType =
  | "NETWORK_RECON"
  | "WEB_AUDIT"
  | "DNS_LOOKUP"
  | "FILE_YARA_SCAN"
  | "CONTAINER_AUDIT"
  | "READ_ONLY_INSPECT"

export interface CapabilityRequest {
  principal: string
  capability: CapabilityType
  target: string
  args: string[]
  authorizationToken?: string
}

export interface CapabilityEvaluation {
  allowed: boolean
  executable: string
  sanitizedArgs: string[]
  reason?: string
}

export class CapabilityPolicyEngine {
  private tokenEngine: CapabilityTokenEngine

  // Interpreter binaries strictly prohibited from raw command dispatch
  private static DANGEROUS_INTERPRETERS = new Set([
    "python", "python3", "node", "bun", "deno", "perl", "ruby", "php", "bash", "sh", "zsh"
  ])

  constructor(tokenEngine?: CapabilityTokenEngine) {
    this.tokenEngine = tokenEngine ?? new CapabilityTokenEngine("ourmine_master_policy_secret_2026")
  }

  public get tokenBroker(): CapabilityTokenEngine {
    return this.tokenEngine
  }

  /**
   * Evaluates capability execution against cryptographic tokens, binary restrictions, and target scope bounds.
   */
  public evaluate(req: CapabilityRequest): CapabilityEvaluation {
    // 1. Check for dangerous interpreter bypass attempts
    const binary = req.args[0] ?? ""
    if (CapabilityPolicyEngine.DANGEROUS_INTERPRETERS.has(binary.toLowerCase())) {
      return {
        allowed: false,
        executable: "",
        sanitizedArgs: [],
        reason: `[Policy Denial]: Interpreter '${binary}' cannot be invoked directly. Use structured security modules or isolated sandbox.`,
      }
    }

    // 2. Cryptographic token verification (if token supplied)
    if (req.authorizationToken) {
      const tokenCheck = this.tokenEngine.verifyToken(req.authorizationToken, req.capability, req.target)
      if (!tokenCheck.valid) {
        return {
          allowed: false,
          executable: "",
          sanitizedArgs: [],
          reason: `[Token Denial]: ${tokenCheck.reason}`,
        }
      }
    }

    // 3. Capability mapping & argument validation
    switch (req.capability) {
      case "NETWORK_RECON": {
        if (!req.target || req.target === "127.0.0.1" || req.target === "localhost") {
          return { allowed: false, executable: "", sanitizedArgs: [], reason: "Target scope violation: cannot scan localhost/loopback" }
        }
        return {
          allowed: true,
          executable: "nmap",
          sanitizedArgs: ["-sV", "-Pn", req.target],
        }
      }

      case "DNS_LOOKUP": {
        return {
          allowed: true,
          executable: "dig",
          sanitizedArgs: [req.target, "+short"],
        }
      }

      case "FILE_YARA_SCAN": {
        if (req.target.includes("..") || req.target.startsWith("/etc") || req.target.startsWith("/proc")) {
          return { allowed: false, executable: "", sanitizedArgs: [], reason: "Path traversal or system directory access prohibited" }
        }
        return {
          allowed: true,
          executable: "yara",
          sanitizedArgs: ["-r", req.target],
        }
      }

      default:
        return {
          allowed: false,
          executable: "",
          sanitizedArgs: [],
          reason: `Capability '${req.capability}' is not configured in policy engine.`,
        }
    }
  }
}

export default CapabilityPolicyEngine
