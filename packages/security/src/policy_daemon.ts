/**
 * @module security/policy_daemon
 * Independent Out-of-Process Policy & Token Authority Daemon
 * Operates as a separate process listening on a local Unix domain socket.
 * Keeps HMAC signing keys and policy evaluation completely isolated from the Node.js orchestrator.
 */

import * as net from "node:net"
import * as fs from "node:fs"
import { CapabilityTokenEngine } from "./crypto_token.ts"

export const POLICY_SOCKET_PATH = process.platform === "win32" ? "\\\\.\\pipe\\ourmine-policy" : "/tmp/ourmine-policy.sock"

export interface PolicyDaemonRequest {
  action: "ISSUE_TOKEN" | "VERIFY_TOKEN"
  principal: string
  capability: string
  targetScope: string
  token?: string
}

export interface PolicyDaemonResponse {
  success: boolean
  token?: string
  reason?: string
}

export class PolicyDaemon {
  private tokenEngine: CapabilityTokenEngine
  private server?: net.Server

  constructor() {
    // Independent HMAC secret generated in policy process memory space
    this.tokenEngine = new CapabilityTokenEngine()
  }

  public start(): Promise<void> {
    return new Promise((resolve) => {
      // Clean up stale socket file if present
      if (process.platform !== "win32" && fs.existsSync(POLICY_SOCKET_PATH)) {
        try { fs.unlinkSync(POLICY_SOCKET_PATH) } catch {}
      }

      this.server = net.createServer((socket) => {
        let buffer = ""
        socket.on("data", (chunk) => {
          buffer += chunk.toString()
          if (buffer.includes("\n")) {
            const lines = buffer.split("\n")
            buffer = lines.pop() ?? ""
            for (const line of lines) {
              if (!line.trim()) continue
              try {
                const req = JSON.parse(line) as PolicyDaemonRequest
                const res = this.handleRequest(req)
                socket.write(JSON.stringify(res) + "\n")
              } catch (e: any) {
                socket.write(JSON.stringify({ success: false, reason: `Invalid JSON request: ${e?.message}` }) + "\n")
              }
            }
          }
        })
      })

      this.server.listen(POLICY_SOCKET_PATH, () => {
        resolve()
      })
    })
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          if (process.platform !== "win32" && fs.existsSync(POLICY_SOCKET_PATH)) {
            try { fs.unlinkSync(POLICY_SOCKET_PATH) } catch {}
          }
          resolve()
        })
      } else {
        resolve()
      }
    })
  }

  private handleRequest(req: PolicyDaemonRequest): PolicyDaemonResponse {
    // 1. Prohibit dangerous execution capabilities
    if (req.capability.includes("SHELL") || req.capability.includes("INTERPRETER")) {
      return { success: false, reason: "Policy Authority Denial: Shell/Interpreter capability requested" }
    }

    if (req.action === "ISSUE_TOKEN") {
      const issued = this.tokenEngine.issueToken(req.principal, req.capability, req.targetScope, 120) // 2-min TTL
      return { success: true, token: issued.token }
    }

    if (req.action === "VERIFY_TOKEN") {
      if (!req.token) return { success: false, reason: "Missing token" }
      const check = this.tokenEngine.verifyToken(req.token, req.capability, req.targetScope)
      return { success: check.valid, reason: check.reason }
    }

    return { success: false, reason: `Unknown action '${req.action}'` }
  }
}

/**
 * Client helper used by orchestrators to request authorization from the independent policy daemon.
 */
export function requestPolicyToken(principal: string, capability: string, targetScope: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(POLICY_SOCKET_PATH, () => {
      const req: PolicyDaemonRequest = { action: "ISSUE_TOKEN", principal, capability, targetScope }
      client.write(JSON.stringify(req) + "\n")
    })

    client.on("data", (data) => {
      try {
        const res = JSON.parse(data.toString().trim()) as PolicyDaemonResponse
        client.end()
        if (res.success && res.token) resolve(res.token)
        else reject(new Error(`Policy Daemon Denial: ${res.reason}`))
      } catch (e) {
        client.end()
        reject(e)
      }
    })

    client.on("error", (err) => {
      reject(new Error(`Policy Daemon Connection Error: ${err.message}`))
    })
  })
}

export default PolicyDaemon
