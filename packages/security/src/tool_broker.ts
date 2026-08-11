/**
 * @module security/tool_broker
 * Hardened Tool Execution Broker
 * Enforces strict command allowlisting, path canonicalization, and argument sanitization.
 * Prevents arbitrary shell execution and command injection attacks.
 */

import { spawn } from "node:child_process"
import * as path from "node:path"

export interface ExecPolicy {
  allowedBinaries: Set<string>
  blockedSubcommands: Set<string>
  maxExecutionTimeMs: number
}

const DEFAULT_POLICY: ExecPolicy = {
  allowedBinaries: new Set([
    "nmap", "gobuster", "ffuf", "nikto", "sqlmap", "dig", "whois",
    "ping", "traceroute", "curl", "git", "yara", "masscan", "hydra",
    "john", "hashcat", "nuclei", "wfuzz", "smbclient", "enum4linux",
    "snmpwalk", "searchsploit", "msfvenom", "impacket-secretsdump",
    "impacket-GetUserSPNs", "impacket-GetNPUsers", "evil-winrm",
    "bloodhound-python", "openssl", "ssh", "nc", "netcat", "socat",
    "ftp", "python3"
  ]),
  blockedSubcommands: new Set([
    "rm -rf /", "mkfs", "dd", ":(){ :|:& };:", "-c import", "-e eval"
  ]),
  maxExecutionTimeMs: 300000,
}

export class ToolBroker {
  private policy: ExecPolicy

  constructor(policy: Partial<ExecPolicy> = {}) {
    this.policy = {
      allowedBinaries: policy.allowedBinaries ?? DEFAULT_POLICY.allowedBinaries,
      blockedSubcommands: policy.blockedSubcommands ?? DEFAULT_POLICY.blockedSubcommands,
      maxExecutionTimeMs: policy.maxExecutionTimeMs ?? DEFAULT_POLICY.maxExecutionTimeMs,
    }
  }

  /**
   * Sanitizes and validates a proposed command string.
   */
  public validateCommand(commandStr: string): { valid: boolean; binary: string; args: string[]; reason?: string } {
    const trimmed = commandStr.trim()
    if (!trimmed) {
      return { valid: false, binary: "", args: [], reason: "Empty command string" }
    }

    // Check against blocked dangerous patterns and shell metacharacters
    const metacharRegex = /[;&|`$]/
    if (metacharRegex.test(trimmed)) {
      return { valid: false, binary: "", args: [], reason: "Forbidden shell metacharacters detected (; & | ` $)" }
    }

    for (const blocked of this.policy.blockedSubcommands) {
      if (trimmed.includes(blocked)) {
        return { valid: false, binary: "", args: [], reason: `Forbidden subcommand pattern: ${blocked}` }
      }
    }

    // Simple shell parsing to extract base binary name
    const parts = trimmed.split(/\s+/)
    const rawBinary = parts[0]
    const binaryName = path.basename(rawBinary)

    if (!this.policy.allowedBinaries.has(binaryName)) {
      return {
        valid: false,
        binary: binaryName,
        args: parts.slice(1),
        reason: `Binary '${binaryName}' is not in the allowed security tool registry.`,
      }
    }

    return {
      valid: true,
      binary: binaryName,
      args: parts.slice(1),
    }
  }

  /**
   * Safely spawns command without shell evaluation (`shell: false`).
   */
  public async executeSafe(commandStr: string, cwd: string = process.cwd()): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    const validation = this.validateCommand(commandStr)
    if (!validation.valid) {
      throw new Error(`[ToolBroker Policy Denial]: ${validation.reason}`)
    }

    return new Promise((resolve, reject) => {
      const proc = spawn(validation.binary, validation.args, {
        cwd,
        env: { ...process.env, PATH: "/usr/local/bin:/usr/bin:/bin" }, // Fixed safe PATH
        shell: false, // Prevents shell metacharacter expansion
      })

      let stdout = ""
      let stderr = ""

      proc.stdout.on("data", (data) => { stdout += data.toString() })
      proc.stderr.on("data", (data) => { stderr += data.toString() })

      const timer = setTimeout(() => {
        proc.kill("SIGKILL")
        reject(new Error(`[ToolBroker Timeout]: Execution exceeded ${this.policy.maxExecutionTimeMs}ms`))
      }, this.policy.maxExecutionTimeMs)

      proc.on("close", (code) => {
        clearTimeout(timer)
        resolve({
          stdout: stdout.slice(0, 100000), // Enforce response truncation limits
          stderr: stderr.slice(0, 20000),
          exitCode: code ?? 1,
        })
      })
    })
  }
}

export default new ToolBroker()
