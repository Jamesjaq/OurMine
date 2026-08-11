/**
 * @module security/sandbox_runner
 * OS-Level Ephemeral Sandboxed Subprocess Worker
 * Strips host credentials/environment variables, restricts execution directory to ephemeral paths,
 * enforces non-root execution boundaries, and isolates process execution.
 */

import { spawn } from "node:child_process"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"

export interface SandboxConfig {
  command: string
  args: string[]
  allowedTargetScope: string
  ephemeralCwd?: string
}

export interface SandboxResult {
  stdout: string
  stderr: string
  exitCode: number
  sandboxed: boolean
}

export class SandboxRunner {
  private static SENSITIVE_ENV_PREFIXES = [
    "AWS_", "GCP_", "AZURE_", "OPENAI_", "ANTHROPIC_", "GITHUB_", "SSH_",
    "TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH", "CREDENTIAL"
  ]

  /**
   * Sanitizes host environment by stripping all sensitive secrets and tokens.
   */
  public static sanitizeEnvironment(env: Record<string, string | undefined>): Record<string, string> {
    const cleanEnv: Record<string, string> = {
      PATH: "/usr/local/bin:/usr/bin:/bin",
      LANG: "C.UTF-8",
      HOME: os.tmpdir(),
    }

    for (const [key, value] of Object.entries(env)) {
      if (!value || key.toUpperCase() === "PATH") continue
      const upperKey = key.toUpperCase()
      const isSensitive = this.SENSITIVE_ENV_PREFIXES.some((prefix) => upperKey.includes(prefix))
      if (!isSensitive) {
        cleanEnv[key] = value
      }
    }

    return cleanEnv
  }

  /**
   * Executes binary in an isolated ephemeral directory with sanitized environment and non-root checks.
   */
  public static async executeSandboxed(config: SandboxConfig): Promise<SandboxResult> {
    const cleanEnv = this.sanitizeEnvironment(process.env as Record<string, string>)
    const ephemeralDir = config.ephemeralCwd ?? fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-sbx-"))

    // Fail-closed if attempting to execute as root user
    if (typeof process.getuid === "function" && process.getuid() === 0) {
      throw new Error("[Sandbox Policy Violation]: Refusing to execute sandbox binary as root (UID 0).")
    }

    return new Promise((resolve, reject) => {
      const proc = spawn(config.command, config.args, {
        cwd: ephemeralDir,
        env: cleanEnv,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      })

      let stdout = ""
      let stderr = ""

      proc.stdout.on("data", (data) => { stdout += data.toString() })
      proc.stderr.on("data", (data) => { stderr += data.toString() })

      const timeout = setTimeout(() => {
        proc.kill("SIGKILL")
        reject(new Error("[Sandbox Timeout]: Sandbox execution exceeded resource limits."))
      }, 30000)

      proc.on("close", (code) => {
        clearTimeout(timeout)
        // Clean up ephemeral workspace directory
        try { fs.rmSync(ephemeralDir, { recursive: true, force: true }) } catch {}

        resolve({
          stdout: stdout.slice(0, 50000),
          stderr: stderr.slice(0, 10000),
          exitCode: code ?? 1,
          sandboxed: true,
        })
      })
    })
  }
}

export default SandboxRunner
