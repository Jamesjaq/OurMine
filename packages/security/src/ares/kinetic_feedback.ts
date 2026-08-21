/**
 * @file kinetic_feedback.ts
 * @brief ARES v5.0 Kinetic Sovereignty — Failure-Analysis & Feedback Engine
 * Analyzes real-time execution telemetry, records actual failure codes,
 * and feeds back into module re-synthesis to prevent forced success.
 */

import * as fs from "node:fs"
import * as path from "node:path"

export interface ExecutionTelemetry {
  moduleName: string
  target: string
  exitCode: number
  stderr: string
  stdout: string
  timestamp: string
}

export class KineticFeedbackEngine {
  private logPath = path.join(process.cwd(), ".ourmine", "telemetry", "execution_log.json")
  private maxLogSize = 5 * 1024 * 1024 // 5 MB

  constructor() {
    const dir = path.dirname(this.logPath)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
  }

  public validateTelemetry(telemetry: unknown): telemetry is ExecutionTelemetry {
    if (!telemetry || typeof telemetry !== "object") return false
    const t = telemetry as Record<string, unknown>
    return (
      typeof t.moduleName === "string" &&
      typeof t.target === "string" &&
      typeof t.exitCode === "number" &&
      typeof t.stderr === "string" &&
      typeof t.stdout === "string" &&
      typeof t.timestamp === "string"
    )
  }

  public recordExecution(telemetry: ExecutionTelemetry): void {
    if (!this.validateTelemetry(telemetry)) {
      throw new Error("Invalid telemetry schema provided to KineticFeedbackEngine.")
    }

    let logs: ExecutionTelemetry[] = []
    if (fs.existsSync(this.logPath)) {
      try {
        // Rotate logs if file exceeds maxLogSize
        const stats = fs.statSync(this.logPath)
        if (stats.size > this.maxLogSize) {
          const bakPath = `${this.logPath}.${Date.now()}.bak`
          fs.renameSync(this.logPath, bakPath)
        } else {
          logs = JSON.parse(fs.readFileSync(this.logPath, "utf8"))
          if (!Array.isArray(logs)) logs = []
        }
      } catch (e) {
        logs = []
      }
    }

    logs.push(telemetry)

    // Atomic write pattern: write to tmp file then rename
    const tmpPath = `${this.logPath}.${process.pid}.${Date.now()}`
    fs.writeFileSync(tmpPath, JSON.stringify(logs, null, 2), "utf8")
    fs.renameSync(tmpPath, this.logPath)
  }

  public evaluateSuccess(telemetry: ExecutionTelemetry): { success: boolean; reason: string } {
    if (!this.validateTelemetry(telemetry)) {
      return {
        success: false,
        reason: "Invalid telemetry schema during evaluation."
      }
    }
    if (telemetry.exitCode !== 0) {
      return {
        success: false,
        reason: `Execution failed with exit code ${telemetry.exitCode}: ${telemetry.stderr.trim() || "Unknown error"}`
      }
    }
    if (telemetry.stderr.toLowerCase().includes("error") || telemetry.stderr.toLowerCase().includes("fail")) {
      return {
        success: false,
        reason: `Execution stderr indicated failure: ${telemetry.stderr.trim()}`
      }
    }
    return {
      success: true,
      reason: "Verified zero exit code and clean execution telemetry."
    }
  }
}
