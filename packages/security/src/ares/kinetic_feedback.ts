/**
 * @file kinetic_feedback.ts
 * @brief ARES v30.0 Kinetic Sovereignty — Failure-Analysis & Feedback Engine
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

  constructor() {
    const dir = path.dirname(this.logPath)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
  }

  public recordExecution(telemetry: ExecutionTelemetry): void {
    let logs: ExecutionTelemetry[] = []
    if (fs.existsSync(this.logPath)) {
      try {
        logs = JSON.parse(fs.readFileSync(this.logPath, "utf8"))
      } catch (e) {
        logs = []
      }
    }
    logs.push(telemetry)
    fs.writeFileSync(this.logPath, JSON.stringify(logs, null, 2))
  }

  public evaluateSuccess(telemetry: ExecutionTelemetry): { success: boolean; reason: string } {
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
