/**
 * @module engagement_memory
 * Long-engagement memory with blue-team response modeling across sessions.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

export interface BlueTeamEvent {
  timestamp: string
  type: "lockout" | "edr_alert" | "ip_block" | "canary_trip" | "rate_limit" | "unknown"
  detail: string
  host?: string
}

export interface FailedAttempt {
  tool: string
  target: string
  reason: string
  timestamp: string
}

export interface EngagementSnapshot {
  target: string
  phase: string
  hostsCompromised: string[]
  credsHarvested: number
  findingsConfirmed: number
  blueTeamEvents: BlueTeamEvent[]
  failedAttempts: FailedAttempt[]
  updatedAt: string
}

const DEFAULT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../.ourmine/agent")

export class EngagementMemory {
  private filePath: string
  private data: EngagementSnapshot

  constructor(target: string, storageDir = DEFAULT_DIR) {
    fs.mkdirSync(storageDir, { recursive: true })
    const safe = target.replace(/[^a-zA-Z0-9._-]/g, "_")
    this.filePath = path.join(storageDir, `engagement_${safe}.json`)
    this.data = this.load() ?? this.empty(target)
  }

  private empty(target: string): EngagementSnapshot {
    return {
      target,
      phase: "recon",
      hostsCompromised: [],
      credsHarvested: 0,
      findingsConfirmed: 0,
      blueTeamEvents: [],
      failedAttempts: [],
      updatedAt: new Date().toISOString(),
    }
  }

  private load(): EngagementSnapshot | null {
    try {
      if (fs.existsSync(this.filePath)) {
        return JSON.parse(fs.readFileSync(this.filePath, "utf8")) as EngagementSnapshot
      }
    } catch { /* corrupt */ }
    return null
  }

  save(): void {
    this.data.updatedAt = new Date().toISOString()
    fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2))
  }

  setPhase(phase: string): void {
    this.data.phase = phase
    this.save()
  }

  recordHost(host: string): void {
    if (!this.data.hostsCompromised.includes(host)) {
      this.data.hostsCompromised.push(host)
      this.save()
    }
  }

  recordCredHarvest(count = 1): void {
    this.data.credsHarvested += count
    this.save()
  }

  recordConfirmedFinding(): void {
    this.data.findingsConfirmed += 1
    this.save()
  }

  recordFailedAttempt(tool: string, target: string, reason: string): void {
    this.data.failedAttempts.push({
      tool,
      target,
      reason: reason.slice(0, 200),
      timestamp: new Date().toISOString(),
    })
    if (this.data.failedAttempts.length > 500) {
      this.data.failedAttempts = this.data.failedAttempts.slice(-500)
    }
    this.detectBlueTeamResponse(reason)
    this.save()
  }

  recordBlueTeamEvent(event: Omit<BlueTeamEvent, "timestamp">): void {
    this.data.blueTeamEvents.push({ ...event, timestamp: new Date().toISOString() })
    if (this.data.blueTeamEvents.length > 200) {
      this.data.blueTeamEvents = this.data.blueTeamEvents.slice(-200)
    }
    this.save()
  }

  private detectBlueTeamResponse(reason: string): void {
    const r = reason.toLowerCase()
    if (/lockout|locked|too many attempts/.test(r)) {
      this.recordBlueTeamEvent({ type: "lockout", detail: reason })
    } else if (/blocked|forbidden|403|429/.test(r)) {
      this.recordBlueTeamEvent({ type: "ip_block", detail: reason })
    } else if (/rate limit|throttl/.test(r)) {
      this.recordBlueTeamEvent({ type: "rate_limit", detail: reason })
    } else if (/edr|defender|crowdstrike|sentinel/.test(r)) {
      this.recordBlueTeamEvent({ type: "edr_alert", detail: reason })
    } else if (/canary|honey/.test(r)) {
      this.recordBlueTeamEvent({ type: "canary_trip", detail: reason })
    }
  }

  shouldThrottleTool(tool: string): { throttle: boolean; reason?: string } {
    const recent = this.data.failedAttempts.filter((f) => f.tool === tool).slice(-5)
    if (recent.length >= 3 && recent.every((f) => /lockout|blocked|rate/.test(f.reason.toLowerCase()))) {
      return { throttle: true, reason: `Tool ${tool} triggered blue-team response — backoff recommended` }
    }
    const lockouts = this.data.blueTeamEvents.filter((e) => e.type === "lockout").slice(-1)
    if (lockouts.length && ["cred_spray", "lateral_move"].includes(tool)) {
      return { throttle: true, reason: "Recent account lockout — delay credential attacks" }
    }
    return { throttle: false }
  }

  getAdaptiveDelayMs(tool: string): number {
    const check = this.shouldThrottleTool(tool)
    if (!check.throttle) return 0
    const events = this.data.blueTeamEvents.length
    return Math.min(300_000, 5_000 * (events + 1))
  }

  snapshot(): EngagementSnapshot {
    return { ...this.data, blueTeamEvents: [...this.data.blueTeamEvents], failedAttempts: [...this.data.failedAttempts], hostsCompromised: [...this.data.hostsCompromised] }
  }

  static loadForTarget(target: string, storageDir?: string): EngagementMemory {
    return new EngagementMemory(target, storageDir)
  }
}

export default { EngagementMemory }
