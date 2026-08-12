/**
 * @module engagement_memory
 * Long-engagement memory with blue-team modeling + cross-turn intel/decision cache.
 * Persists under .ourmine/ares/memory/ so agents never re-read the same intel.
 */
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import { ensureAresDir } from "./ares/_base.ts"
import type { EngagementSnapshot as SliceCompactSnapshot } from "./semantic_compression.ts"

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

export interface IntelReadRecord {
  artifactId: string
  snippet: string
  profileId?: string
  readAt: string
}

export interface EngagementDecision {
  key: string
  value: string
  at: string
}

export interface EngagementSnapshotRecord {
  token: string
  snapshot: SliceCompactSnapshot
  at: string
}

export interface EngagementSnapshot {
  target: string
  phase: string
  hostsCompromised: string[]
  credsHarvested: number
  findingsConfirmed: number
  blueTeamEvents: BlueTeamEvent[]
  failedAttempts: FailedAttempt[]
  intelRead: IntelReadRecord[]
  decisions: EngagementDecision[]
  hostRefs: Record<string, string>
  lastSliceSnapshot?: EngagementSnapshotRecord
  updatedAt: string
}

const MEMORY_DIR = ensureAresDir("memory")
const LEGACY_DIR = path.resolve(process.cwd(), ".ourmine/agent")

export class EngagementMemory {
  private filePath: string
  private data: EngagementSnapshot

  constructor(target: string, storageDir = MEMORY_DIR) {
    fs.mkdirSync(storageDir, { recursive: true })
    const safe = target.replace(/[^a-zA-Z0-9._-]/g, "_")
    this.filePath = path.join(storageDir, `engagement_${safe}.json`)
    this.data = this.load() ?? this.migrateLegacy(safe) ?? this.empty(target)
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
      intelRead: [],
      decisions: [],
      hostRefs: {},
      updatedAt: new Date().toISOString(),
    }
  }

  private migrateLegacy(safe: string): EngagementSnapshot | null {
    const legacyPath = path.join(LEGACY_DIR, `engagement_${safe}.json`)
    if (!fs.existsSync(legacyPath)) return null
    try {
      const legacy = JSON.parse(fs.readFileSync(legacyPath, "utf8")) as EngagementSnapshot
      this.data = {
        ...this.empty(legacy.target),
        ...legacy,
        intelRead: legacy.intelRead ?? [],
        decisions: legacy.decisions ?? [],
        hostRefs: legacy.hostRefs ?? {},
      }
      this.save()
      return this.data
    } catch {
      return null
    }
  }

  private load(): EngagementSnapshot | null {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as EngagementSnapshot
        return {
          ...this.empty(raw.target),
          ...raw,
          intelRead: raw.intelRead ?? [],
          decisions: raw.decisions ?? [],
          hostRefs: raw.hostRefs ?? {},
        }
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
      this.registerHostRef(host)
      this.save()
    }
  }

  /** Stable @hN ref for repeated host strings across turns. */
  registerHostRef(host: string): string {
    const key = host.toLowerCase()
    if (this.data.hostRefs[key]) return this.data.hostRefs[key]
    const ref = `@h${Object.keys(this.data.hostRefs).length + 1}`
    this.data.hostRefs[key] = ref
    this.save()
    return ref
  }

  resolveHostRef(ref: string): string | undefined {
    const entry = Object.entries(this.data.hostRefs).find(([, r]) => r === ref)
    return entry?.[0]
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

  /** Mark intel artifact as read — subsequent turns skip re-fetch. */
  markIntelRead(artifactId: string, snippet: string, profileId?: string): void {
    if (this.hasReadIntel(artifactId)) return
    this.data.intelRead.push({
      artifactId,
      snippet: snippet.slice(0, 200),
      profileId,
      readAt: new Date().toISOString(),
    })
    if (this.data.intelRead.length > 100) {
      this.data.intelRead = this.data.intelRead.slice(-100)
    }
    this.save()
  }

  hasReadIntel(artifactId: string): boolean {
    return this.data.intelRead.some((r) => r.artifactId === artifactId)
  }

  getIntelSnippet(artifactId: string): string | undefined {
    return this.data.intelRead.find((r) => r.artifactId === artifactId)?.snippet
  }

  /** Persist cross-turn decisions (phase picks, module skips, policy outcomes). */
  recordDecision(key: string, value: string): void {
    const existing = this.data.decisions.findIndex((d) => d.key === key)
    const entry: EngagementDecision = { key, value: value.slice(0, 300), at: new Date().toISOString() }
    if (existing >= 0) this.data.decisions[existing] = entry
    else this.data.decisions.push(entry)
    if (this.data.decisions.length > 200) {
      this.data.decisions = this.data.decisions.slice(-200)
    }
    this.save()
  }

  getDecision(key: string): string | undefined {
    return this.data.decisions.find((d) => d.key === key)?.value
  }

  /** Store last compact slice snapshot for delta-only continue responses. */
  saveSliceSnapshot(token: string, snapshot: SliceCompactSnapshot): void {
    this.data.lastSliceSnapshot = {
      token,
      snapshot,
      at: new Date().toISOString(),
    }
    this.save()
  }

  getSliceSnapshot(token: string): SliceCompactSnapshot | undefined {
    if (this.data.lastSliceSnapshot?.token === token) {
      return this.data.lastSliceSnapshot.snapshot
    }
    return undefined
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
    return {
      ...this.data,
      blueTeamEvents: [...this.data.blueTeamEvents],
      failedAttempts: [...this.data.failedAttempts],
      hostsCompromised: [...this.data.hostsCompromised],
      intelRead: [...this.data.intelRead],
      decisions: [...this.data.decisions],
      hostRefs: { ...this.data.hostRefs },
    }
  }

  static loadForTarget(target: string, storageDir?: string): EngagementMemory {
    return new EngagementMemory(target, storageDir)
  }

  static memoryDir(): string {
    return MEMORY_DIR
  }
}

export function intelCacheKey(profileId: string, persona: string, objective: string): string {
  const raw = `${profileId}|${persona}|${objective}`
  return crypto.createHash("sha256").update(raw).digest("base64url").slice(0, 16)
}

export default { EngagementMemory, intelCacheKey }
