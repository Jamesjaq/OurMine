/**
 * @module telemetry_receiver
 * Campaign telemetry receiver for phishing clicks and credential capture submissions.
 */
import * as fs from "node:fs"
import * as path from "node:path"

export interface TelemetryEvent {
  campaignId: string
  eventType: "click" | "credential" | "pixel"
  username?: string
  password?: string
  ip?: string
  userAgent?: string
  timestamp: string
}

const EVENTS_LOG_PATH = path.join(process.cwd(), "campaigns", "telemetry_events.jsonl")

export function recordTelemetryEvent(event: Omit<TelemetryEvent, "timestamp">): TelemetryEvent {
  const fullEvent: TelemetryEvent = {
    ...event,
    timestamp: new Date().toISOString()
  }
  try {
    fs.mkdirSync(path.dirname(EVENTS_LOG_PATH), { recursive: true })
    fs.appendFileSync(EVENTS_LOG_PATH, JSON.stringify(fullEvent) + "\n")
  } catch {
    // ignore filesystem write errors
  }
  return fullEvent
}

export function getTelemetryEvents(campaignId?: string): TelemetryEvent[] {
  try {
    if (!fs.existsSync(EVENTS_LOG_PATH)) return []
    const lines = fs.readFileSync(EVENTS_LOG_PATH, "utf8").split("\n").filter(Boolean)
    const events = lines.map((l) => JSON.parse(l) as TelemetryEvent)
    if (campaignId) {
      return events.filter((e) => e.campaignId === campaignId)
    }
    return events
  } catch {
    return []
  }
}

export default { recordTelemetryEvent, getTelemetryEvents }
