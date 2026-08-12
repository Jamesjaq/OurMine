/**
 * @module mcp_artifacts
 * Artifact indirection for large MCP tool payloads — full detail under .ourmine/ares/artifacts/.
 */
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import { ensureAresDir } from "./ares/_base.ts"

const ARTIFACT_DIR = ensureAresDir("artifacts")

export interface StoredArtifact {
  kind: string
  id: string
  writtenAt: string
  payload: unknown
}

export function writeArtifact(kind: string, payload: unknown): string {
  const id = `${kind}_${Date.now().toString(36)}_${crypto.randomBytes(4).toString("hex")}`
  const fp = path.join(ARTIFACT_DIR, `${id}.json`)
  const record: StoredArtifact = {
    kind,
    id,
    writtenAt: new Date().toISOString(),
    payload,
  }
  fs.writeFileSync(fp, JSON.stringify(record, null, 2))
  return id
}

export function readArtifact(id: string): unknown | null {
  const safe = id.replace(/[^a-zA-Z0-9_-]/g, "")
  if (!safe) return null
  const fp = path.join(ARTIFACT_DIR, `${safe}.json`)
  if (!fs.existsSync(fp)) return null
  try {
    const data = JSON.parse(fs.readFileSync(fp, "utf8")) as StoredArtifact
    return data.payload ?? data
  } catch {
    return null
  }
}

const LARGE_ARRAY_KEYS = ["steps", "otHosts", "progressLog", "modules", "phases", "results", "findings", "confirmed", "candidates", "planNextActions", "graphNextActions"] as const

/** True when payload should be stored as artifact instead of inlined in MCP text. */
export function shouldStoreAsArtifact(payload: Record<string, unknown>, maxLen = 1200): boolean {
  for (const key of LARGE_ARRAY_KEYS) {
    const arr = payload[key]
    if (Array.isArray(arr) && arr.length > 6) return true
  }
  const serialized = JSON.stringify(payload)
  return serialized.length > maxLen
}

/** Compact preview for artifact-indirected responses. */
export function artifactPreview(payload: Record<string, unknown>): Record<string, unknown> {
  const preview: Record<string, unknown> = {}
  if (typeof payload.summary === "string") preview.summary = payload.summary.slice(0, 300)
  if (payload.dryRun != null) preview.dryRun = payload.dryRun
  if (payload.success != null) preview.success = payload.success
  if (payload.phase) preview.phase = payload.phase
  if (payload.target) preview.target = payload.target
  if (payload.objective) preview.objective = payload.objective
  if (typeof payload.succeeded === "number") preview.succeeded = payload.succeeded
  if (Array.isArray(payload.steps)) preview.stepCount = payload.steps.length
  if (Array.isArray(payload.otHosts)) preview.otHostCount = payload.otHosts.length
  if (Array.isArray(payload.progressLog)) preview.progressLines = payload.progressLog.length
  return preview
}

export default { writeArtifact, readArtifact, shouldStoreAsArtifact, artifactPreview }
