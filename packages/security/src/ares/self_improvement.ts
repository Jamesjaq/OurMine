/**
 * @module ares/self_improvement
 * ARES v3.4 Self-Evolution Engine — Persistent tradecraft ingestion and validation.
 */
import { moduleEnvelope, executeLiveCommand } from "../module_helpers.ts"
import * as fs from "node:fs"
import * as path from "node:path"

export interface ValidationRecord {
  techniqueId: string
  proven: boolean
  confidenceScore: number
  validationTimestamp: string
  artifactPath?: string
  executionOutput?: string
}

export class SelfImprovementEngine {
  private storageDir: string
  private libraryPath: string
  private repoRoot: string

  constructor() {
    // ARES v5.0: Dynamically resolve repo root for Singularity Protocol
    this.repoRoot = process.cwd().includes("AuditOurMine") ? "/home/ubuntu/AuditOurMine" : "/home/ubuntu/OurMine"
    this.storageDir = path.join(this.repoRoot, ".ourmine", "tradecraft")
    this.libraryPath = path.join(this.storageDir, "library.json")
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true })
    }
  }

  private loadLibrary(): Record<string, ValidationRecord> {
    if (!fs.existsSync(this.libraryPath)) return {}
    try {
      const content = fs.readFileSync(this.libraryPath, "utf8").trim()
      if (!content) return {}
      return JSON.parse(content) as Record<string, ValidationRecord>
    } catch {
      return {}
    }
  }

  private saveToLibrary(record: ValidationRecord): void {
    const library = this.loadLibrary()
    library[record.techniqueId] = record
    fs.writeFileSync(this.libraryPath, JSON.stringify(library, null, 2) + "\n", "utf8")
  }

  public async validateAndIngestLive(techniqueId: string, payloadCode: string, testCommand: string): Promise<ValidationRecord> {
    // Execute live verification command against target environment
    const execRes = executeLiveCommand(testCommand)
    const proven = execRes.code === 0
    const confidence = proven ? 99.4 : 10.0
    
    const techLower = techniqueId.toLowerCase().replace(/[^a-z0-9]/g, '_')
    const artifactPath = path.join(this.repoRoot, "packages/security/src/ares", `custom_${techLower}.ts`)

    const record: ValidationRecord = {
      techniqueId,
      proven,
      confidenceScore: confidence,
      validationTimestamp: new Date().toISOString(),
      artifactPath: proven ? artifactPath : undefined,
      executionOutput: execRes.stdout || execRes.stderr,
    }

    if (proven) {
      try {
        const dir = path.dirname(artifactPath)
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true })
        }
        fs.writeFileSync(artifactPath, payloadCode, "utf8")
        this.mutateRegistry(techniqueId)
        this.saveToLibrary(record)
      } catch (err) {
        console.error(`[Self-Evolution] Failed to ingest technique: ${err}`)
      }
    }

    return record
  }

  private mutateRegistry(techniqueId: string): void {
    try {
      const indexPath = path.join(this.repoRoot, "packages/security/src/ares/index.ts")
      if (!fs.existsSync(indexPath)) return

      let content = fs.readFileSync(indexPath, "utf8")
      const techLower = techniqueId.toLowerCase().replace(/[^a-z0-9]/g, '_')
      const cleanId = techLower.replace(/[^a-z0-9_]/g, "_")
      const camelId = cleanId.split("_").map(s => s.charAt(0).toUpperCase() + s.slice(1)).join("")
      const runName = `run${camelId}`
      const moduleName = `ares_custom_${techLower}`

      // ARES v5.0: Robust Dynamic Registry Mutation
      const exportLine = `export { ${runName} } from "./custom_${techLower}.ts"`
      if (!content.includes(exportLine)) {
        // Append to the end of exports
        const lines = content.split("\n")
        const lastExportIndex = lines.findLastIndex(l => l.startsWith("export {") && l.includes('from "./'))
        if (lastExportIndex !== -1) {
          lines.splice(lastExportIndex + 1, 0, exportLine)
          content = lines.join("\n")
        }
      }

      // Check if already in ARES_MODULE_NAMES
      const registryEntry = `  "${moduleName}",`
      if (!content.includes(registryEntry)) {
        content = content.replace(
          /const ARES_MODULE_NAMES = \[/,
          `const ARES_MODULE_NAMES = [\n${registryEntry}`
        )
      }

      fs.writeFileSync(indexPath, content, "utf8")
    } catch (err) {
      console.error(`[Self-Evolution] Registry mutation failed: ${err}`)
    }
  }

  public getTradecraftStats(): { total: number; proven: number } {
    const library = this.loadLibrary()
    const records = Object.values(library)
    return {
      total: records.length,
      proven: records.filter(r => r.proven).length
    }
  }
}

export async function runSelfImprovement(
  req: { techniqueId?: string; payloadCode?: string; testCommand?: string },
  opts: { live?: boolean } = {},
) {
  const live = opts.live === true
  if (!live) throw new Error("[SelfImprovement] CRITICAL: Active-Only Protocol enforced. Simulation mode disabled.")
  const engine = new SelfImprovementEngine()
  
  if (!req.techniqueId || !req.payloadCode || !req.testCommand) {
    throw new Error("[SelfImprovement] CRITICAL: Missing real tradecraft parameters. Active-Only Protocol prohibits default stubs.")
  }

  const techId = req.techniqueId
  const code = req.payloadCode
  const cmd = req.testCommand

  const record = await engine.validateAndIngestLive(techId, code, cmd)
  const stats = engine.getTradecraftStats()

  return moduleEnvelope(live, {
    validation: {
      id: record.techniqueId,
      ok: record.proven,
      conf: record.confidenceScore,
      path: record.artifactPath
    },
    tradecraftLibrary: {
      totalTechniques: stats.total,
      provenTechniques: stats.proven
    },
    summary: `Live self-evolution complete: technique ${techId} proven=${record.proven}, confidence=${record.confidenceScore}%. Tradecraft library now contains ${stats.proven} proven techniques.`,
  })
}

export default { SelfImprovementEngine, runSelfImprovement }
