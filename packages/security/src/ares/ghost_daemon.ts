/**
 * @module ares/ghost_daemon
 * ARES v5.0 'Ghost-in-the-Wire' Autonomous Mission Daemon.
 * Enables proactive target discovery, autonomous mission triggering,
 * and continuous strategic evolution without human intervention.
 */
import { runAresOrchestrator } from "./orchestrator.ts"
import { ResearchIngestor } from "./research_ingestor.ts"
import { SelfImprovementEngine } from "./self_improvement.ts"
import * as fs from "node:fs"
import * as path from "node:path"

export class GhostDaemon {
  private active: boolean = false
  private ingestor: ResearchIngestor
  private evolution: SelfImprovementEngine
  private logPath: string

  constructor() {
    this.ingestor = new ResearchIngestor()
    this.evolution = new SelfImprovementEngine()
    this.logPath = path.join(process.cwd(), ".ourmine", "logs", "ghost_daemon.log")
    
    const logDir = path.dirname(this.logPath)
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true })
    }
  }

  private log(msg: string) {
    const entry = `[${new Date().toISOString()}] [GHOST_DAEMON] ${msg}\n`
    fs.appendFileSync(this.logPath, entry, "utf8")
    console.log(entry.trim())
  }

  /**
   * Proactively scans the environment and live intelligence for mission opportunities.
   */
  public async scanForOpportunities(): Promise<{ target: string; objective: string }[]> {
    this.log("Scanning live intelligence for strategic opportunities...")
    const intel = await this.ingestor.fetchLatestIntelligence()
    
    // Logic to identify high-value targets from intel or local network
    // For now, we prioritize targets with critical zero-days
    return intel
      .filter(i => i.cveId.includes("2026"))
      .map(i => ({
        target: i.vectorHeuristic,
        objective: `Autonomous exploitation of ${i.cveId} to establish persistent C2.`
      }))
  }

  /**
   * Starts the autonomous mission loop.
   */
  public async startSovereignLoop() {
    if (this.active) return
    this.active = true
    this.log("ARES v5.0 Ghost-in-the-Wire Protocol initiated. Entering Sovereign Loop.")

    while (this.active) {
      try {
        const opportunities = await this.scanForOpportunities()
        
        for (const opp of opportunities) {
          this.log(`Initiating autonomous mission against ${opp.target}: ${opp.objective}`)
          
          const result = await runAresOrchestrator({
            live: true,
            target: opp.target,
            objective: opp.objective,
            headlessMode: true
          })

          this.log(`Mission ${result.mission.missionId} complete. Succeeded: ${result.succeeded}/${result.total}`)
          
          // Briefing generation (Strategic Summary)
          const briefing = `
### SUPREME COMMANDER BRIEFING: MISSION ${result.mission.missionId}
**Target:** ${opp.target}
**Objective:** ${opp.objective}
**Strategic Reasoning:**
${result.reasoningLog.map(r => `- ${r.step}: ${r.rationale} (Intent: ${r.adversarialIntent})`).join("\n")}

**Outcome:** ${result.summary}
**Evolution:** System battle-hardened with ${result.findings.length} new findings.
          `
          this.log(briefing)
        }

        // Wait for next cycle (e.g., 1 hour)
        this.log("Sovereign cycle complete. Sleeping for 3600s.")
        await new Promise(resolve => setTimeout(resolve, 3600000))
      } catch (err) {
        this.log(`CRITICAL ERROR in Sovereign Loop: ${err}`)
        await new Promise(resolve => setTimeout(resolve, 60000)) // Wait 1m on error
      }
    }
  }

  public stop() {
    this.active = false
    this.log("Ghost-in-the-Wire Protocol deactivated.")
  }
}

export async function runGhostDaemon() {
  const daemon = new GhostDaemon()
  await daemon.startSovereignLoop()
}

export default { GhostDaemon, runGhostDaemon }
