/**
 * @module c2_dwell_scheduler
 * Long-dwell C2 scheduling — periodic beacon tasking over configurable hours.
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { LegitC2Server, InMemoryTransport } from "./c2_platform.ts"
import { runAutonomousC2Pump } from "./c2_autonomous.ts"
import { runEdrFeedbackLoop } from "./edr_feedback_loop.ts"
import { resolveLiveMode } from "./exec_options.ts"

export interface DwellTick {
  tick: number
  timestamp: string
  tasksCompleted: number
  channel: string
}

export interface DwellScheduleResult {
  ticks: DwellTick[]
  dwellHours: number
  totalTasks: number
  edrLoop: Awaited<ReturnType<typeof runEdrFeedbackLoop>>
  summary: string
}

export async function runDwellSchedule(opts: {
  graph: AttackSurfaceGraph
  scopeHosts: string[]
  live?: boolean
  dwellHours?: number
  tickIntervalMs?: number
  maxTicks?: number
}): Promise<DwellScheduleResult> {
  const live = resolveLiveMode(opts)
  const dwellHours = opts.dwellHours ?? 168
  const tickMs = opts.tickIntervalMs ?? 2000
  const maxTicks = opts.maxTicks ?? Math.min(10, Math.ceil(dwellHours / 24))
  const ticks: DwellTick[] = []

  const edrLoop = await runEdrFeedbackLoop({ live, maxIterations: 2 })

  if (!live) {
    return {
      ticks: [],
      dwellHours,
      totalTasks: 0,
      edrLoop,
      summary: `Dwell schedule planned for ${dwellHours}h — live execution required`,
    }
  }

  process.env.OURMINE_AUTONOMOUS_C2 = "1"
  const server = new LegitC2Server({ checkpointPath: ".ourmine/c2/dwell_schedule.jsonl" })
  const beaconId = "dwell-beacon"
  if (!server.sessions.has(beaconId)) {
    server.registerBeacon(beaconId, new InMemoryTransport(), { host: opts.scopeHosts[0] ?? "local", user: "dwell" })
  }

  for (let i = 0; i < maxTicks; i++) {
    const pump = await runAutonomousC2Pump({
      server,
      graph: opts.graph,
      scopeHosts: opts.scopeHosts,
      maxTasksPerPump: 3,
    })
    ticks.push({
      tick: i + 1,
      timestamp: new Date().toISOString(),
      tasksCompleted: pump.tasksCompleted,
      channel: edrLoop.finalChannel,
    })
    if (i < maxTicks - 1) await new Promise((r) => setTimeout(r, tickMs))
  }

  const totalTasks = ticks.reduce((s, t) => s + t.tasksCompleted, 0)
  return {
    ticks,
    dwellHours,
    totalTasks,
    edrLoop,
    summary: `Dwell schedule: ${ticks.length} tick(s), ${totalTasks} task(s) over simulated ${dwellHours}h window`,
  }
}

export default { runDwellSchedule }
