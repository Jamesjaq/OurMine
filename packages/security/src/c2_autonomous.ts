/**
 * @module c2_autonomous
 * Scope-gated C2 closed loop — beacon register → task → result → graph update without per-task HITL.
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { LegitC2Server, type C2Task, type BeaconSession } from "./c2_platform.ts"

export interface C2AutonomousOpts {
  server: LegitC2Server
  graph: AttackSurfaceGraph
  scopeHosts: string[]
  maxTasksPerPump?: number
  requireEnvFlag?: boolean
}

export interface C2AutonomousPumpResult {
  beaconsActive: number
  tasksQueued: number
  tasksCompleted: number
  graphUpdates: string[]
  denied: string[]
  summary: string
}

export function isAutonomousC2Enabled(): boolean {
  return process.env.OURMINE_AUTONOMOUS_C2 === "1"
    || process.env.OURMINE_AUTONOMOUS_C2 === "true"
    || process.env.OURMINE_AUTONOMOUS === "1"
    || process.env.OURMINE_TIER1 === "1"
    || process.env.OURMINE_TIER1 === "true"
}

function hostInScope(host: string, scope: string[]): boolean {
  const h = host.toLowerCase()
  return scope.some((s) => h === s.toLowerCase() || h.includes(s.toLowerCase()))
}

export async function queueAutonomousTask(
  server: LegitC2Server,
  beaconId: string,
  command: string,
  scopeHosts: string[],
  session?: BeaconSession,
): Promise<C2Task | { denied: true; reason: string }> {
  const sess = session ?? server.sessions.get(beaconId)
  if (!sess) return { denied: true, reason: "unknown beacon" }
  if (!hostInScope(sess.host || "", scopeHosts)) {
    return { denied: true, reason: `beacon host ${sess.host} out of scope` }
  }
  if (!isAutonomousC2Enabled()) {
    return { denied: true, reason: "Set OURMINE_AUTONOMOUS_C2=1 for scope-gated autonomous tasking" }
  }
  const result = server.queueTask(beaconId, command, { requireApproval: false })
  if (result.error) return { denied: true, reason: String(result.error) }
  const taskId = String(result.task_id ?? "")
  const task = [...server.tasks.values()].find((t) => t.task_id === taskId)
  return task ?? { denied: true, reason: "task not created" }
}

export async function runAutonomousC2Pump(opts: C2AutonomousOpts): Promise<C2AutonomousPumpResult> {
  const { server, graph, scopeHosts } = opts
  const graphUpdates: string[] = []
  const denied: string[] = []
  let tasksQueued = 0
  let tasksCompleted = 0

  if (!isAutonomousC2Enabled()) {
    return {
      beaconsActive: server.sessions.size,
      tasksQueued: 0,
      tasksCompleted: 0,
      graphUpdates: [],
      denied: ["OURMINE_AUTONOMOUS_C2 not set"],
      summary: "Autonomous C2 disabled",
    }
  }

  for (const [id, session] of server.sessions) {
    if (session.status !== "active") continue
    if (!hostInScope(session.host, scopeHosts)) {
      denied.push(id)
      continue
    }
    const task = await queueAutonomousTask(server, id, "whoami && hostname", scopeHosts, session)
    if ("denied" in task) {
      denied.push(task.reason)
    } else {
      tasksQueued++
    }
  }

  const pumpResult = await server.pump()
  for (const t of server.tasks.values()) {
    if (t.status === "completed") {
      tasksCompleted++
      const sess = server.sessions.get(t.beacon_id)
      const host = sess?.host ?? "unknown"
      graph.upsertAsset(host)
      const note = `[C2] task ${t.task_id} completed on ${host}: ${t.result.slice(0, 120)}`
      graphUpdates.push(note)
      const asset = graph.upsertAsset(host)
      asset.notes.push(note)
    }
  }

  return {
    beaconsActive: [...server.sessions.values()].filter((s) => s.status === "active").length,
    tasksQueued,
    tasksCompleted,
    graphUpdates,
    denied,
    summary: `C2 pump: ${tasksCompleted} completed, ${tasksQueued} queued, ${denied.length} denied`,
    ...(pumpResult ? {} : {}),
  }
}

export default { isAutonomousC2Enabled, queueAutonomousTask, runAutonomousC2Pump }
