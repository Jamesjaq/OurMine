/**
 * @module self_healing
 * ARES Self-Healing Engine — ensures C2 resilience and autonomous agent recovery.
 */
import { CovertC2Engine } from "../covert_c2.ts"

export interface AgentHealth {
  agentId: string
  lastCheckin: string
  status: "active" | "degraded" | "lost"
  currentChannel: string
}

export class SelfHealingEngine {
  private agents = new Map<string, AgentHealth>()
  private channelHistory = new Map<string, string[]>() // agentId -> channel names
  private c2Engine: CovertC2Engine

  constructor(c2Engine: CovertC2Engine) {
    this.c2Engine = c2Engine
  }

  /** Record a check-in and update agent health status. */
  registerCheckin(agentId: string, channelName: string): void {
    this.agents.set(agentId, {
      agentId,
      lastCheckin: new Date().toISOString(),
      status: "active",
      currentChannel: channelName
    })
    
    const history = this.channelHistory.get(agentId) ?? []
    if (!history.includes(channelName)) {
      history.push(channelName)
      this.channelHistory.set(agentId, history)
    }
  }

  /** Identify agents that have missed their heartbeat and need recovery. */
  findLostAgents(timeoutMinutes = 10): AgentHealth[] {
    const now = Date.now()
    const lost: AgentHealth[] = []
    
    for (const agent of this.agents.values()) {
      const last = new Date(agent.lastCheckin).getTime()
      if (now - last > timeoutMinutes * 60 * 1000) {
        agent.status = "lost"
        lost.push(agent)
      }
    }
    
    return lost
  }

  /** 
   * Suggest a C2 channel rotation for a lost agent. 
   * Cycles through available covert channels to re-establish connectivity.
   */
  suggestRecoveryChannel(agentId: string): string | null {
    const agent = this.agents.get(agentId)
    if (!agent) return null

    const allChannels = this.c2Engine.listChannels().map(c => c.name as string)
    const history = this.channelHistory.get(agentId) ?? []
    
    // Pick the first available channel that isn't the current failed one
    const nextChannel = allChannels.find(c => c !== agent.currentChannel)
    return nextChannel ?? allChannels[0] ?? null
  }

  /** Generate a "Self-Healing" plan for a campaign. */
  generateResiliencePlan(agentIds: string[]): Record<string, string> {
    const plan: Record<string, string> = {}
    for (const id of agentIds) {
      const recovery = this.suggestRecoveryChannel(id)
      if (recovery) plan[id] = `Rotate to ${recovery} if heartbeat > 5m`
    }
    return plan
  }
}

export default SelfHealingEngine

import { moduleEnvelope } from "../module_helpers.ts"

export async function runSelfHealing(
  req: { agentIds?: string[]; checkin?: { agentId: string; channel: string } },
  opts: { live?: boolean } = {},
) {
  const live = opts.live === true
  const c2 = new CovertC2Engine()
  const engine = new SelfHealingEngine(c2)
  
  if (req.checkin) {
    engine.registerCheckin(req.checkin.agentId, req.checkin.channel)
  }
  
  const lost = engine.findLostAgents()
  const plan = engine.generateResiliencePlan(req.agentIds ?? [])
  
  return moduleEnvelope(live, {
    lostAgents: lost,
    resiliencePlan: plan,
    summary: `Self-healing engine monitored ${req.agentIds?.length ?? 0} agents, found ${lost.length} lost, generated recovery plan.`,
  })
}
