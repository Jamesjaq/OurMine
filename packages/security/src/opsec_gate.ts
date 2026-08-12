/**
 * @module opsec_gate
 * Pre-execution OPSEC gate — review, YARA self-check, pacing, local audit log.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { reviewAction, type OpsecReview } from "./opsec.ts"
import { scanText } from "./yara.ts"
import { OpsecThrottleEngine } from "./opsec_throttle.ts"

const PROFILE_RPM: Record<string, number> = {
  scattered_spider: 15,
  kimsuky: 20,
  akira: 45,
  medusa: 45,
  qilin: 40,
  lockbit5: 40,
  lockbit: 35,
  play: 35,
  ransomhub: 35,
  default: 30,
}

const throttleByProfile = new Map<string, OpsecThrottleEngine>()

function throttleFor(profile?: string): OpsecThrottleEngine {
  const key = profile ?? "default"
  if (!throttleByProfile.has(key)) {
    throttleByProfile.set(
      key,
      new OpsecThrottleEngine({ maxRequestsPerMinute: PROFILE_RPM[key] ?? PROFILE_RPM.default }),
    )
  }
  return throttleByProfile.get(key)!
}

function opsecLogDir(): string {
  const dir = path.join(process.cwd(), ".ourmine", "opsec")
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function appendOpsecLog(entry: Record<string, unknown>): void {
  try {
    const file = path.join(opsecLogDir(), `review_${new Date().toISOString().slice(0, 10)}.jsonl`)
    fs.appendFileSync(file, JSON.stringify({ ...entry, ts: new Date().toISOString() }) + "\n")
  } catch {
    /* local-only audit — never fail execution on log errors */
  }
}

export interface GateResult {
  allowed: boolean
  review: OpsecReview
  mitigatedCommand?: string
  yaraHits: string[]
}

export async function gateExecution(opts: {
  tool: string
  command: string
  profile?: string
  force?: boolean
  live?: boolean
}): Promise<GateResult> {
  const review = reviewAction({
    action_id: `${opts.tool}_${Date.now()}`,
    tool: opts.tool,
    command: opts.command,
  })

  const yaraMatches = scanText(opts.command)
  const yaraHits = yaraMatches.map((m) => m.rule)

  if (opts.live !== false) {
    await throttleFor(opts.profile).paceExecution()
  }

  let allowed = review.safe_to_run
  if (review.signature_risk === "high" && !opts.force) {
    allowed = false
  }

  appendOpsecLog({
    tool: opts.tool,
    profile: opts.profile,
    command: opts.command.slice(0, 500),
    allowed,
    signature_risk: review.signature_risk,
    yaraHits,
    mitigations: review.mitigations,
  })

  return {
    allowed: opts.force ? true : allowed,
    review,
    mitigatedCommand: opts.command,
    yaraHits,
  }
}

export default { gateExecution }
