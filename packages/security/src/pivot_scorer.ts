/**
 * @module pivot_scorer
 * Cross-segment OT pivot scoring from cred graph + recon evidence.
 */
import type { CredentialGraph } from "./credential_graph.ts"
import type { PhaseStepResult } from "./ares/phase_runner.ts"

export interface SubnetScore {
  subnet: string
  confidence: number
  reason: string
}

const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/

function extractPrivateIps(text: string): string[] {
  return [...new Set((text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []).filter((ip) => PRIVATE.test(ip)))]
}

function ipToSlash24(ip: string): string | null {
  const m = ip.match(/^(\d+\.\d+\.\d+)\.\d+$/)
  return m ? `${m[1]}.0/24` : null
}

/** Score plant subnets for IT→OT pivot priority (higher = sweep first). */
export function scoreOtSubnets(
  subnets: string[],
  credGraph?: CredentialGraph,
  reconSteps?: PhaseStepResult[],
): SubnetScore[] {
  const scores = new Map<string, { confidence: number; reasons: string[] }>()

  const bump = (subnet: string, delta: number, reason: string) => {
    const cur = scores.get(subnet) ?? { confidence: 0, reasons: [] }
    cur.confidence += delta
    if (!cur.reasons.includes(reason)) cur.reasons.push(reason)
    scores.set(subnet, cur)
  }

  for (const subnet of subnets) {
    bump(subnet.includes("/") ? subnet : `${subnet}/24`, 0.1, "explicit subnet candidate")
  }

  if (credGraph) {
    for (const s of credGraph.inferOtSubnets()) bump(s, 0.45, "cred-graph private host on adjacent /24")
    for (const h of credGraph.discoveredHosts()) {
      const s = ipToSlash24(h)
      if (s) bump(s, 0.35, `cred-graph host ${h}`)
    }
    for (const p of credGraph.toJSON().pivots ?? []) {
      if (p.success && PRIVATE.test(p.to)) {
        const s = ipToSlash24(p.to)
        if (s) bump(s, 0.5, `successful pivot to ${p.to}`)
      }
    }
  }

  for (const step of reconSteps ?? []) {
    const text = `${step.module} ${step.summary}`
    if (/modbus|502|scada|plc|dnp3|bacnet|ics|ot/i.test(text)) {
      for (const ip of extractPrivateIps(text)) {
        const s = ipToSlash24(ip)
        if (s) bump(s, 0.4, `recon OT signal in ${step.module}`)
      }
    }
    for (const ip of extractPrivateIps(text)) {
      const s = ipToSlash24(ip)
      if (s) bump(s, 0.15, `recon private IP in ${step.module}`)
    }
  }

  const env = process.env.OURMINE_OT_SUBNETS
  if (env) {
    for (const s of env.split(",").map((x) => x.trim()).filter(Boolean)) {
      bump(s.includes("/") ? s : `${s}/24`, 0.6, "OURMINE_OT_SUBNETS env")
    }
  }

  return [...scores.entries()]
    .map(([subnet, { confidence, reasons }]) => ({
      subnet,
      confidence: Math.min(1, Math.round(confidence * 100) / 100),
      reason: reasons.slice(0, 3).join("; "),
    }))
    .sort((a, b) => b.confidence - a.confidence)
}

export default { scoreOtSubnets }
