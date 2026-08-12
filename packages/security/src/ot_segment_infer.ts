/**
 * @module ot_segment_infer
 * Infer OT plant subnets from IT recon, cred graph, and env — no manual plant_subnet required.
 */
import type { CredentialGraph } from "./credential_graph.ts"
import type { PhaseStepResult } from "./ares/phase_runner.ts"

const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/

function ipToSlash24(ip: string): string | null {
  const m = ip.match(/^(\d+\.\d+\.\d+)\.\d+$/)
  return m ? `${m[1]}.0/24` : null
}

function extractIpsFromText(text: string): string[] {
  const found = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []
  return [...new Set(found.filter((ip) => PRIVATE.test(ip)))]
}

export function inferPlantSubnets(opts: {
  target: string
  reconSteps?: PhaseStepResult[]
  credGraph?: CredentialGraph
  itHost?: string
}): string[] {
  const subnets = new Set<string>()
  const env = process.env.OURMINE_OT_SUBNETS
  if (env) {
    for (const s of env.split(",").map((x) => x.trim()).filter(Boolean)) {
      subnets.add(s.includes("/") ? s : `${s}/24`)
    }
  }

  const anchor = opts.itHost ?? opts.target.replace(/\/.*$/, "")
  const anchorSlash = ipToSlash24(anchor)
  if (anchorSlash && PRIVATE.test(anchor)) subnets.add(anchorSlash)

  for (const step of opts.reconSteps ?? []) {
    for (const ip of extractIpsFromText(step.summary)) {
      const s = ipToSlash24(ip)
      if (s) subnets.add(s)
    }
  }

  if (opts.credGraph) {
    for (const s of opts.credGraph.inferOtSubnets()) subnets.add(s)
    for (const h of opts.credGraph.discoveredHosts()) {
      const s = ipToSlash24(h)
      if (s && PRIVATE.test(h)) subnets.add(s)
    }
  }

  const otVlan = process.env.OURMINE_OT_VLAN
  if (otVlan && /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(otVlan)) subnets.add(otVlan)

  if (subnets.size === 0 && PRIVATE.test(anchor)) {
    subnets.add(`${anchor.split(".").slice(0, 3).join(".")}.0/24`)
  }

  return [...subnets].slice(0, 8)
}

export default { inferPlantSubnets }
