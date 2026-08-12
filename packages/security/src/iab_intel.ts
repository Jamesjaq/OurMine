/**
 * @module iab_intel
 * Initial Access Broker market schema — stealer-log → VPN/RDP handoff patterns.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import { writeArtifact } from "./mcp_artifacts.ts"

const INTEL_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel",
)

export interface IabChainStage {
  id: string
  name: string
  priceRangeUsd?: number[]
  sources?: string[]
  artifacts?: string[]
  indicators?: string[]
}

export interface StealerPattern {
  id: string
  stealerArtifact: string
  targetService: string
  techniques: string[]
  modules: string[]
}

export interface IabBroker {
  id: string
  type: string
  pairedActor?: string
  focus: string[]
}

export interface IabMarketSchema {
  schemaVersion: number
  chainStages: IabChainStage[]
  stealerToAccessPatterns: StealerPattern[]
  iabBrokers: IabBroker[]
}

function readJson<T>(file: string, fallback: T): T {
  try {
    return JSON.parse(fs.readFileSync(path.join(INTEL_DIR, file), "utf8")) as T
  } catch {
    return fallback
  }
}

export function loadIabMarket(): IabMarketSchema {
  return readJson<IabMarketSchema>("iab_market.json", {
    schemaVersion: 0,
    chainStages: [],
    stealerToAccessPatterns: [],
    iabBrokers: [],
  })
}

export function matchStealerPattern(artifacts: string[]): StealerPattern[] {
  const market = loadIabMarket()
  const q = artifacts.map((a) => a.toLowerCase())
  return market.stealerToAccessPatterns.filter((p) => {
    const art = p.stealerArtifact.toLowerCase()
    return q.some((a) => a.includes(art) || art.includes(a))
  })
}

export function iabHandoffPlaybook(brokerId: string): {
  broker: IabBroker | null
  modules: string[]
  pairedActor?: string
  artifactId?: string
} {
  const market = loadIabMarket()
  const broker = market.iabBrokers.find((b) => b.id === brokerId) ?? null
  const modules = broker?.type === "ot_iab"
    ? ["edge_audit", "ot_batch_scan", "hybrid_pivot", "iot_scada"]
    : ["edge_audit", "cred_access_auto", "rmm_audit", "citrix_audit"]

  const payload = { brokerId, broker, modules, pairedActor: broker?.pairedActor }
  const artifactId = writeArtifact("iab_handoff", payload)

  return {
    broker,
    modules,
    pairedActor: broker?.pairedActor,
    artifactId,
  }
}

export function iabModulesForHint(hint: string): string[] {
  const h = hint.toLowerCase()
  const patterns = loadIabMarket().stealerToAccessPatterns
  const mods = new Set<string>()
  for (const p of patterns) {
    if (h.includes(p.stealerArtifact.replace(/_/g, " "))
      || h.includes(p.targetService)
      || (h.includes("stealer") && h.includes("vpn"))
      || (h.includes("cookie") && h.includes("vpn"))) {
      for (const m of p.modules) mods.add(m)
    }
  }
  return [...mods]
}

export default {
  loadIabMarket,
  matchStealerPattern,
  iabHandoffPlaybook,
  iabModulesForHint,
}
