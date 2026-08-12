/**
 * @module iab_handoff_sim
 * Staged IAB chain simulation — stealer log → VPN session → RaaS deploy evidence.
 */
import type { CredentialGraph } from "./credential_graph.ts"
import { matchStealerPattern, loadIabMarket, type StealerPattern } from "./iab_intel.ts"
import { writeArtifact } from "./mcp_artifacts.ts"

export interface IabStageEvidence {
  stage: "stealer_log" | "vpn_session" | "raas_deploy"
  artifacts: string[]
  techniques: string[]
  modules: string[]
  synthetic: boolean
}

export interface IabHandoffResult {
  target: string
  stages: IabStageEvidence[]
  patternIds: string[]
  artifactId: string
  credentialNodes: number
  summary: string
}

const STAGE_MODULES: Record<IabStageEvidence["stage"], string[]> = {
  stealer_log: ["collection_engine", "cred_access_auto"],
  vpn_session: ["citrix_audit", "edge_audit", "cloud_token"],
  raas_deploy: ["rmm_audit", "raas_leak_catalog", "raas_tor_portal"],
}

export function runIabChain(
  target: string,
  artifacts: string[] = ["session_cookie", "domain_password"],
  opts: { pattern?: StealerPattern } = {},
): IabHandoffResult {
  const patterns = opts.pattern ? [opts.pattern] : matchStealerPattern(artifacts)
  const patternIds = patterns.map((p) => p.id)
  const market = loadIabMarket()

  const stages: IabStageEvidence[] = [
    {
      stage: "stealer_log",
      artifacts: ["cookies", "passwords", "autofill"],
      techniques: ["T1539", "T1552.001"],
      modules: [...STAGE_MODULES.stealer_log, ...(patterns[0]?.modules ?? [])].slice(0, 4),
      synthetic: true,
    },
    {
      stage: "vpn_session",
      artifacts: ["fortinet_session", "citrix_aaacookie", "rdp_port3389"],
      techniques: patterns[0]?.techniques ?? ["T1078", "T1021.001"],
      modules: patterns[0]?.modules ?? STAGE_MODULES.vpn_session,
      synthetic: true,
    },
    {
      stage: "raas_deploy",
      artifacts: ["anydesk_deploy", "rmm_install", "vss_delete"],
      techniques: ["T1219", "T1486"],
      modules: STAGE_MODULES.raas_deploy,
      synthetic: true,
    },
  ]

  const payload = { target, stages, patternIds, brokerCount: market.iabBrokers.length }
  const artifactId = writeArtifact("iab_handoff_sim", payload)

  return {
    target,
    stages,
    patternIds,
    artifactId,
    credentialNodes: 0,
    summary: `IAB chain ${patternIds.length ? patternIds.join("→") : "default"} (${stages.length} stages, synthetic)`,
  }
}

export function applyIabChainToGraph(
  graph: CredentialGraph,
  result: IabHandoffResult,
): number {
  let count = 0
  for (const stage of result.stages) {
    for (const art of stage.artifacts) {
      graph.addStealerCredential({
        type: stage.stage === "stealer_log" ? "cookie" : "password",
        source: stage.stage === "stealer_log" ? "stealer_log" : "iab_market",
        username: `iab_${stage.stage}`,
        value: `[SYNTHETIC:${art}]`,
        host: result.target,
      })
      count++
    }
  }
  result.credentialNodes = count
  return count
}

export default { runIabChain, applyIabChainToGraph }
