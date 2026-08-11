/**
 * @module credential_graph
 * Credential vault + pivot chain engine — harvests feed graph edges for lateral movement.
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"

export type CredentialType = "password" | "nthash" | "ticket" | "token" | "key" | "cookie"

export interface CredentialNode {
  id: string
  type: CredentialType
  source: string
  username?: string
  domain?: string
  host?: string
  value: string
  discoveredAt: string
  used: boolean
}

export interface PivotEdge {
  from: string
  to: string
  method: string
  credentialId: string
  success: boolean
}

export interface BloodHoundPathRef {
  start: string
  end: string
  nodes: string[]
  targetHosts: string[]
}

export class CredentialGraph {
  private creds = new Map<string, CredentialNode>()
  private pivots: PivotEdge[] = []
  private bloodhoundPaths: BloodHoundPathRef[] = []
  private bloodhoundExportPath?: string

  addCredential(cred: Omit<CredentialNode, "id" | "discoveredAt" | "used">): CredentialNode {
    const id = `cred_${this.creds.size + 1}_${Date.now()}`
    const node: CredentialNode = {
      ...cred,
      id,
      discoveredAt: new Date().toISOString(),
      used: false,
    }
    this.creds.set(id, node)
    return node
  }

  listCredentials(host?: string): CredentialNode[] {
    const all = [...this.creds.values()]
    return host ? all.filter((c) => !c.host || c.host === host) : all
  }

  unusedForHost(host: string): CredentialNode[] {
    return this.listCredentials(host).filter((c) => !c.used)
  }

  markUsed(id: string): void {
    const c = this.creds.get(id)
    if (c) c.used = true
  }

  recordPivot(edge: Omit<PivotEdge, "success"> & { success?: boolean }): PivotEdge {
    const pivot: PivotEdge = { ...edge, success: edge.success ?? false }
    this.pivots.push(pivot)
    if (edge.success) this.markUsed(edge.credentialId)
    return pivot
  }

  suggestPivots(graph: AttackSurfaceGraph): Array<{ host: string; tool: string; credId: string; reason: string }> {
    const summary = graph.summary()
    const suggestions: Array<{ host: string; tool: string; credId: string; reason: string }> = []

    for (const bh of this.bloodhoundPaths.slice(0, 5)) {
      for (const host of bh.targetHosts) {
        const cred = this.unusedForHost("")[0]
        if (cred) {
          suggestions.push({
            host,
            tool: "pivot_replay",
            credId: cred.id,
            reason: `BloodHound path ${bh.start} → ${bh.end} via ${host}`,
          })
        }
      }
    }

    for (const cred of this.unusedForHost("")) {
      const hosts = [graph.summary().target ?? "unknown"]
      if (cred.type === "nthash" || cred.type === "password") {
        for (const host of hosts) {
          suggestions.push({
            host,
            tool: cred.type === "nthash" ? "lateral_move" : "cred_spray",
            credId: cred.id,
            reason: `${cred.type} from ${cred.source} → ${host}`,
          })
        }
      }
      if (cred.type === "token") {
        suggestions.push({
          host: cred.host ?? "cloud",
          tool: "cloud_token",
          credId: cred.id,
          reason: `OAuth/cloud token from ${cred.source}`,
        })
      }
    }

    return suggestions.slice(0, 10)
  }

  injectIntoGraph(graph: AttackSurfaceGraph): void {
    for (const cred of this.creds.values()) {
      const host = cred.host ?? graph.summary().target ?? "unknown"
      const asset = graph.upsertAsset(host)
      asset.notes.push(`[CRED] ${cred.type} ${cred.username ?? ""}@${cred.domain ?? host} (source: ${cred.source})`)
    }
  }

  toJSON(): { credentials: CredentialNode[]; pivots: PivotEdge[]; bloodhoundPaths: BloodHoundPathRef[]; bloodhoundExportPath?: string } {
    return {
      credentials: [...this.creds.values()],
      pivots: this.pivots,
      bloodhoundPaths: this.bloodhoundPaths,
      bloodhoundExportPath: this.bloodhoundExportPath,
    }
  }

  static fromJSON(data: {
    credentials?: CredentialNode[]
    pivots?: PivotEdge[]
    bloodhoundPaths?: BloodHoundPathRef[]
    bloodhoundExportPath?: string
  }): CredentialGraph {
    const g = new CredentialGraph()
    for (const c of data.credentials ?? []) g.creds.set(c.id, c)
    g.pivots = data.pivots ?? []
    g.bloodhoundPaths = data.bloodhoundPaths ?? []
    g.bloodhoundExportPath = data.bloodhoundExportPath
    return g
  }

  ingestBloodHoundPaths(paths: BloodHoundPathRef[], exportPath?: string): number {
    this.bloodhoundPaths = paths
    if (exportPath) this.bloodhoundExportPath = exportPath
    return paths.length
  }

  getBloodHoundPaths(): BloodHoundPathRef[] {
    return [...this.bloodhoundPaths]
  }

  /** Hosts discovered via BloodHound path analysis. */
  bloodhoundTargetHosts(): string[] {
    const hosts = new Set<string>()
    for (const p of this.bloodhoundPaths) {
      for (const h of p.targetHosts) hosts.add(h)
    }
    return [...hosts]
  }

  /** Ingest credentials from post-ex harvest JSON output. */
  ingestFromPostExOutput(output: string, source = "postex_harvest"): number {
    let added = 0
    try {
      const findings = JSON.parse(output) as Array<{ category?: string; name?: string; value?: string; path?: string }>
      for (const f of findings) {
        if (f.category !== "credential") continue
        const isHash = /^\$[0-9a-z]+\$/.test(f.value ?? "") || (f.name ?? "").includes("shadow")
        this.addCredential({
          type: isHash ? "nthash" : "password",
          source,
          username: f.name,
          host: undefined,
          value: (f.value ?? "").slice(0, 200),
        })
        added++
      }
    } catch { /* non-json output */ }
    return added
  }

  /** Record successful lateral auth as pivot edge. */
  ingestLateralResult(host: string, output: string, credId?: string): void {
    try {
      const result = JSON.parse(output) as { success?: boolean; method?: string }
      if (result.success && credId) {
        this.recordPivot({ from: "local", to: host, method: result.method ?? "lateral", credentialId: credId, success: true })
      }
    } catch { /* ignore */ }
  }
}

export default { CredentialGraph }
