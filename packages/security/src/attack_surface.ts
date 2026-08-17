/**
 * @module security/attack_surface
 * Attack Surface Graph — Stateful, evidence-backed target model.
 *
 * Transforms disconnected tool outputs into a structured, queryable graph:
 *   Target → Assets → Services → Vulnerabilities → Evidence → Attack Paths
 *
 * This is the critical missing layer identified in the Eighth-Pass audit.
 * Without this, each tool result is an isolated text blob handed to the LLM.
 * With this, tool outputs compose into a structured model that drives
 * adaptive next-step selection without requiring LLM re-interpretation.
 */

import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import type { ParsedPort, ParsedVulnerability } from "./scanner_parsers.ts"
import { FindingStateMachine, type FindingState } from "./finding_lifecycle.ts"

// ─── Core types ──────────────────────────────────────────────────────────────

export type Confidence = "confirmed" | "probable" | "suspected" | "false_positive" | "unverified"
export type Severity    = "critical" | "high" | "medium" | "low" | "info"
export type CapLevel    = 0 | 1 | 2 | 3 | 4  // Info/Enum/Detect/Validate/Impact

export interface Evidence {
  id:        string
  tool:      string
  command:   string
  rawOutput: string
  parsedAt:  string
  executionMs: number
}

export interface ServiceNode {
  port:       number
  protocol:   string
  state:      "open" | "closed" | "filtered"
  service:    string
  version:    string
  evidence:   Evidence[]
  vulns:      VulnNode[]
}

export interface EndpointNode {
  path:       string
  status:     number
  size?:      number
  method:     string
  source:     string
  timestamp:  string
  evidence:   Evidence[]
  /** classification heuristic — not a confirmed vuln */
  heuristic?: "admin" | "api" | "auth" | "upload" | "backup" | "other"
}

export interface VulnNode {
  id:           string
  title:        string
  severity:     Severity
  confidence:   Confidence
  /** Mirrors stateMachine.current — keep in sync via ValidationEngine */
  state:        FindingState
  capLevel:     CapLevel
  cve?:         string
  evidence:     Evidence[]
  validatedAt?: string
  falsePositiveReason?: string
  /** Attached after first eligibility check. Owned by ValidationEngine. */
  stateMachine?: FindingStateMachine
}

export interface AssetNode {
  ip:        string
  hostname:  string
  os?:       string
  services:  Map<number, ServiceNode>
  endpoints: EndpointNode[]
  notes:    string[]
  evidence: Evidence[]
}

export interface AttackPath {
  id:       string
  label:    string
  steps:    string[]   // asset/service/vuln IDs
  severity: Severity
  narrative: string
}

// ─── Attack Surface Graph ─────────────────────────────────────────────────────

export class AttackSurfaceGraph {
  readonly target:   string
  readonly sessionId: string
  private assets:    Map<string, AssetNode> = new Map()
  private paths:     AttackPath[] = []
  private toolLog:   Evidence[] = []
  private startedAt: string

  constructor(target: string, sessionId?: string) {
    this.target    = target
    this.sessionId = sessionId ?? crypto.randomUUID()
    this.startedAt = new Date().toISOString()
  }

  // ─── Evidence factory ───────────────────────────────────────────────────────

  makeEvidence(tool: string, command: string, rawOutput: string, executionMs = 0): Evidence {
    const ev: Evidence = {
      id:          crypto.randomUUID(),
      tool,
      command,
      rawOutput:   rawOutput.slice(0, 8_000),
      parsedAt:    new Date().toISOString(),
      executionMs,
    }
    this.toolLog.push(ev)
    return ev
  }

  // ─── Asset management ───────────────────────────────────────────────────────

  upsertAsset(ip: string, hostname = "", ev?: Evidence): AssetNode {
    const key = ip
    if (!this.assets.has(key)) {
      this.assets.set(key, {
        ip,
        hostname:  hostname || ip,
        services:  new Map(),
        endpoints: [],
        notes:     [],
        evidence:  [],
      })
    }
    const asset = this.assets.get(key)!
    if (hostname && !asset.hostname) asset.hostname = hostname
    if (ev) asset.evidence.push(ev)
    return asset
  }

  // ─── Ingest Nmap parsed ports ───────────────────────────────────────────────

  ingestNmap(ip: string, ports: ParsedPort[], ev: Evidence): ServiceNode[] {
    const asset = this.upsertAsset(ip, ip, ev)
    const added: ServiceNode[] = []
    for (const p of ports) {
      if (p.state !== "open") continue
      const existing = asset.services.get(p.port)
      if (existing) {
        existing.evidence.push(ev)
        if (p.version) existing.version = p.version
        added.push(existing)
        continue
      }
      const svc: ServiceNode = {
        port:     p.port,
        protocol: p.protocol,
        state:    "open",
        service:  p.service,
        version:  p.version ?? "",
        evidence: [ev],
        vulns:    [],
      }
      asset.services.set(p.port, svc)
      added.push(svc)
    }
    return added
  }

  // ─── Ingest Nuclei parsed vulnerabilities ──────────────────────────────────

  ingestNuclei(ip: string, vulns: ParsedVulnerability[], ev: Evidence): VulnNode[] {
    const asset = this.upsertAsset(ip, ip, ev)
    const added: VulnNode[] = []

    for (const v of vulns) {
      // Try to bind to a service node by port extracted from target URL
      const portMatch = v.target.match(/:(\d+)/)
      const port = portMatch ? parseInt(portMatch[1]!, 10) : 80
      const svc = asset.services.get(port)

      const vuln: VulnNode = {
        id:         v.id,
        title:      v.title,
        severity:   v.severity,
        confidence: "suspected",     // Nuclei = detection only until validated
        state:      "SUSPECTED",     // state machine initial state
        capLevel:   2,
        evidence:   [ev],
      }

      if (svc) {
        // Idempotency: skip if same finding already in the graph
        if (!svc.vulns.find(existing => existing.id === v.id)) {
          svc.vulns.push(vuln)
        }
      } else {
        asset.notes.push(`Nuclei finding '${v.title}' on ${v.target} (no matching service node)`)
      }
      added.push(vuln)
    }
    return added
  }

  // ─── Ingest Gobuster endpoint list ─────────────────────────────────────────

  ingestGobuster(ip: string, port: number, lines: string[], ev: Evidence): EndpointNode[] {
    const asset = this.upsertAsset(ip, ip, ev)
    const svc   = asset.services.get(port)
    const added: EndpointNode[] = []

    for (const line of lines) {
      const trimmed = line.trim()
      const m = trimmed.match(/^(\/?[^\s]+)[\s\t]+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/)
      if (!m) continue
      const rawPath = m[1]!
      if (rawPath.startsWith("==") || rawPath.startsWith("[+]") || rawPath.startsWith("Finished")) continue
      const endpPath   = rawPath.startsWith("/") ? rawPath : "/" + rawPath
      const status     = parseInt(m[2]!, 10)
      const size       = m[3] ? parseInt(m[3], 10) : undefined

      // Idempotency: skip already-known endpoints
      if (asset.endpoints.find(e => e.path === endpPath && e.status === status)) continue

      // Classify heuristic (not a vuln — just a candidate for further investigation)
      let heuristic: EndpointNode["heuristic"] = "other"
      if (/admin|manager|console|dashboard|cpanel|phpmyadmin/i.test(endpPath)) heuristic = "admin"
      else if (/api|graphql|rest|v\d+/i.test(endpPath))                        heuristic = "api"
      else if (/login|signin|auth|sso|oauth/i.test(endpPath))                  heuristic = "auth"
      else if (/upload|import|attach/i.test(endpPath))                         heuristic = "upload"
      else if (/backup|bak|\.sql|\.tar|\.zip|\.gz/i.test(endpPath))           heuristic = "backup"

      const endpoint: EndpointNode = {
        path:      endpPath,
        status,
        size,
        method:    "GET",
        source:    "gobuster",
        timestamp: new Date().toISOString(),
        evidence:  [ev],
        heuristic,
      }
      asset.endpoints.push(endpoint)
      added.push(endpoint)
    }
    return added
  }

  /** Called by ValidationEngine after each conclusion to force path re-evaluation. */
  invalidatePaths(): void {
    this.paths = this.analyzeAttackPaths()
  }

  // ─── Validate a suspected finding ──────────────────────────────────────────
  //
  // Direct path retained for testing. Production code MUST use ValidationEngine
  // which enforces the state machine and requires real evidence before CONFIRMED.

  validateFinding(ip: string, port: number, vulnId: string, validationEvidence: Evidence, confirmed: boolean, reason?: string): VulnNode | null {
    const asset = this.assets.get(ip)
    const svc = asset?.services.get(port)
    const vuln = svc?.vulns.find(v => v.id === vulnId)
    if (!vuln) return null

    vuln.evidence.push(validationEvidence)
    if (confirmed) {
      vuln.confidence  = "confirmed"
      vuln.state       = "CONFIRMED"
      vuln.capLevel    = 3
      vuln.validatedAt = new Date().toISOString()
    } else {
      vuln.confidence          = "false_positive"
      vuln.state               = "FALSE_POSITIVE"
      vuln.falsePositiveReason = reason
    }
    return vuln
  }

  // ─── Adaptive next-step recommendation ─────────────────────────────────────
  //
  // This is what separates an evidence-driven engine from an LLM wrapper:
  // deterministic service → action routing that doesn't require LLM re-interpretation.

  recommendNextActions(ip: string): { tool: string; reason: string; command: string; skip?: string }[] {
    const asset = this.assets.get(ip)
    if (!asset) return []

    const recommendations: { tool: string; reason: string; command: string; skip?: string }[] = []
    const alreadyEnumerated = new Set(asset.endpoints.map(e => e.path.split("/")[1] ?? ""))

    for (const [port, svc] of asset.services) {
      const target   = `${ip}:${port}`
      const isHTTP   = ["http", "https", "http-alt", "http-proxy"].includes(svc.service) || [80, 8080, 443, 8443].includes(port)
      const isDB     = ["mysql", "postgresql", "ms-sql", "mongodb"].includes(svc.service) || [3306, 5432, 1433, 27017].includes(port)
      const hasVulns = svc.vulns.some(v => v.state !== "FALSE_POSITIVE")
      const allConfirmed = svc.vulns.length > 0 && svc.vulns.every(v => v.state === "CONFIRMED" || v.state === "FALSE_POSITIVE")

      // HTTP services → web enumeration (skip if already done)
      if (isHTTP) {
        if (asset.endpoints.length === 0) {
          recommendations.push({
            tool: "gobuster",
            reason: `HTTP service on port ${port} — enumerate directories`,
            command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -q`,
          })
        } else {
          recommendations.push({
            tool: "gobuster",
            reason: `Already enumerated ${asset.endpoints.length} endpoints on port ${port}`,
            command: "",
            skip: `${asset.endpoints.length} endpoints already in graph`,
          })
        }
        // Nuclei: only if no vuln scan done yet
        if (!hasVulns) {
          recommendations.push({
            tool: "nuclei",
            reason: `HTTP service on port ${port} — scan for web vulnerabilities`,
            command: `nuclei -u http://${target} -severity critical,high,medium -json`,
          })
        } else if (allConfirmed) {
          recommendations.push({
            tool: "nuclei",
            reason: `All vulns on port ${port} are confirmed or false_positive`,
            command: "",
            skip: "vuln assessment complete",
          })
        }
      }

      // SSH: only for old versions, only if no vuln already
      if (svc.service === "ssh" || port === 22) {
        const versionNum = parseFloat(svc.version.match(/OpenSSH (\d+\.\d+)/)?.[1] ?? "99")
        if (versionNum < 8.0 && !svc.vulns.find(v => v.id.includes("ssh"))) {
          recommendations.push({
            tool: "nmap",
            reason: `Older SSH ${svc.version} — check for known CVEs`,
            command: `nmap -sV --script ssh-auth-methods,ssh2-enum-algos -p ${port} ${ip}`,
          })
        }
      }

      // DB: only if not already validated
      if (isDB && !svc.vulns.find(v => v.id.includes("empty-password") && v.state === "CONFIRMED")) {
        recommendations.push({
          tool: "nmap",
          reason: `Database ${svc.service} on port ${port} — check anonymous auth`,
          command: `nmap --script ${svc.service}-empty-password -p ${port} ${ip}`,
        })
      }

      // SMB
      if (svc.service === "microsoft-ds" || port === 445) {
        recommendations.push({
          tool: "nmap",
          reason: "SMB on port 445 — enumerate shares and EternalBlue",
          command: `nmap --script smb-enum-shares,smb-vuln-ms17-010 -p 445 ${ip}`,
        })
      }

      // Suspected vulns → flag for ValidationEngine (not ad-hoc curl)
      for (const vuln of svc.vulns) {
        if (vuln.state === "SUSPECTED") {
          recommendations.push({
            tool: "validation_engine",
            reason: `Auto-validate suspected '${vuln.title}' on ${target}`,
            command: `[ValidationEngine.validate({ vuln, ip:'${ip}', port:${port}, service:'${svc.service}', graph })]`,
          })
        }
      }
    }

    return recommendations.filter(r => !r.skip || r.command !== "")
  }

  // ─── Attack-path reasoning ──────────────────────────────────────────────────

  analyzeAttackPaths(): AttackPath[] {
    this.paths = []

    for (const [ip, asset] of this.assets) {
      const services = [...asset.services.values()]
      // Exclude FALSE_POSITIVE vulns from all reasoning
      const activeVulns    = services.flatMap(s => s.vulns.filter(v => v.state !== "FALSE_POSITIVE"))
      const confirmedVulns = activeVulns.filter(v => v.state === "CONFIRMED")
      const highVulns      = activeVulns.filter(v => ["critical", "high"].includes(v.severity))
      const webServices    = services.filter(s => ["http", "https"].includes(s.service) || [80, 443, 8080, 8443].includes(s.port))
      const dbServices     = services.filter(s => ["mysql", "postgresql", "mongodb"].includes(s.service))
      const adminEndpoints = asset.endpoints.filter(e => e.heuristic === "admin")

      // Confirmed web + DB chaining
      if (webServices.length > 0 && dbServices.length > 0 && confirmedVulns.length > 0) {
        this.paths.push({
          id:       crypto.randomUUID(),
          label:    "Web App → Database Access Path (Confirmed)",
          steps:    [ip, ...webServices.map(s => `${ip}:${s.port}`), ...dbServices.map(s => `${ip}:${s.port}`)],
          severity: "critical",
          narrative: `Target ${ip} has ${confirmedVulns.length} CONFIRMED finding(s) on web services (${webServices.map(s => s.port).join(",")}) with database services (${dbServices.map(s => s.port).join(",")}). Evidence-backed access chain exists.`,
        })
      } else if (webServices.length > 0 && dbServices.length > 0 && highVulns.length > 0) {
        this.paths.push({
          id:       crypto.randomUUID(),
          label:    "Web App → Database Access Path (Suspected)",
          steps:    [ip, ...webServices.map(s => `${ip}:${s.port}`), ...dbServices.map(s => `${ip}:${s.port}`)],
          severity: "high",
          narrative: `Target ${ip} exposes web services (${webServices.map(s => s.port).join(",")}) with ${highVulns.length} suspected finding(s) and database services. Validation required.`,
        })
      }

      // Admin endpoints found via enumeration
      if (adminEndpoints.length > 0 && webServices.length > 0) {
        this.paths.push({
          id:       crypto.randomUUID(),
          label:    `Admin/Privileged Endpoints Exposed (${adminEndpoints.length})`,
          steps:    adminEndpoints.map(e => `${ip}${e.path}`),
          severity: "medium",
          narrative: `Enumeration found ${adminEndpoints.length} admin/privileged endpoint(s) on ${ip}: ${adminEndpoints.map(e => e.path).join(", ")}. These are heuristic candidates, not confirmed vulnerabilities.`,
        })
      }

      // Unvalidated high vulns needing attention
      const suspectedHigh = highVulns.filter(v => v.state === "SUSPECTED" || v.state === "VALIDATION_PENDING")
      if (suspectedHigh.length > 0) {
        this.paths.push({
          id:       crypto.randomUUID(),
          label:    `${suspectedHigh.length} High/Critical Findings Pending Validation`,
          steps:    suspectedHigh.map(v => v.id),
          severity: "high",
          narrative: `${suspectedHigh.length} high/critical finding(s) on ${ip} remain at 'suspected' — automatic validation pending or unavailable.`,
        })
      }
    }

    return this.paths
  }

  // ─── Summary & serialization ────────────────────────────────────────────────

  summary() {
    const allServices  = [...this.assets.values()].flatMap(a => [...a.services.values()])
    const allVulns     = allServices.flatMap(s => s.vulns)
    const allEndpoints = [...this.assets.values()].flatMap(a => a.endpoints)

    return {
      sessionId:   this.sessionId,
      target:      this.target,
      startedAt:   this.startedAt,
      assets:      this.assets.size,
      services:    allServices.length,
      openPorts:   allServices.filter(s => s.state === "open").map(s => s.port),
      endpoints: {
        total:  allEndpoints.length,
        admin:  allEndpoints.filter(e => e.heuristic === "admin").length,
        api:    allEndpoints.filter(e => e.heuristic === "api").length,
        auth:   allEndpoints.filter(e => e.heuristic === "auth").length,
      },
      vulns: {
        total:       allVulns.length,
        confirmed:   allVulns.filter(v => v.state === "CONFIRMED").length,
        suspected:   allVulns.filter(v => v.state === "SUSPECTED" || v.state === "VALIDATION_PENDING").length,
        validating:  allVulns.filter(v => v.state === "VALIDATING").length,
        falsePos:    allVulns.filter(v => v.state === "FALSE_POSITIVE").length,
        unverified:  allVulns.filter(v => v.state === "UNVERIFIED").length,
        bySeverity: {
          critical: allVulns.filter(v => v.severity === "critical" && v.state !== "FALSE_POSITIVE").length,
          high:     allVulns.filter(v => v.severity === "high"     && v.state !== "FALSE_POSITIVE").length,
          medium:   allVulns.filter(v => v.severity === "medium"   && v.state !== "FALSE_POSITIVE").length,
          low:      allVulns.filter(v => v.severity === "low"      && v.state !== "FALSE_POSITIVE").length,
          info:     allVulns.filter(v => v.severity === "info"     && v.state !== "FALSE_POSITIVE").length,
        },
      },
      attackPaths: this.paths.length,
      toolCalls:   this.toolLog.length,
    }
  }

  toJSON() {
    return {
      ...this.summary(),
      assets: Object.fromEntries(
        [...this.assets.entries()].map(([k, a]) => [k, {
          ...a,
          services: Object.fromEntries([...a.services.entries()]),
        }])
      ),
      paths:   this.paths,
      toolLog: this.toolLog,
    }
  }

  /** Persist graph to disk for session continuity across agent restarts. */
  save(dir: string) {
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(
      path.join(dir, `asm_${this.sessionId}.json`),
      JSON.stringify(this.toJSON(), null, 2)
    )
  }

  /** Rehydrate a graph from its serialized JSON representation. */
  static fromJSON(data: any): AttackSurfaceGraph {
    const g = new AttackSurfaceGraph(data.target, data.sessionId)
    for (const [ip, assetData] of Object.entries(data.assets ?? {})) {
      const a = g.upsertAsset(ip)
      const ad = assetData as any
      a.notes = ad.notes ?? []
      a.evidence = ad.evidence ?? []
      a.endpoints = ad.endpoints ?? []
      for (const [portStr, svcData] of Object.entries(ad.services ?? {})) {
        a.services.set(parseInt(portStr, 10), svcData as ServiceNode)
      }
    }
    g.paths = data.paths ?? []
    return g
  }

  /** Load a persisted graph. */
  static load(filePath: string): AttackSurfaceGraph {
    return AttackSurfaceGraph.fromJSON(JSON.parse(fs.readFileSync(filePath, "utf8")))
  }
}

export default AttackSurfaceGraph
