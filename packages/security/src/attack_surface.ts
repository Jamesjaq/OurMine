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

export interface VulnNode {
  id:           string
  title:        string
  severity:     Severity
  confidence:   Confidence
  capLevel:     CapLevel
  cve?:         string
  evidence:     Evidence[]
  validatedAt?: string
  falsePositiveReason?: string
}

export interface AssetNode {
  ip:       string
  hostname: string
  os?:      string
  services: Map<number, ServiceNode>
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
        hostname: hostname || ip,
        services: new Map(),
        notes:    [],
        evidence: [],
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
        capLevel:   2,
        evidence:   [ev],
      }

      if (svc) {
        svc.vulns.push(vuln)
      } else {
        // No matching service node yet — attach directly to asset notes
        asset.notes.push(`Nuclei finding '${v.title}' on ${v.target} (no matching service node)`)
      }
      added.push(vuln)
    }
    return added
  }

  // ─── Validate a suspected finding ──────────────────────────────────────────

  validateFinding(ip: string, port: number, vulnId: string, validationEvidence: Evidence, confirmed: boolean, reason?: string): VulnNode | null {
    const asset = this.assets.get(ip)
    const svc = asset?.services.get(port)
    const vuln = svc?.vulns.find(v => v.id === vulnId)
    if (!vuln) return null

    vuln.evidence.push(validationEvidence)
    if (confirmed) {
      vuln.confidence  = "confirmed"
      vuln.capLevel    = 3
      vuln.validatedAt = new Date().toISOString()
    } else {
      vuln.confidence          = "false_positive"
      vuln.falsePositiveReason = reason
    }
    return vuln
  }

  // ─── Adaptive next-step recommendation ─────────────────────────────────────
  //
  // This is what separates an evidence-driven engine from an LLM wrapper:
  // deterministic service → action routing that doesn't require LLM re-interpretation.

  recommendNextActions(ip: string): { tool: string; reason: string; command: string }[] {
    const asset = this.assets.get(ip)
    if (!asset) return []

    const recommendations: { tool: string; reason: string; command: string }[] = []

    for (const [port, svc] of asset.services) {
      const target = `${ip}:${port}`

      // HTTP services → web enumeration
      if (["http", "https", "http-alt", "http-proxy"].includes(svc.service) || port === 80 || port === 8080 || port === 443 || port === 8443) {
        recommendations.push({
          tool: "gobuster",
          reason: `HTTP service on port ${port} — enumerate directories`,
          command: `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -q`,
        })
        recommendations.push({
          tool: "nuclei",
          reason: `HTTP service on port ${port} — scan for web vulnerabilities`,
          command: `nuclei -u http://${target} -severity critical,high,medium -json`,
        })
      }

      // SSH services → banner & version check
      if (svc.service === "ssh" || port === 22) {
        const versionNum = parseFloat(svc.version.match(/OpenSSH (\d+\.\d+)/)?.[1] ?? "99")
        if (versionNum < 8.0) {
          recommendations.push({
            tool: "nmap",
            reason: `Older SSH version ${svc.version} on port ${port} — check for CVEs`,
            command: `nmap -sV --script ssh-auth-methods,ssh2-enum-algos -p ${port} ${ip}`,
          })
        }
      }

      // MySQL / database services → test for anonymous access
      if (["mysql", "postgresql", "ms-sql", "mongodb"].includes(svc.service) || [3306, 5432, 1433, 27017].includes(port)) {
        recommendations.push({
          tool: "nmap",
          reason: `Database service ${svc.service} on port ${port} — check authentication requirements`,
          command: `nmap --script ${svc.service}-empty-password,${svc.service}-info -p ${port} ${ip}`,
        })
      }

      // SMB services → enumerate shares
      if (svc.service === "microsoft-ds" || port === 445) {
        recommendations.push({
          tool: "nmap",
          reason: `SMB on port 445 — enumerate shares and check for EternalBlue`,
          command: `nmap --script smb-enum-shares,smb-vuln-ms17-010 -p 445 ${ip}`,
        })
      }

      // Suspected vulns that need validation
      for (const vuln of svc.vulns) {
        if (vuln.confidence === "suspected") {
          recommendations.push({
            tool: "curl",
            reason: `Validate suspected finding '${vuln.title}' on ${target}`,
            command: `curl -sv http://${target}/ -H "X-Validation: true" 2>&1`,
          })
        }
      }
    }

    return recommendations
  }

  // ─── Attack-path reasoning ──────────────────────────────────────────────────

  analyzeAttackPaths(): AttackPath[] {
    this.paths = []

    for (const [ip, asset] of this.assets) {
      const services = [...asset.services.values()]
      const confirmedVulns = services.flatMap(s => s.vulns.filter(v => v.confidence === "confirmed"))
      const highVulns      = services.flatMap(s => s.vulns.filter(v => ["critical", "high"].includes(v.severity)))
      const webServices    = services.filter(s => ["http", "https"].includes(s.service) || [80, 443, 8080, 8443].includes(s.port))
      const dbServices     = services.filter(s => ["mysql", "postgresql", "mongodb"].includes(s.service))

      // Web + DB chaining pattern
      if (webServices.length > 0 && dbServices.length > 0 && highVulns.length > 0) {
        this.paths.push({
          id:       crypto.randomUUID(),
          label:    "Web App → Database Access Path",
          steps:    [ip, ...webServices.map(s => `${ip}:${s.port}`), ...dbServices.map(s => `${ip}:${s.port}`)],
          severity: "critical",
          narrative: `Target ${ip} exposes web services (${webServices.map(s => s.port).join(",")}) with ${highVulns.length} high/critical finding(s) and database services (${dbServices.map(s => s.port).join(",")}) suggesting potential SQL injection or auth bypass → data access chain.`,
        })
      }

      // Unvalidated high vulns
      if (highVulns.length > 0 && confirmedVulns.length < highVulns.length) {
        this.paths.push({
          id:       crypto.randomUUID(),
          label:    `${highVulns.length} High/Critical Findings Pending Validation`,
          steps:    highVulns.map(v => v.id),
          severity: "high",
          narrative: `${highVulns.length} high/critical finding(s) detected on ${ip} with confidence 'suspected'. Manual validation required before escalation.`,
        })
      }
    }

    return this.paths
  }

  // ─── Summary & serialization ────────────────────────────────────────────────

  summary() {
    const allServices = [...this.assets.values()].flatMap(a => [...a.services.values()])
    const allVulns    = allServices.flatMap(s => s.vulns)

    return {
      sessionId:   this.sessionId,
      target:      this.target,
      startedAt:   this.startedAt,
      assets:      this.assets.size,
      services:    allServices.length,
      openPorts:   allServices.filter(s => s.state === "open").map(s => s.port),
      vulns: {
        total:       allVulns.length,
        confirmed:   allVulns.filter(v => v.confidence === "confirmed").length,
        suspected:   allVulns.filter(v => v.confidence === "suspected").length,
        falsePos:    allVulns.filter(v => v.confidence === "false_positive").length,
        bySeverity: {
          critical: allVulns.filter(v => v.severity === "critical").length,
          high:     allVulns.filter(v => v.severity === "high").length,
          medium:   allVulns.filter(v => v.severity === "medium").length,
          low:      allVulns.filter(v => v.severity === "low").length,
          info:     allVulns.filter(v => v.severity === "info").length,
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

  /** Load a persisted graph. */
  static load(filePath: string): AttackSurfaceGraph {
    const data = JSON.parse(fs.readFileSync(filePath, "utf8"))
    const g = new AttackSurfaceGraph(data.target, data.sessionId)
    // Restore assets and services from serialized form
    for (const [ip, assetData] of Object.entries(data.assets ?? {})) {
      const a = g.upsertAsset(ip)
      const ad = assetData as any
      a.notes    = ad.notes    ?? []
      a.evidence = ad.evidence ?? []
      for (const [portStr, svcData] of Object.entries(ad.services ?? {})) {
        a.services.set(parseInt(portStr, 10), svcData as ServiceNode)
      }
    }
    g.paths = data.paths ?? []
    return g
  }
}

export default AttackSurfaceGraph
