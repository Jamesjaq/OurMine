import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import { AttackSurfaceGraph, type Evidence } from "./attack_surface.ts"

export type KnowledgeStatus = "OBSERVED" | "INFERRED" | "HYPOTHESIZED" | "VERIFIED" | "REJECTED"
export type WorldEntityKind = "HOST" | "SERVICE" | "APPLICATION" | "IDENTITY" | "ACCOUNT" | "PROCESS" | "FILE" | "DATABASE" | "SEGMENT" | "TRUST" | "CONTROL" | "RESOURCE" | "PERMISSION" | "OBSERVATION" | "VULNERABILITY" | "CAPABILITY" | "OBJECTIVE"

export interface WorldEntity {
  id: string
  kind: WorldEntityKind
  label: string
  properties: Record<string, unknown>
  status: KnowledgeStatus
  confidence: number
  firstSeen: string
  lastSeen: string
  evidenceIds: string[]
}

export interface WorldRelationship {
  id: string
  from: string
  to: string
  type: string
  status: KnowledgeStatus
  confidence: number
  firstSeen: string
  lastSeen: string
  evidenceIds: string[]
}

export interface WorldObservation {
  id: string
  subjectId: string
  fact: string
  source: string
  status: KnowledgeStatus
  confidence: number
  observedAt: string
  evidenceIds: string[]
}

export interface CapabilityContract {
  id: string
  namespace: string
  status: "TRUSTED_PRIMITIVE" | "UNCERTAIN" | "REJECTED"
  preconditions: string[]
  effects: string[]
  observableEffects: string[]
  failureModes: string[]
  rollback: string[]
  evidenceIds: string[]
  confidence: number
}

export interface WorldObjective {
  id: string
  description: string
  constraints: string[]
  successCriteria: string[]
  status: "OPEN" | "ACHIEVED" | "REJECTED"
  createdAt: string
}

export interface SecurityWorldModelSnapshot {
  version: 1
  target: string
  sessionId: string
  updatedAt: string
  graph: ReturnType<AttackSurfaceGraph["toJSON"]>
  entities: WorldEntity[]
  relationships: WorldRelationship[]
  observations: WorldObservation[]
  capabilities: CapabilityContract[]
  objectives: WorldObjective[]
}

function now(): string { return new Date().toISOString() }
function id(prefix: string): string { return `${prefix}_${crypto.randomUUID()}` }

export class SecurityWorldModel {
  readonly graph: AttackSurfaceGraph
  readonly target: string
  readonly sessionId: string
  private entities = new Map<string, WorldEntity>()
  private relationships = new Map<string, WorldRelationship>()
  private observations = new Map<string, WorldObservation>()
  private capabilities = new Map<string, CapabilityContract>()
  private objectives = new Map<string, WorldObjective>()

  constructor(target: string, sessionId?: string, graph?: AttackSurfaceGraph) {
    this.target = target
    this.sessionId = sessionId ?? crypto.randomUUID()
    this.graph = graph ?? new AttackSurfaceGraph(target, this.sessionId)
  }

  upsertEntity(input: Omit<WorldEntity, "id" | "firstSeen" | "lastSeen"> & { id?: string }): WorldEntity {
    const key = input.id ?? `${input.kind}:${input.label}`
    const existing = this.entities.get(key)
    if (existing) {
      existing.properties = { ...existing.properties, ...input.properties }
      existing.lastSeen = now()
      existing.confidence = Math.max(existing.confidence, input.confidence)
      existing.evidenceIds = [...new Set([...existing.evidenceIds, ...input.evidenceIds])]
      if (input.status === "VERIFIED" || (input.status === "REJECTED" && existing.status !== "VERIFIED")) existing.status = input.status
      return existing
    }
    const timestamp = now()
    const entity: WorldEntity = { ...input, id: key, firstSeen: timestamp, lastSeen: timestamp, evidenceIds: [...input.evidenceIds] }
    this.entities.set(key, entity)
    return entity
  }

  relate(from: string, to: string, type: string, status: KnowledgeStatus, confidence: number, evidenceIds: string[] = []): WorldRelationship {
    const key = `${from}|${type}|${to}`
    const existing = this.relationships.get(key)
    if (existing) {
      existing.lastSeen = now()
      existing.confidence = Math.max(existing.confidence, confidence)
      existing.evidenceIds = [...new Set([...existing.evidenceIds, ...evidenceIds])]
      if (status === "VERIFIED" || (status === "REJECTED" && existing.status !== "VERIFIED")) existing.status = status
      return existing
    }
    const timestamp = now()
    const relationship: WorldRelationship = { id: id("rel"), from, to, type, status, confidence, firstSeen: timestamp, lastSeen: timestamp, evidenceIds }
    this.relationships.set(key, relationship)
    return relationship
  }

  observe(subjectId: string, fact: string, source: string, status: KnowledgeStatus = "OBSERVED", confidence = 0.5, evidence: Evidence[] = []): WorldObservation {
    const observation: WorldObservation = { id: id("obs"), subjectId, fact, source, status, confidence, observedAt: now(), evidenceIds: evidence.map((e) => e.id) }
    this.observations.set(observation.id, observation)
    const entity = this.entities.get(subjectId)
    if (entity) {
      entity.lastSeen = observation.observedAt
      entity.evidenceIds = [...new Set([...entity.evidenceIds, ...observation.evidenceIds])]
    }
    return observation
  }

  registerCapability(contract: CapabilityContract): CapabilityContract {
    if (contract.status !== "TRUSTED_PRIMITIVE") throw new Error(`Capability ${contract.id} is not trusted and cannot enter the reasoning model`)
    this.capabilities.set(contract.id, { ...contract, evidenceIds: [...contract.evidenceIds] })
    return contract
  }

  addObjective(input: Omit<WorldObjective, "id" | "createdAt" | "status"> & { id?: string; status?: WorldObjective["status"] }): WorldObjective {
    const objective: WorldObjective = { ...input, id: input.id ?? id("obj"), createdAt: now(), status: input.status ?? "OPEN" }
    this.objectives.set(objective.id, objective)
    return objective
  }

  syncAttackSurface(evidence: Evidence[] = []): void {
    const data = this.graph.toJSON() as any
    for (const [ip, asset] of Object.entries(data.assets ?? {})) {
      const host = this.upsertEntity({ kind: "HOST", label: ip, properties: { hostname: (asset as any).hostname, os: (asset as any).os }, status: "OBSERVED", confidence: 0.9, evidenceIds: evidence.map((e) => e.id) })
      for (const [port, service] of Object.entries((asset as any).services ?? {})) {
        const svc = service as any
        const serviceEntity = this.upsertEntity({ kind: "SERVICE", label: `${ip}:${port}`, properties: { port: Number(port), protocol: svc.protocol, service: svc.service, version: svc.version }, status: "OBSERVED", confidence: 0.9, evidenceIds: (svc.evidence ?? []).map((e: Evidence) => e.id) })
        this.relate(host.id, serviceEntity.id, "EXPOSES", "OBSERVED", 0.9, (svc.evidence ?? []).map((e: Evidence) => e.id))
        for (const vuln of svc.vulns ?? []) {
          const v = this.upsertEntity({ kind: "VULNERABILITY", label: vuln.id, properties: { title: vuln.title, severity: vuln.severity, state: vuln.state }, status: vuln.state === "CONFIRMED" ? "VERIFIED" : vuln.state === "FALSE_POSITIVE" ? "REJECTED" : "INFERRED", confidence: vuln.confidence === "confirmed" ? 1 : vuln.confidence === "suspected" ? 0.5 : 0.2, evidenceIds: (vuln.evidence ?? []).map((e: Evidence) => e.id) })
          this.relate(serviceEntity.id, v.id, "HAS_VULNERABILITY", v.status, v.confidence, v.evidenceIds)
        }
      }
      for (const endpoint of (asset as any).endpoints ?? []) {
        const app = this.upsertEntity({ kind: "APPLICATION", label: `${ip}${endpoint.path}`, properties: { path: endpoint.path, status: endpoint.status, heuristic: endpoint.heuristic }, status: "OBSERVED", confidence: 0.8, evidenceIds: (endpoint.evidence ?? []).map((e: Evidence) => e.id) })
        this.relate(host.id, app.id, "SERVES", "OBSERVED", 0.8, app.evidenceIds)
      }
    }
  }

  findPaths(from: string, to?: string, includeHypotheses = false): string[][] {
    const edges = [...this.relationships.values()].filter((r) => includeHypotheses || ["OBSERVED", "VERIFIED"].includes(r.status))
    const paths: string[][] = []
    const walk = (current: string, path: string[]) => {
      if (path.length > 12) return
      if (!to || current === to) { if (path.length > 1) paths.push(path); if (to && current === to) return }
      for (const edge of edges.filter((r) => r.from === current)) if (!path.includes(edge.to)) walk(edge.to, [...path, edge.to])
    }
    walk(from, [from])
    return paths
  }

  uncertainties(): Array<WorldEntity | WorldRelationship | WorldObservation> {
    return [...this.entities.values(), ...this.relationships.values(), ...this.observations.values()].filter((item) => item.status === "HYPOTHESIZED" || item.status === "INFERRED")
  }

  snapshot(): SecurityWorldModelSnapshot {
    return { version: 1, target: this.target, sessionId: this.sessionId, updatedAt: now(), graph: this.graph.toJSON(), entities: [...this.entities.values()], relationships: [...this.relationships.values()], observations: [...this.observations.values()], capabilities: [...this.capabilities.values()], objectives: [...this.objectives.values()] }
  }

  save(filePath: string): void {
    fs.mkdirSync(path.dirname(filePath), { recursive: true })
    fs.writeFileSync(filePath, JSON.stringify(this.snapshot(), null, 2) + "\n")
  }

  static load(filePath: string): SecurityWorldModel {
    const snapshot = JSON.parse(fs.readFileSync(filePath, "utf8")) as SecurityWorldModelSnapshot
    const model = new SecurityWorldModel(snapshot.target, snapshot.sessionId, AttackSurfaceGraph.fromJSON(snapshot.graph))
    for (const entity of snapshot.entities ?? []) model.entities.set(entity.id, entity)
    for (const relationship of snapshot.relationships ?? []) model.relationships.set(`${relationship.from}|${relationship.type}|${relationship.to}`, relationship)
    for (const observation of snapshot.observations ?? []) model.observations.set(observation.id, observation)
    for (const capability of snapshot.capabilities ?? []) model.capabilities.set(capability.id, capability)
    for (const objective of snapshot.objectives ?? []) model.objectives.set(objective.id, objective)
    return model
  }
}

export default SecurityWorldModel
