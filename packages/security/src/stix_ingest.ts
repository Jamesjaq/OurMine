/**
 * @module stix_ingest
 * STIX 2.1 / TAXII 2.1 threat intel ingestion.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import type { IntelRecord } from "./intel_feeds.ts"

export interface StixObject {
  type: string
  id: string
  name?: string
  description?: string
  pattern?: string
  created?: string
  modified?: string
  external_references?: Array<{ source_name?: string; external_id?: string; url?: string }>
}

export interface StixBundle {
  type: "bundle"
  id: string
  objects: StixObject[]
}

const CACHE_DIR = path.join(process.cwd(), ".ourmine", "intel", "stix")

export function parseStixBundle(raw: string | StixBundle): StixObject[] {
  const bundle = typeof raw === "string" ? JSON.parse(raw) as StixBundle : raw
  return bundle.objects ?? []
}

export function stixToIntelRecords(objects: StixObject[]): IntelRecord[] {
  const records: IntelRecord[] = []
  for (const obj of objects) {
    if (obj.type === "indicator" && obj.pattern) {
      const cve = obj.pattern.match(/CVE-\d{4}-\d+/i)?.[0]
      records.push({
        source: "stix_indicator",
        type: cve ? "cve" : "ioc",
        cve: cve ?? undefined,
        ioc: obj.pattern.slice(0, 200),
        timestamp: obj.modified ?? obj.created ?? new Date().toISOString(),
        confidence: "medium",
        rawRef: obj.id,
      })
    }
    if (obj.type === "intrusion-set" || obj.type === "threat-actor") {
      records.push({
        source: "stix_actor",
        type: "actor",
        actor: obj.name ?? obj.id,
        timestamp: obj.modified ?? new Date().toISOString(),
        confidence: "high",
        rawRef: obj.id,
      })
    }
    if (obj.type === "malware") {
      records.push({
        source: "stix_malware",
        type: "family",
        family: obj.name ?? obj.id,
        timestamp: obj.modified ?? new Date().toISOString(),
        confidence: "medium",
        rawRef: obj.id,
      })
    }
  }
  return records
}

export async function fetchTaxiiCollection(
  baseUrl: string,
  collectionId: string,
  opts: { apiKey?: string; limit?: number } = {},
): Promise<StixObject[]> {
  const url = `${baseUrl.replace(/\/$/, "")}/collections/${collectionId}/objects/?limit=${opts.limit ?? 100}`
  const headers: Record<string, string> = { Accept: "application/vnd.oasis.stix+json; version=2.1" }
  if (opts.apiKey) headers.Authorization = `Bearer ${opts.apiKey}`

  const res = await fetch(url, { headers, signal: AbortSignal.timeout(30000) })
  if (!res.ok) throw new Error(`TAXII fetch failed: ${res.status}`)
  const data = (await res.json()) as { objects?: StixObject[] }
  const objects = data.objects ?? []

  fs.mkdirSync(CACHE_DIR, { recursive: true })
  fs.writeFileSync(path.join(CACHE_DIR, `${collectionId}_${Date.now()}.json`), JSON.stringify(objects, null, 2))
  return objects
}

export function matchStixOnGraph(graph: AttackSurfaceGraph, records: IntelRecord[]): string[] {
  const hits: string[] = []
  const summary = graph.summary()
  const target = (summary.target ?? "").toLowerCase()

  for (const r of records) {
    const ioc = (r.ioc ?? r.cve ?? r.family ?? r.actor ?? "").toLowerCase()
    if (!ioc) continue
    if (target.includes(ioc) || ioc.includes(target.split(".")[0] ?? "")) {
      hits.push(`stix:${r.source}:${ioc}`)
      const asset = graph.upsertAsset(summary.target)
      asset.notes.push(`[STIX] ${r.type}: ${ioc}`)
    }
  }
  return hits
}

export async function ingestTaxiiFeed(
  baseUrl: string,
  collectionId: string,
  graph: AttackSurfaceGraph,
  opts: { apiKey?: string } = {},
): Promise<{ records: IntelRecord[]; hits: string[] }> {
  const objects = await fetchTaxiiCollection(baseUrl, collectionId, opts)
  const records = stixToIntelRecords(objects)
  const hits = matchStixOnGraph(graph, records)
  return { records, hits }
}

export default { parseStixBundle, stixToIntelRecords, fetchTaxiiCollection, matchStixOnGraph, ingestTaxiiFeed }
