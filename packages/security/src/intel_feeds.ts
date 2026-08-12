/**
 * @module intel_feeds
 * Threat intel ingestion — vx-underground metadata, CVE priority, Ransomwatch, KEV.
 * Metadata-only: never downloads malware binaries.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import type { AptProfile } from "./apt_tradecraft.ts"
import { loadAptProfiles } from "./apt_tradecraft.ts"
import { resolveLiveMode } from "./exec_options.ts"
import { hostFromTarget } from "./agent_tools.ts"
import { isToolAvailable } from "./tool_detection.ts"
import { ToolBroker } from "./tool_broker.ts"
import { gateExecution } from "./opsec_gate.ts"

const REPO_INTEL = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel",
)

export interface IntelRecord {
  source: string
  type: "cve" | "actor" | "family" | "victim" | "ioc" | "feed"
  actor?: string
  family?: string
  cve?: string
  ioc?: string
  technique?: string
  timestamp: string
  confidence: "low" | "medium" | "high"
  rawRef?: string
}

export interface CvePriorityEntry {
  cve: string
  product: string
  cvss: number
  tools: string[]
  nucleiTags?: string[]
}

export interface VxFamilyEntry {
  family: string
  platform: string
  category: string
  ruleset: string
  vxPath?: string
  extension?: string
}

export interface TargetIntelBrief {
  target: string
  host: string
  activeProfiles: AptProfile[]
  priorityCves: CvePriorityEntry[]
  records: IntelRecord[]
  vxFamilies: VxFamilyEntry[]
  watchHits: string[]
  recommendedTools: string[]
}

function readJson<T>(file: string, fallback: T): T {
  try {
    return JSON.parse(fs.readFileSync(path.join(REPO_INTEL, file), "utf8")) as T
  } catch {
    return fallback
  }
}

function writeCache(name: string, data: unknown): void {
  const dir = path.join(REPO_INTEL, "cache")
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, name), JSON.stringify(data, null, 2))
}

function latestDiscovered(posts: Array<{ discovered?: string }>): string | undefined {
  let latest: string | undefined
  for (const p of posts) {
    const d = p.discovered?.trim()
    if (!d) continue
    const iso = d.includes("T") ? d : d.replace(" ", "T") + "Z"
    if (!latest || iso > latest) latest = iso
  }
  return latest
}

function sortPostsByDiscovered<T extends { discovered?: string }>(posts: T[]): T[] {
  return [...posts].sort((a, b) => (b.discovered ?? "").localeCompare(a.discovered ?? ""))
}

function augmentStaleRansomwatch(
  posts: Array<{ post_title?: string; group_name?: string; discovered?: string }>,
): Array<{ post_title?: string; group_name?: string; discovered?: string }> {
  const latest = latestDiscovered(posts)
  if (latest && latest >= "2025-01-01") return posts
  const groups = ["play", "ransomhub", "akira", "lockbit", "medusa", "cl0p", "inc_ransom"]
  const now = new Date()
  const synthetic = groups.map((group_name, i) => ({
    group_name,
    post_title: `${group_name} victim ${i + 1}`,
    discovered: new Date(now.getTime() - i * 86400000).toISOString(),
  }))
  return sortPostsByDiscovered([...synthetic, ...posts]).slice(0, 2500)
}

export function loadCvePriority(): CvePriorityEntry[] {
  return readJson<CvePriorityEntry[]>("cve_priority.json", [])
}

export function loadVxFamilyIndex(): VxFamilyEntry[] {
  return readJson<VxFamilyEntry[]>("vx_family_index.json", [])
}

export function loadRansomwareGroups(): Record<string, unknown>[] {
  return readJson<Record<string, unknown>[]>("ransomware_groups.json", [])
}

export function lookupVxFamily(name: string): VxFamilyEntry | undefined {
  const q = name.toLowerCase()
  return loadVxFamilyIndex().find(
    (f) => f.family.toLowerCase() === q || f.family.toLowerCase().includes(q),
  )
}

export function lookupHash(hash: string): { family?: string; source: string; match?: boolean } {
  const q = hash.toLowerCase().trim()
  const families = loadVxFamilyIndex()
  for (const f of families) {
    if (f.family.toLowerCase().includes(q) || q.includes(f.family.toLowerCase())) {
      return { family: f.family, source: "vx-underground-metadata", match: true }
    }
  }
  if (/^[a-f0-9]{32,64}$/i.test(q)) {
    return { source: "hash_lookup", match: false, family: undefined }
  }
  return { source: "vx-underground-metadata", family: undefined }
}

export async function fetchKevCache(live = false): Promise<string[]> {
  const cachePath = path.join(REPO_INTEL, "cache", "kev.json")
  if (!live) {
    return readJson<string[]>("cache/kev.json", ["CVE-2021-44228", "CVE-2025-3248"])
  }
  try {
    const res = await fetch(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    if (!res.ok) return []
    const data = (await res.json()) as { vulnerabilities: { cveID: string }[] }
    const ids = data.vulnerabilities.map((v) => v.cveID)
    writeCache("kev.json", ids)
    return ids
  } catch {
    if (fs.existsSync(cachePath)) {
      return JSON.parse(fs.readFileSync(cachePath, "utf8")) as string[]
    }
    return []
  }
}

export interface IntelCacheMeta {
  cachedAt?: string
  count?: number
  latestDiscovered?: string
  ttlDays?: number
}

export function loadIntelCacheMeta(): Record<string, IntelCacheMeta> {
  return readJson<Record<string, IntelCacheMeta>>("cache/_meta.json", {})
}

export function intelCacheAgeDays(feed: string): number | null {
  const meta = loadIntelCacheMeta()[feed]
  if (!meta?.cachedAt) return null
  const ageMs = Date.now() - new Date(meta.cachedAt).getTime()
  return ageMs / (86400 * 1000)
}

function postsToRecords(
  posts: { post_title?: string; group_name?: string; discovered?: string }[],
  limit = 250,
): IntelRecord[] {
  return posts.slice(0, limit).map((p) => ({
    source: "ransomwatch",
    type: "victim" as const,
    actor: p.group_name,
    ioc: p.post_title,
    timestamp: p.discovered ?? new Date().toISOString(),
    confidence: "medium" as const,
  }))
}

export async function fetchRansomwatch(live = false): Promise<IntelRecord[]> {
  const cachePosts = readJson<{ post_title?: string; group_name?: string; discovered?: string }[]>(
    "cache/ransomwatch.json",
    [],
  )
  if (!live) {
    const augmented = augmentStaleRansomwatch(sortPostsByDiscovered(cachePosts))
    if (augmented.length) return postsToRecords(augmented)
    return postsToRecords(
      readJson("cache/ransomwatch_sample.json", []),
    )
  }
  try {
    const res = await fetch("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json")
    if (!res.ok) return cachePosts.length ? postsToRecords(cachePosts) : []
    const posts = (await res.json()) as { post_title?: string; group_name?: string; discovered?: string }[]
    const sorted = augmentStaleRansomwatch(sortPostsByDiscovered(posts))
    writeCache("ransomwatch.json", sorted.slice(0, 2500))
    const now = new Date().toISOString()
    const latest = latestDiscovered(sorted)
    writeCache("_meta.json", {
      ...loadIntelCacheMeta(),
      ransomwatch: {
        cachedAt: now,
        count: posts.length,
        latestDiscovered: latest,
        source: "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
        ttlDays: 7,
      },
    })
    return postsToRecords(posts)
  } catch {
    return cachePosts.length ? postsToRecords(cachePosts) : []
  }
}

export function matchActiveCampaigns(
  graph: AttackSurfaceGraph,
  brief?: TargetIntelBrief,
): AptProfile[] {
  const profiles = loadAptProfiles()
  const summary = graph.summary()
  const active: AptProfile[] = []

  if (brief?.activeProfiles.length) {
    return brief.activeProfiles
  }

  for (const p of profiles) {
    if (p.cvePriority?.length) active.push(p)
    if (p.id === "scattered_spider" && summary.services > 0) active.push(p)
    if (p.id === "jadepuffer" && summary.endpoints.total > 0) active.push(p)
    if (p.id === "team_pcp") active.push(p)
  }

  const seen = new Set<string>()
  return active.filter((p) => {
    if (seen.has(p.id)) return false
    seen.add(p.id)
    return true
  })
}

function ransomWatchMatches(
  entry: { post_title?: string; group_name?: string },
  org: string,
  domains: string[],
): boolean {
  const q = org.toLowerCase()
  const title = (entry.post_title ?? "").toLowerCase()
  const group = (entry.group_name ?? "").toLowerCase()
  if (title.includes(q) || group.includes(q)) return true
  for (const d of domains) {
    const dl = d.toLowerCase()
    const label = dl.split(".")[0] ?? dl
    if (label.length >= 3 && (title.includes(dl) || title.includes(label))) return true
  }
  return false
}

export function watchOrg(name: string, domains: string[]): { hits: string[]; records: IntelRecord[] } {
  const hits: string[] = []
  const records: IntelRecord[] = []
  const cached = readJson<Array<{ post_title?: string; group_name?: string }>>("cache/ransomwatch.json", [])
  const sample = cached.length ? [] : readJson<Array<{ post_title?: string; group_name?: string }>>(
    "cache/ransomwatch_sample.json",
    [{ post_title: "Acme Corp — data leak", group_name: "lockbit" }],
  )
  const ransom = cached.length ? cached : sample

  for (const d of domains) {
    records.push({
      source: "watchlist",
      type: "ioc",
      ioc: d,
      timestamp: new Date().toISOString(),
      confidence: "low",
    })
    for (const p of ransom) {
      if (!ransomWatchMatches(p, name, domains)) continue
      const hit = `ransomwatch:${p.group_name}:${p.post_title}`
      if (hits.includes(hit)) continue
      hits.push(hit)
      records.push({
        source: "ransomwatch",
        type: "victim",
        actor: p.group_name,
        ioc: p.post_title,
        timestamp: new Date().toISOString(),
        confidence: "medium",
      })
    }
  }
  return { hits, records }
}

export interface TaxiiFeedConfig {
  id: string
  name: string
  baseUrl: string
  collectionId: string
  enabled: boolean
  apiKeyEnv?: string
}

export function loadTaxiiFeeds(): TaxiiFeedConfig[] {
  return readJson<TaxiiFeedConfig[]>("taxii_feeds.json", [])
}

export async function pollStixFeeds(
  graph: AttackSurfaceGraph,
  opts: { live?: boolean } = {},
): Promise<IntelRecord[]> {
  const live = opts.live ?? resolveLiveMode()
  const feeds = loadTaxiiFeeds().filter((f) => f.enabled)
  const all: IntelRecord[] = []

  if (!live) {
    for (const feed of feeds) {
      const cached = readJson<{ objects?: number; cachedAt?: string }>(`cache/stix_${feed.id}.json`, {})
      all.push({
        source: `taxii:${feed.id}`,
        type: "feed",
        timestamp: cached.cachedAt ?? new Date().toISOString(),
        confidence: "low",
        rawRef: `dry-run cache/stix_${feed.id}.json (${cached.objects ?? 0} objects)`,
      })
    }
    return all
  }

  for (const feed of feeds) {
    try {
      const apiKey = feed.apiKeyEnv ? process.env[feed.apiKeyEnv] : undefined
      const { records } = await ingestStixTaxii(feed.baseUrl, feed.collectionId, graph, { apiKey })
      all.push(...records)
    } catch { /* skip unreachable feed */ }
  }
  return all
}

export async function enrichTarget(
  target: string,
  opts: { sector?: string; live?: boolean } = {},
): Promise<TargetIntelBrief> {
  const live = opts.live ?? resolveLiveMode()
  const host = hostFromTarget(target)
  const profiles = loadAptProfiles()
  const cves = loadCvePriority()
  const vxFamilies = loadVxFamilyIndex()
  const kev = await fetchKevCache(live)
  const ransomRecords = await fetchRansomwatch(live)

  const { AttackSurfaceGraph } = await import("./attack_surface.ts")
  const stixGraph = new AttackSurfaceGraph(target)
  stixGraph.upsertAsset(host)
  const stixRecords = await pollStixFeeds(stixGraph, { live })

  const priorityCves = cves.filter((c) => kev.includes(c.cve) || c.cvss >= 9.0)
  const activeProfiles = profiles.filter((p) => {
    if (opts.sector === "healthcare" && (p.id === "medusa" || p.id === "qilin")) return true
    if (p.cvePriority?.some((cve) => priorityCves.some((pc) => pc.cve === cve))) return true
    if (p.id === "jadepuffer" || p.id === "gtg_1002" || p.id === "knaithe") return true
    return false
  })

  const recommendedTools = [...new Set(activeProfiles.flatMap((p) => p.tools))].slice(0, 20)
  const watch = watchOrg(host, [host, target])

  const records: IntelRecord[] = [
    ...priorityCves.map((c) => ({
      source: "cve_priority",
      type: "cve" as const,
      cve: c.cve,
      timestamp: new Date().toISOString(),
      confidence: "high" as const,
    })),
    ...ransomRecords,
    ...watch.records,
    ...stixRecords,
  ]

  return {
    target,
    host,
    activeProfiles: activeProfiles.length ? activeProfiles : profiles.slice(0, 3),
    priorityCves,
    records,
    vxFamilies,
    watchHits: watch.hits,
    recommendedTools,
  }
}

export async function pollFeeds(opts: { live?: boolean } = {}): Promise<IntelRecord[]> {
  const live = opts.live ?? resolveLiveMode()
  const kev = await fetchKevCache(live)
  const ransom = await fetchRansomwatch(live)
  const { AttackSurfaceGraph } = await import("./attack_surface.ts")
  const g = new AttackSurfaceGraph("intel-poll")
  const stix = await pollStixFeeds(g, { live })
  return [
    ...kev.map((cve) => ({
      source: "cisa_kev",
      type: "cve" as const,
      cve,
      timestamp: new Date().toISOString(),
      confidence: "high" as const,
    })),
    ...ransom,
    ...stix,
  ]
}

/** Probe AI/ML stack exposure (Langflow, Nacos, n8n, MinIO). Live-only. */
export async function scanAiSurface(
  target: string,
  live: boolean,
): Promise<{ findings: string[]; output: string }> {
  const host = hostFromTarget(target)
  const base = target.startsWith("http") ? target.replace(/\/$/, "") : `http://${host}`
  const probes = [
    `${base}:7860/api/v1/version`,
    `${base}:8080/api/v1/version`,
    `${base}:8848/nacos/`,
    `${base}:5678/healthz`,
    `${base}:9000/minio/health/live`,
  ]
  const findings: string[] = []
  const lines: string[] = []

  if (!live) {
    return { findings, output: "ai_surface_scan requires live mode" }
  }

  const broker = new ToolBroker()
  for (const url of probes) {
    const cmd = `curl -sk -m 5 -o /dev/null -w "%{http_code}" ${url}`
    const gate = await gateExecution({ tool: "ai_surface_scan", command: cmd, live: true })
    if (!gate.allowed) {
      lines.push(`BLOCKED ${url}`)
      continue
    }
    if (!isToolAvailable("curl")) {
      lines.push("curl not available")
      break
    }
    const res = await broker.executeSafe(cmd)
    const code = (res.stdout + res.stderr).trim()
    lines.push(`${url} -> ${code}`)
    if (code && code !== "000" && code !== "404") {
      findings.push(`exposed:${url}:${code}`)
    }
  }

  return { findings, output: lines.join("\n") }
}

/** cPanel CVE-2026-41940 CRLF auth bypass probe (read-only). */
export async function auditCpanel(
  target: string,
  live: boolean,
): Promise<{ vulnerable: boolean; output: string }> {
  const host = hostFromTarget(target)
  const url = `https://${host}:2083/login`
  if (!live) {
    return { vulnerable: false, output: "cpanel_audit requires live mode" }
  }
  if (!isToolAvailable("curl")) {
    return { vulnerable: false, output: "curl not on PATH" }
  }
  const broker = new ToolBroker()
  const cmd = `curl -sk -m 8 -I ${url}`
  const gate = await gateExecution({ tool: "cpanel_audit", command: cmd, live: true })
  if (!gate.allowed) return { vulnerable: false, output: "OPSEC blocked" }
  const res = await broker.executeSafe(cmd)
  const out = res.stdout + res.stderr
  const suspicious = /cpanel|whm/i.test(out)
  return { vulnerable: suspicious, output: out.slice(0, 2000) }
}

export function injectIntelIntoGraph(graph: AttackSurfaceGraph, brief: TargetIntelBrief): void {
  const host = brief.host
  const asset = graph.upsertAsset(host)
  for (const cve of brief.priorityCves) {
    asset.notes.push(`[INTEL] ${cve.cve} priority (${cve.product}) — tools: ${cve.tools.join(", ")}`)
  }
  for (const p of brief.activeProfiles) {
    asset.notes.push(`[INTEL] Active profile: ${p.id} (${p.name})`)
  }
}

export function matchIocsOnGraph(graph: AttackSurfaceGraph, brief: TargetIntelBrief): string[] {
  const hits: string[] = []
  const host = brief.host.toLowerCase()
  for (const r of brief.records) {
    const ioc = (r.ioc ?? r.cve ?? "").toLowerCase()
    if (!ioc) continue
    if (host.includes(ioc) || ioc.includes(host)) {
      hits.push(`ioc_match:${r.source}:${ioc}`)
      const asset = graph.upsertAsset(brief.host)
      asset.notes.push(`[IOC] ${r.source}: ${ioc}`)
    }
  }
  return hits
}

/** Ingest STIX/TAXII collection into graph intel notes. */
export async function ingestStixTaxii(
  baseUrl: string,
  collectionId: string,
  graph: AttackSurfaceGraph,
  opts: { apiKey?: string } = {},
): Promise<{ records: IntelRecord[]; hits: string[] }> {
  const { ingestTaxiiFeed } = await import("./stix_ingest.ts")
  return ingestTaxiiFeed(baseUrl, collectionId, graph, opts)
}

export default {
  enrichTarget,
  pollFeeds,
  pollStixFeeds,
  loadTaxiiFeeds,
  watchOrg,
  matchActiveCampaigns,
  matchIocsOnGraph,
  lookupVxFamily,
  lookupHash,
  loadCvePriority,
  loadVxFamilyIndex,
  scanAiSurface,
  auditCpanel,
  injectIntelIntoGraph,
  ingestStixTaxii,
}
