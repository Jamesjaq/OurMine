/**
 * @module passive_intel
 * Cached Shodan/Censys passive recon — live API calls when keys present.
 * Enable with OURMINE_PASSIVE_INTEL=1.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import { writeArtifact } from "./mcp_artifacts.ts"
import { isBattleReady, resolveLiveMode } from "./exec_options.ts"

export interface PassiveIntelHit {
  source: "shodan" | "censys" | "cache"
  ip?: string
  port?: number
  service?: string
  banner?: string
  cve?: string
  tags?: string[]
}

export interface PassiveIntelResult {
  target: string
  enabled: boolean
  dryRun: boolean
  hits: PassiveIntelHit[]
  summary: string
  artifactId?: string
  cachedAt: string
  sources?: string[]
  error?: string
}

const CACHE_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel/cache",
)

const SHODAN_HOST_RE = /^\d+\.\d+\.\d+\.\d+$/

export function isPassiveIntelEnabled(): boolean {
  const v = process.env.OURMINE_PASSIVE_INTEL?.trim().toLowerCase()
  if (v === "0" || v === "false" || v === "no") return false
  if (v === "1" || v === "true" || v === "yes") return true
  if (hasShodanKey() || hasCensysKeys()) return true
  if (isBattleReady()) return true
  return false
}

function cachePath(target: string): string {
  const safe = target.replace(/[^a-zA-Z0-9._-]/g, "_")
  return path.join(CACHE_DIR, `passive_${safe}.json`)
}

function readCache(target: string): PassiveIntelHit[] | null {
  const fp = cachePath(target)
  if (!fs.existsSync(fp)) return null
  try {
    const data = JSON.parse(fs.readFileSync(fp, "utf8")) as { hits?: PassiveIntelHit[] }
    return data.hits ?? null
  } catch {
    return null
  }
}

function writeCache(target: string, hits: PassiveIntelHit[]): void {
  fs.mkdirSync(CACHE_DIR, { recursive: true })
  fs.writeFileSync(cachePath(target), JSON.stringify({ hits, cachedAt: new Date().toISOString() }, null, 2))
}

function normalizeHost(target: string): string {
  return target.replace(/^https?:\/\//, "").split("/")[0]?.split(":")[0] ?? target
}

function hasShodanKey(): boolean {
  return Boolean(process.env.SHODAN_API_KEY)
}

function hasCensysKeys(): boolean {
  return Boolean(process.env.CENSYS_API_ID && process.env.CENSYS_API_SECRET)
}

function censysAuthHeader(): string {
  const id = process.env.CENSYS_API_ID ?? ""
  const secret = process.env.CENSYS_API_SECRET ?? ""
  return `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`
}

/** Fetch Shodan host or DNS domain records. */
export async function fetchShodan(target: string): Promise<PassiveIntelHit[]> {
  const apiKey = process.env.SHODAN_API_KEY
  if (!apiKey) return []

  const host = normalizeHost(target)
  const hits: PassiveIntelHit[] = []

  if (SHODAN_HOST_RE.test(host)) {
    const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(host)}?key=${encodeURIComponent(apiKey)}`
    const resp = await fetch(url, { signal: AbortSignal.timeout(15_000) })
    if (!resp.ok) {
      throw new Error(`Shodan host API HTTP ${resp.status}`)
    }
    const data = (await resp.json()) as {
      ip_str?: string
      data?: Array<{ port?: number; product?: string; transport?: string; data?: string; vulns?: string[] }>
      vulns?: string[]
    }
    for (const svc of data.data ?? []) {
      hits.push({
        source: "shodan",
        ip: data.ip_str ?? host,
        port: svc.port,
        service: svc.product ?? svc.transport ?? "unknown",
        banner: typeof svc.data === "string" ? svc.data.slice(0, 500) : undefined,
        cve: svc.vulns?.[0] ?? data.vulns?.[0],
        tags: ["shodan-live"],
      })
    }
    if (!hits.length && data.ip_str) {
      hits.push({
        source: "shodan",
        ip: data.ip_str,
        service: "host",
        banner: "Shodan host record (no open ports in response)",
        tags: ["shodan-live"],
      })
    }
    return hits
  }

  const url = `https://api.shodan.io/dns/domain/${encodeURIComponent(host)}?key=${encodeURIComponent(apiKey)}`
  const resp = await fetch(url, { signal: AbortSignal.timeout(15_000) })
  if (!resp.ok) {
    throw new Error(`Shodan DNS API HTTP ${resp.status}`)
  }
  const data = (await resp.json()) as {
    subdomains?: string[]
    data?: Array<{ subdomain?: string; type?: string; value?: string }>
  }
  for (const rec of data.data ?? []) {
    hits.push({
      source: "shodan",
      service: rec.type ?? "dns",
      banner: `${rec.subdomain ?? host}.${host} → ${rec.value ?? ""}`.slice(0, 500),
      tags: ["shodan-live", "dns"],
    })
  }
  if (!hits.length && (data.subdomains?.length ?? 0) > 0) {
    hits.push({
      source: "shodan",
      service: "dns",
      banner: `Subdomains: ${(data.subdomains ?? []).slice(0, 10).join(", ")}`,
      tags: ["shodan-live", "dns"],
    })
  }
  return hits
}

/** Fetch Censys host search results. */
export async function fetchCensys(target: string): Promise<PassiveIntelHit[]> {
  if (!hasCensysKeys()) return []

  const host = normalizeHost(target)
  const query = SHODAN_HOST_RE.test(host) ? `ip:${host}` : `dns.names: ${host}`
  const resp = await fetch("https://search.censys.io/api/v2/hosts/search", {
    method: "POST",
    headers: {
      Authorization: censysAuthHeader(),
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ q: query, per_page: 25 }),
    signal: AbortSignal.timeout(20_000),
  })
  if (!resp.ok) {
    throw new Error(`Censys search API HTTP ${resp.status}`)
  }
  const data = (await resp.json()) as {
    result?: {
      hits?: Array<{
        ip?: string
        services?: Array<{ port?: number; service_name?: string; banner?: string }>
      }>
    }
  }

  const hits: PassiveIntelHit[] = []
  for (const hit of data.result?.hits ?? []) {
    for (const svc of hit.services ?? []) {
      hits.push({
        source: "censys",
        ip: hit.ip,
        port: svc.port,
        service: svc.service_name ?? "unknown",
        banner: typeof svc.banner === "string" ? svc.banner.slice(0, 500) : undefined,
        tags: ["censys-live"],
      })
    }
    if (!(hit.services?.length) && hit.ip) {
      hits.push({
        source: "censys",
        ip: hit.ip,
        service: "host",
        tags: ["censys-live"],
      })
    }
  }
  return hits
}

async function fetchLiveHits(target: string): Promise<{ hits: PassiveIntelHit[]; sources: string[]; error?: string }> {
  const hits: PassiveIntelHit[] = []
  const sources: string[] = []
  const errors: string[] = []

  if (hasShodanKey()) {
    try {
      const shodanHits = await fetchShodan(target)
      hits.push(...shodanHits)
      sources.push("shodan")
    } catch (e) {
      errors.push(`shodan: ${String(e)}`)
    }
  }

  if (hasCensysKeys()) {
    try {
      const censysHits = await fetchCensys(target)
      hits.push(...censysHits)
      sources.push("censys")
    } catch (e) {
      errors.push(`censys: ${String(e)}`)
    }
  }

  return {
    hits,
    sources,
    error: errors.length ? errors.join("; ") : undefined,
  }
}

/** Run passive intel lookup — cache-first; live APIs when keys + live mode. */
export async function runPassiveIntel(
  target: string,
  opts: { live?: boolean; forceRefresh?: boolean } = {},
): Promise<PassiveIntelResult> {
  const enabled = isPassiveIntelEnabled()
  const live = opts.live ?? resolveLiveMode()
  const dryRun = !live
  const cachedAt = new Date().toISOString()

  if (!enabled) {
    return {
      target,
      enabled: false,
      dryRun: true,
      hits: [],
      summary: "passive intel disabled — set OURMINE_PASSIVE_INTEL=1",
      cachedAt,
    }
  }

  const hasKeys = hasShodanKey() || hasCensysKeys()

  if (!opts.forceRefresh) {
    const cached = readCache(target)
    if (cached?.length) {
      const tagged = cached.map((h) => ({ ...h, source: h.source === "cache" ? "cache" as const : h.source }))
      const summary = `${tagged.length} cached passive hit(s) for ${target}${dryRun ? " (dry-run)" : ""}`
      const artifactId = writeArtifact("passive_intel", { target, hits: tagged, summary, cachedAt })
      return {
        target,
        enabled: true,
        dryRun,
        hits: tagged,
        summary,
        artifactId,
        cachedAt,
        sources: ["cache"],
      }
    }
  }

  if (hasKeys && live) {
    const { hits, sources, error } = await fetchLiveHits(target)
    writeCache(target, hits)
    const summary = hits.length
      ? `${hits.length} live passive hit(s) for ${target} via ${sources.join("+")}`
      : `no passive hits for ${target}${error ? ` (${error})` : ""}`
    const artifactId = writeArtifact("passive_intel", { target, hits, summary, cachedAt, sources, error })
    return {
      target,
      enabled: true,
      dryRun: false,
      hits,
      summary,
      artifactId,
      cachedAt,
      sources,
      error,
    }
  }

  if (hasKeys && dryRun) {
    const summary = `passive intel dry-run for ${target} — pass live:true to query ${hasShodanKey() ? "Shodan" : ""}${hasShodanKey() && hasCensysKeys() ? "+" : ""}${hasCensysKeys() ? "Censys" : ""}`
    return {
      target,
      enabled: true,
      dryRun: true,
      hits: [],
      summary,
      cachedAt,
      sources: [],
    }
  }

  const summary = `no passive intel cache for ${target} — set SHODAN_API_KEY or CENSYS_API_ID/CENSYS_API_SECRET for live lookup`
  return {
    target,
    enabled: true,
    dryRun,
    hits: [],
    summary,
    cachedAt,
    sources: [],
  }
}

export default { isPassiveIntelEnabled, runPassiveIntel, fetchShodan, fetchCensys }
