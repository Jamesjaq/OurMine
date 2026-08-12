/**
 * @module apt_intel_feed
 * APT/HACKER intelligence pipeline — MITRE ATT&CK + KEV + ransomwatch + APT playbooks.
 * Default path uses repo + .ourmine/intel cache; optional live refresh.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import type { FlowObjective, TargetPersona } from "./target_flow.ts"
import { detectInstitutionalSector, aptProfileIdForSector, type InstitutionalSector } from "./institutional_hints.ts"
import {
  detectOtVertical,
  aptPlaybookForVertical,
  type OtVertical,
} from "./ot_verticals.ts"
import { loadAptProfiles, type AptProfile } from "./apt_tradecraft.ts"
import { buildPlaybookFromProfile, type PlaybookGraph } from "./apt_playbook.ts"
import { fetchKevCache, fetchRansomwatch, loadRansomwareGroups } from "./intel_feeds.ts"
import { writeArtifact } from "./mcp_artifacts.ts"
import { isExecutableModule } from "./module_registry.ts"

const REPO_INTEL = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel",
)

const CACHE_DIR = path.resolve(process.cwd(), ".ourmine/intel")

export interface MitreTechnique {
  id: string
  name: string
  domain: "enterprise" | "ics"
  modules: string[]
}

export interface AptPlaybookMapping {
  objectiveHint: FlowObjective
  techniqueChain: string[]
  modules: string[]
  intelSnippetTemplate?: string
  cloudNative?: boolean
  endpointMalware?: boolean
  pairedOps?: { iab?: string; ot_mapping?: string }
}

export interface TechniqueRef {
  id: string
  name: string
  domain: "enterprise" | "ics"
  modules: string[]
}

export interface AptIntelBundle {
  profileId: string
  profileName: string
  objectiveHint: FlowObjective
  persona?: TargetPersona
  techniques: TechniqueRef[]
  modules: string[]
  kevHits: string[]
  ransomGroups: string[]
  playbook: PlaybookGraph
  cachedAt: string
}

export interface ThreatIntelResult {
  intelSnippet: string
  artifactId: string
  profileId: string
  profileName: string
  objectiveHint: FlowObjective
  techniques: TechniqueRef[]
  modules: string[]
  kevCount: number
  ransomGroupCount: number
}

function readJson<T>(file: string, fallback: T): T {
  try {
    return JSON.parse(fs.readFileSync(path.join(REPO_INTEL, file), "utf8")) as T
  } catch {
    return fallback
  }
}

function ensureIntelCacheDir(): string {
  fs.mkdirSync(CACHE_DIR, { recursive: true })
  return CACHE_DIR
}

function normalizeQuery(q: string): string {
  return q.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "")
}

/** Resolve APT profile by id, name, or alias (e.g. "Volt Typhoon" → volt_typhoon). */
export function resolveAptProfile(query?: string): AptProfile | null {
  if (!query?.trim()) return null
  const profiles = loadAptProfiles()
  const q = query.trim().toLowerCase()
  const norm = normalizeQuery(query)

  return profiles.find((p) => {
    if (p.id === norm || p.id === q) return true
    if (p.name.toLowerCase() === q) return true
    if (p.aliases.some((a) => a.toLowerCase() === q || normalizeQuery(a) === norm)) return true
    if (p.name.toLowerCase().includes(q) || q.includes(p.name.toLowerCase())) return true
    if (p.aliases.some((a) => a.toLowerCase().includes(q) || q.includes(a.toLowerCase()))) return true
    return false
  }) ?? null
}

export function loadMitreTechniques(): MitreTechnique[] {
  return readJson<MitreTechnique[]>("mitre_techniques.json", [])
}

export function loadAptPlaybookMappings(): Record<string, AptPlaybookMapping> {
  return readJson<Record<string, AptPlaybookMapping>>("apt_playbook_modules.json", {})
}

function lookupTechnique(id: string, catalog: MitreTechnique[]): TechniqueRef | null {
  const hit = catalog.find((t) => t.id === id || t.id.startsWith(id))
  if (!hit) {
    const num = parseInt(id.slice(1), 10)
    const domain: "enterprise" | "ics" = !Number.isNaN(num) && num >= 800 ? "ics" : "enterprise"
    return { id, name: id, domain, modules: [] }
  }
  const modules = hit.modules.filter((m) => isExecutableModule(m))
  return { id: hit.id, name: hit.name, domain: hit.domain, modules }
}

/** Infer objective from APT actor name when explicit hint absent. */
export function objectiveFromAptName(query?: string): FlowObjective | null {
  const profile = resolveAptProfile(query ?? "")
  if (!profile) return null
  const mappings = loadAptPlaybookMappings()
  if (mappings[profile.id]?.objectiveHint) return mappings[profile.id]!.objectiveHint
  if (profile.id === "volt_typhoon") return "hybrid_it_ot"
  if (profile.id === "sandworm" || profile.id === "xenotime") return "ot_ics"
  if (profile.id === "salt_typhoon") return "telecom"
  if (profile.id === "lazarus" || profile.id === "apt38" || profile.id === "unc4899") return "supply_chain"
  if (profile.id === "scattered_spider") return "identity_first"
  if (profile.id === "apt29" || profile.id === "shinyhunters") return "identity_first"
  if (profile.id === "fin7" || profile.id === "alphv_blackcat") return "ransomware_impact"
  if (profile.id === "medusa" || profile.focus.includes("backup_discovery")) return "ransomware_impact"
  if (profile.focus.some((f) => f.includes("ot") || f.includes("critical_infrastructure"))) return "hybrid_it_ot"
  if (profile.focus.some((f) => f.includes("telecom"))) return "telecom"
  return null
}

function pickTechniqueIds(profile: AptProfile, count = 5): string[] {
  const mappings = loadAptPlaybookMappings()
  const mapped = mappings[profile.id]?.techniqueChain ?? []
  const merged = [...mapped, ...profile.techniques]
  const seen = new Set<string>()
  const out: string[] = []
  for (const t of merged) {
    if (seen.has(t)) continue
    seen.add(t)
    out.push(t)
    if (out.length >= count) break
  }
  return out
}

function mergeModules(profile: AptProfile, techniques: TechniqueRef[]): string[] {
  const mappings = loadAptPlaybookMappings()
  const fromMap = mappings[profile.id]?.modules ?? []
  const fromProfile = profile.tools
  const fromTech = techniques.flatMap((t) => t.modules)
  const seen = new Set<string>()
  return [...fromMap, ...fromProfile, ...fromTech].filter((m) => {
    if (seen.has(m)) return false
    seen.add(m)
    return true
  })
}

export function formatIntelSnippet(
  profile: AptProfile,
  techniques: TechniqueRef[],
  objectiveHint?: FlowObjective,
): string {
  const mappings = loadAptPlaybookMappings()
  const mapping = mappings[profile.id]
  const techStr = techniques.slice(0, 3).map((t) => t.id).join("→")
  const modStr = mergeModules(profile, techniques).slice(0, 3).join(", ")

  let snippet: string
  if (mapping?.intelSnippetTemplate) {
    snippet = mapping.intelSnippetTemplate
      .replace("{name}", profile.name)
      .replace("{techniques}", techStr)
      .replace("{modules}", modStr)
  } else {
    snippet = `${profile.name}: ${techStr}; ${modStr}`
  }
  if (objectiveHint) snippet = `[${objectiveHint}] ${snippet}`
  return snippet.slice(0, 200)
}

export function preloadTechniquesForPersona(opts: {
  persona?: TargetPersona
  objective?: FlowObjective
  aptHint?: string
  target?: string
  count?: number
}): TechniqueRef[] {
  const count = opts.count ?? 5
  const catalog = loadMitreTechniques()
  const profile = resolveAptProfile(opts.aptHint ?? "")
    ?? profileForInstitutionalSector(
      detectInstitutionalSector(opts.aptHint, opts.target),
      opts.aptHint,
      opts.target,
    )
    ?? profileForOtVertical(detectOtVertical(opts.aptHint, opts.target))
    ?? profileForPersona(opts.persona, opts.objective)

  if (profile) {
    return pickTechniqueIds(profile, count)
      .map((id) => lookupTechnique(id, catalog))
      .filter((t): t is TechniqueRef => t != null)
  }

  const domain = opts.objective === "ot_ics" || opts.objective === "hybrid_it_ot" ? "ics" : "enterprise"
  const pool = catalog.filter((t) => t.domain === domain)
  return pool.slice(0, count).map((t) => ({
    id: t.id, name: t.name, domain: t.domain, modules: t.modules,
  }))
}

export function profileForOtVertical(vertical?: OtVertical | null): AptProfile | null {
  if (!vertical) return null
  const playbookId = aptPlaybookForVertical(vertical)
  if (!playbookId) return null
  return loadAptProfiles().find((p) => p.id === playbookId) ?? null
}

export function profileForInstitutionalSector(
  sector?: InstitutionalSector | null,
  hint?: string,
  target?: string,
): AptProfile | null {
  if (sector === "critical_infra") {
    const verticalProfile = profileForOtVertical(detectOtVertical(hint, target))
    if (verticalProfile) return verticalProfile
  }
  if (!sector) return null
  const profileId = aptProfileIdForSector(sector)
  if (!profileId) return null
  return loadAptProfiles().find((p) => p.id === profileId) ?? null
}

export function profileForPersona(persona?: TargetPersona, objective?: FlowObjective): AptProfile | null {
  const profiles = loadAptProfiles()
  if (objective === "hybrid_it_ot") return profiles.find((p) => p.id === "volt_typhoon") ?? null
  if (objective === "telecom") return profiles.find((p) => p.id === "salt_typhoon") ?? null
  if (objective === "supply_chain") return profiles.find((p) => p.id === "lazarus") ?? null
  if (objective === "identity_first") return profiles.find((p) => p.id === "scattered_spider") ?? null
  if (objective === "cloud_ransom" || objective === "ransomware_impact") {
    return profiles.find((p) => p.id === "alphv_blackcat") ?? profiles.find((p) => p.id === "medusa") ?? null
  }
  if (objective === "proximity_physical") {
    return profiles.find((p) => p.id === "proximity_tradecraft") ?? profiles.find((p) => p.id === "scattered_spider") ?? null
  }
  if (objective === "ot_ics") {
    return profiles.find((p) => p.id === "utility_scada")
      ?? profiles.find((p) => p.id === "healthcare_tradecraft")
      ?? profiles.find((p) => p.id === "volt_typhoon")
      ?? null
  }
  if (persona === "hybrid_it_ot" || persona === "ot_scada_plant") {
    return profiles.find((p) => p.id === "volt_typhoon") ?? null
  }
  if (persona === "telecom_carrier") return profiles.find((p) => p.id === "salt_typhoon") ?? null
  if (persona === "physical_usb" || persona === "wireless_perimeter" || persona === "iot_device") {
    return profiles.find((p) => p.id === "scattered_spider") ?? null
  }
  if (persona === "supply_chain_repo") return profiles.find((p) => p.id === "lazarus") ?? null
  return null
}

export function writeIntelCache(profileId: string, bundle: AptIntelBundle): string {
  const dir = ensureIntelCacheDir()
  const fp = path.join(dir, `${profileId}.json`)
  fs.writeFileSync(fp, JSON.stringify(bundle, null, 2))
  return fp
}

export function readIntelCache(profileId: string): AptIntelBundle | null {
  const fp = path.join(CACHE_DIR, `${profileId}.json`)
  if (!fs.existsSync(fp)) return null
  try {
    return JSON.parse(fs.readFileSync(fp, "utf8")) as AptIntelBundle
  } catch {
    return null
  }
}

async function aggregateKevAndRansom(profile: AptProfile, live: boolean): Promise<{
  kevHits: string[]
  ransomGroups: string[]
}> {
  const kev = await fetchKevCache(live)
  const kevHits = kev.filter((cve) => profile.cvePriority?.includes(cve))
  const ransomRecords = await fetchRansomwatch(live)
  const groups = loadRansomwareGroups()
  const ransomNames = new Set<string>()
  for (const g of groups) {
    const id = String(g.id ?? g.name ?? "").toLowerCase()
    if (profile.vxFamilies?.some((f) => id.includes(f.toLowerCase()))) {
      ransomNames.add(String(g.name ?? g.id))
    }
  }
  for (const r of ransomRecords) {
    const actor = (r.actor ?? "").toLowerCase()
    if (profile.name.toLowerCase().includes(actor) || profile.aliases.some((a) => actor.includes(a.toLowerCase()))) {
      if (r.actor) ransomNames.add(r.actor)
    }
  }
  return { kevHits, ransomGroups: [...ransomNames] }
}

export async function buildAptIntelBundle(opts: {
  aptHint?: string
  target?: string
  persona?: TargetPersona
  objective?: FlowObjective
  live?: boolean
  refresh?: boolean
}): Promise<AptIntelBundle | null> {
  const profile = resolveAptProfile(opts.aptHint ?? "")
    ?? profileForInstitutionalSector(
      detectInstitutionalSector(opts.aptHint, opts.target),
      opts.aptHint,
      opts.target,
    )
    ?? profileForOtVertical(detectOtVertical(opts.aptHint, opts.target))
    ?? profileForPersona(opts.persona, opts.objective)
  if (!profile) return null

  if (!opts.refresh) {
    const cached = readIntelCache(profile.id)
    if (cached) return cached
  }

  const live = opts.live ?? false
  const catalog = loadMitreTechniques()
  const techniqueIds = pickTechniqueIds(profile, 5)
  const techniques = techniqueIds
    .map((id) => lookupTechnique(id, catalog))
    .filter((t): t is TechniqueRef => t != null)

  const mappings = loadAptPlaybookMappings()
  const objectiveHint = opts.objective
    ?? mappings[profile.id]?.objectiveHint
    ?? objectiveFromAptName(profile.name)
    ?? "standard"

  const { kevHits, ransomGroups } = await aggregateKevAndRansom(profile, live)
  const playbook = buildPlaybookFromProfile(profile)

  const bundle: AptIntelBundle = {
    profileId: profile.id,
    profileName: profile.name,
    objectiveHint,
    persona: opts.persona,
    techniques,
    modules: mergeModules(profile, techniques),
    kevHits,
    ransomGroups,
    playbook,
    cachedAt: new Date().toISOString(),
  }

  writeIntelCache(profile.id, bundle)
  return bundle
}

/** Persona-aware one-call threat intel for MCP + engagement slice. */
export async function getThreatIntel(opts: {
  target?: string
  persona?: TargetPersona
  objective?: FlowObjective
  aptHint?: string
  actor?: string
  live?: boolean
  refresh?: boolean
}): Promise<ThreatIntelResult | null> {
  const aptQuery = opts.aptHint ?? opts.actor ?? ""
  const bundle = await buildAptIntelBundle({
    aptHint: aptQuery || undefined,
    target: opts.target,
    persona: opts.persona,
    objective: opts.objective,
    live: opts.live ?? false,
    refresh: opts.refresh ?? false,
  })
  if (!bundle) return null

  const profile = loadAptProfiles().find((p) => p.id === bundle.profileId)!
  const intelSnippet = formatIntelSnippet(profile, bundle.techniques, bundle.objectiveHint)
  const artifactId = writeArtifact("apt_intel", {
    target: opts.target,
    ...bundle,
  })

  return {
    intelSnippet,
    artifactId,
    profileId: bundle.profileId,
    profileName: bundle.profileName,
    objectiveHint: bundle.objectiveHint,
    techniques: bundle.techniques,
    modules: bundle.modules,
    kevCount: bundle.kevHits.length,
    ransomGroupCount: bundle.ransomGroups.length,
  }
}

/** Preload intel for engagement slice — delegates to autonomous prefetch. */
export async function preloadEngagementIntel(opts: {
  target: string
  persona: TargetPersona
  objective: FlowObjective
  aptHint?: string
  live?: boolean
}): Promise<{
  intelSnippet: string
  artifactId?: string
  techniques: TechniqueRef[]
  objectiveHint: FlowObjective
  profileId?: string
}> {
  const { runIntelPrefetch } = await import("./intel_autonomous.ts")
  const result = await runIntelPrefetch(opts.target, opts.persona, {
    objective: opts.objective,
    aptHint: opts.aptHint,
    live: opts.live,
    hint: opts.aptHint,
  })
  return {
    intelSnippet: result.intelDigest,
    artifactId: result.artifactId,
    techniques: result.techniques,
    objectiveHint: result.objective,
    profileId: result.profileId,
  }
}

export default {
  resolveAptProfile,
  loadMitreTechniques,
  loadAptPlaybookMappings,
  objectiveFromAptName,
  formatIntelSnippet,
  preloadTechniquesForPersona,
  profileForPersona,
  buildAptIntelBundle,
  getThreatIntel,
  preloadEngagementIntel,
  writeIntelCache,
  readIntelCache,
}
