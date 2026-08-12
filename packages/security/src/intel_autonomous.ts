/**
 * @module intel_autonomous
 * Autonomous intel prefetch — feeds engagement_slice + ares_threat_intel without user prompt.
 * Sources: CISA KEV cache, MITRE ATT&CK persona map, stack CVEs, ransomwatch TTPs, PoC hints.
 * Live refresh when OURMINE_INTEL_REFRESH=1.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import type { PlanAction } from "./pentest_plan_builder.ts"
import type { FlowObjective, TargetPersona } from "./target_flow.ts"
import { buildFlowProfile } from "./target_flow.ts"
import { AttackSurfaceGraph as ASG } from "./attack_surface.ts"
import {
  fetchKevCache,
  fetchRansomwatch,
  loadCvePriority,
  loadRansomwareGroups,
  intelCacheAgeDays,
  loadIntelCacheMeta,
  type CvePriorityEntry,
} from "./intel_feeds.ts"
import {
  loadAptPlaybookMappings,
  preloadTechniquesForPersona,
  resolveAptProfile,
  profileForPersona,
  type TechniqueRef,
} from "./apt_intel_feed.ts"
import { loadAptProfiles, type AptProfile } from "./apt_tradecraft.ts"
import { searchExploitDB } from "./toolkit.ts"
import { writeArtifact } from "./mcp_artifacts.ts"
import { isExecutableModule, normalizeModuleKey } from "./module_registry.ts"
import { isBattleReady } from "./exec_options.ts"
import { extortionModeFromEnv } from "./extortion_mode.ts"
import { compressIntelMeta, compressIabStage } from "./semantic_compression.ts"

const REPO_INTEL = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel",
)

export interface StackSignal {
  product: string
  source: "banner" | "service" | "hint" | "port"
  detail?: string
}

export interface StackCveMatch {
  cve: string
  product: string
  cvss: number
  inKev: boolean
  tools: string[]
}

export interface PocHint {
  source: "exploit-db" | "gh_grep"
  query: string
  cve?: string
  product?: string
  title?: string
  exploitId?: string
}

export interface RansomTtpAction {
  group: string
  techniques: string[]
  modules: string[]
  recentVictim?: string
}

/** Compact recommended-action codes — full labels/rationale live in artifact only. */
export const INTEL_ACTION_CODES: Record<string, { tool: string; module?: string; query?: string }> = {
  "dc:audit": { tool: "ares_dispatch", module: "device_code_audit" },
  "iab:vpn": { tool: "ares_dispatch", module: "citrix_audit" },
  "iab:rdp": { tool: "ares_dispatch", module: "cred_access_auto" },
  "iab:sl": { tool: "ares_dispatch", module: "edge_audit" },
  "ext:only": { tool: "ares_dispatch", module: "raas_leak_catalog" },
  "kev:scan": { tool: "ares_dispatch", module: "nuclei_scan" },
  "poc:grep": { tool: "gh_grep" },
  "poc:edb": { tool: "ares_dispatch", module: "web_exploit" },
  "raas:ttp": { tool: "ares_dispatch", module: "ransomware_assess" },
  "mod:run": { tool: "ares_dispatch" },
}

const MODULE_ACTION_CODE: Record<string, string> = {
  device_code_audit: "dc:audit",
  device_code_phish: "dc:audit",
  citrix_audit: "iab:vpn",
  edge_audit: "iab:vpn",
  cloud_token: "iab:vpn",
  cred_access_auto: "iab:rdp",
  cred_spray: "iab:rdp",
  rmm_audit: "iab:rdp",
  raas_leak_catalog: "ext:only",
  raas_exfil_upload: "ext:only",
  nuclei_scan: "kev:scan",
  web_exploit: "poc:edb",
  ransomware_assess: "raas:ttp",
  postex_harvest: "raas:ttp",
}

export function resolveIntelActionCode(mod: string | undefined, tool: string, extortionOnly = false): string {
  if (extortionOnly && (mod?.includes("raas") || mod?.includes("ransom"))) return "ext:only"
  if (mod && MODULE_ACTION_CODE[mod]) return MODULE_ACTION_CODE[mod]!
  if (tool === "gh_grep") return "poc:grep"
  if (mod) return "mod:run"
  return "mod:run"
}

export interface IntelPrefetchResult {
  target: string
  persona: TargetPersona
  objective: FlowObjective
  profileId?: string
  profileName?: string
  intelDigest: string
  artifactId: string
  techniques: TechniqueRef[]
  modules: string[]
  kevHits: string[]
  stackSignals: StackSignal[]
  stackCves: StackCveMatch[]
  ransomActions: RansomTtpAction[]
  pocHints: PocHint[]
  recommendedNextActions: PlanAction[]
  /** Compact action codes parallel to recommendedNextActions (artifact holds full PlanAction[]). */
  actionCodes?: string[]
  cachedAt: string
  identityAwareness?: string[]
  iabStage?: string
  extortionOnly?: boolean
  intelMeta?: Record<string, string | boolean>
}

/** T1451 SIM-swap / MFA downgrade awareness — intel only, no execution. */
export function simSwapAwareness(persona: TargetPersona, objective: FlowObjective, hint?: string): string[] {
  const h = `${hint ?? ""} ${persona} ${objective}`.toLowerCase()
  const financeOrTelecom = persona === "telecom_carrier"
    || objective === "telecom"
    || objective === "identity_first"
    || /bank|swift|finance|mfa|sim.?swap|sms.?otp/i.test(h)
  if (!financeOrTelecom) return []
  return [
    "T1451: SIM-swap / SMS OTP bypass — verify MFA policy blocks SMS-only fallback",
    "Awareness: helpdesk pretext + OAuth consent phishing often precede SIM-swap (no automated execution)",
    "Recommend: idp_audit + oauth_consent_audit for MFA downgrade paths",
  ]
}

/** OURMINE_INTEL_REFRESH=1 — live KEV/ransomwatch/exploit-db pull (auto on battle-ready). */
export function intelRefreshEnabled(): boolean {
  const v = process.env.OURMINE_INTEL_REFRESH?.trim().toLowerCase()
  if (v === "0" || v === "false" || v === "no") return false
  if (v === "1" || v === "true" || v === "yes") return true
  return isBattleReady()
}

function readJson<T>(file: string, fallback: T): T {
  try {
    return JSON.parse(fs.readFileSync(path.join(REPO_INTEL, file), "utf8")) as T
  } catch {
    return fallback
  }
}

const PRODUCT_ALIASES: Record<string, RegExp[]> = {
  Langflow: [/langflow/i, /7860/],
  "Alibaba Nacos": [/nacos/i, /8848/],
  "cPanel/WHM": [/cpanel|whm/i, /2083/],
  SharePoint: [/sharepoint|microsoft-iis.*asp/i],
  "Oracle EBS": [/oracle.*ebs|weblogic/i],
  "SonicWall VPN": [/sonicwall/i],
  Log4j: [/log4j|apache.*tomcat/i],
  Modbus: [/modbus/i, /\b502\b/],
  OpenSSH: [/openssh/i, /\b22\b/],
  ESXi: [/vmware|esxi|vcenter/i],
  Kubernetes: [/kubernetes|k8s|kube-api/i],
}

const HINT_PRODUCTS: Array<{ re: RegExp; product: string }> = [
  { re: /\b(langflow|nacos|n8n|minio|agentic)\b/i, product: "Langflow" },
  { re: /\b(cpanel|whm)\b/i, product: "cPanel/WHM" },
  { re: /\b(sharepoint|onprem)\b/i, product: "SharePoint" },
  { re: /\b(oracle|ebs|weblogic)\b/i, product: "Oracle EBS" },
  { re: /\b(sonicwall|vpn)\b/i, product: "SonicWall VPN" },
  { re: /\b(modbus|scada|plc|502)\b/i, product: "Modbus" },
  { re: /\b(esxi|vcenter|vmware)\b/i, product: "ESXi" },
  { re: /\b(k8s|kubernetes)\b/i, product: "Kubernetes" },
]

function extractStackFromGraph(graph: AttackSurfaceGraph): StackSignal[] {
  const out: StackSignal[] = []
  const seen = new Set<string>()

  for (const asset of Object.values(graph.toJSON().assets ?? {})) {
    const ad = asset as {
      services?: Record<string, { service?: string; version?: string; port?: number }>
    }
    for (const svc of Object.values(ad.services ?? {})) {
      const label = `${svc.service ?? ""} ${svc.version ?? ""}`.trim()
      if (!label) continue
      for (const [product, patterns] of Object.entries(PRODUCT_ALIASES)) {
        if (patterns.some((p) => p.test(label) || (svc.port != null && p.test(String(svc.port))))) {
          const key = `${product}|banner`
          if (!seen.has(key)) {
            seen.add(key)
            out.push({ product, source: "banner", detail: label.slice(0, 80) })
          }
        }
      }
      if (svc.service && !seen.has(svc.service)) {
        seen.add(svc.service)
        out.push({ product: svc.service, source: "service", detail: svc.version })
      }
    }
  }
  return out
}

function extractStackFromHint(target: string, hint?: string): StackSignal[] {
  const out: StackSignal[] = []
  const text = `${target} ${hint ?? ""}`
  for (const { re, product } of HINT_PRODUCTS) {
    if (re.test(text)) out.push({ product, source: "hint" })
  }
  return out
}

export function matchStackCves(
  signals: StackSignal[],
  kev: string[],
  catalog: CvePriorityEntry[] = loadCvePriority(),
): StackCveMatch[] {
  const kevSet = new Set(kev)
  const products = new Set(signals.map((s) => s.product.toLowerCase()))
  const matches: StackCveMatch[] = []

  for (const entry of catalog) {
    const prodLower = entry.product.toLowerCase()
    const hit = products.has(prodLower)
      || [...products].some((p) => prodLower.includes(p) || p.includes(prodLower.split("/")[0] ?? ""))
      || entry.nucleiTags?.some((t) => [...products].some((p) => p.includes(t)))
    if (!hit) continue
    matches.push({
      cve: entry.cve,
      product: entry.product,
      cvss: entry.cvss,
      inKev: kevSet.has(entry.cve),
      tools: entry.tools,
    })
  }

  return matches.sort((a, b) => {
    if (a.inKev !== b.inKev) return a.inKev ? -1 : 1
    return b.cvss - a.cvss
  }).slice(0, 8)
}

function loadRansomwatchPosts(): Array<{ post_title?: string; group_name?: string; discovered?: string }> {
  const cached = readJson<Array<{ post_title?: string; group_name?: string; discovered?: string }>>(
    "cache/ransomwatch.json",
    [],
  )
  if (cached.length) return cached
  return readJson("cache/ransomwatch_sample.json", [{ post_title: "Manufacturing victim", group_name: "lockbit" }])
}

/** Warn when intel cache exceeds TTL — compact st key via compressIntelStaleness. */
export function intelStalenessWarning(): string | null {
  const meta = loadIntelCacheMeta()
  const ttl = meta.ransomwatch?.ttlDays ?? 7
  const age = intelCacheAgeDays("ransomwatch")
  if (age == null) return "INTEL_STALE: no ransomwatch cache metadata — run npm run intel:refresh"
  if (age > ttl) {
    return `INTEL_STALE: ransomwatch cache ${Math.floor(age)}d old (TTL ${ttl}d) — refresh recommended`
  }
  return null
}

const RANSOM_GROUP_ALIASES: Record<string, string> = {
  lockbit: "lockbit",
  lockbit2: "lockbit",
  lockbit3: "lockbit",
  lockbit5: "lockbit",
  "lockbit 3": "lockbit",
  "lockbit black": "lockbit",
  "lockbit 5": "lockbit",
  akira: "akira",
  clop: "cl0p",
  cl0p: "cl0p",
  medusa: "medusa",
  qilin: "medusa",
  play: "play",
  "play ransomware": "play",
  ransomhub: "ransomhub",
  "ransom hub": "ransomhub",
  blackcat: "alphv_blackcat",
  alphv: "alphv_blackcat",
  dragonforce: "dragonforce",
  lorenz: "the_gentlemen",
  ragnarlocker: "lockbit",
  conti: "lockbit",
  blackbasta: "akira",
  royal: "akira",
  hive: "lockbit",
  interlock: "interlock",
  ghost: "ghost",
  inc: "inc_ransom",
  "inc ransom": "inc_ransom",
}

function normalizeRansomGroup(name: string): string {
  const q = name.toLowerCase().trim()
  return RANSOM_GROUP_ALIASES[q] ?? q.replace(/[\s.-]+/g, "_")
}

/** Map ransomwatch cache → TTP modules + recommended actions. */
export function mapRansomTtps(
  posts: Array<{ post_title?: string; group_name?: string }> = loadRansomwatchPosts(),
  limit = 6,
): RansomTtpAction[] {
  const ransomCatalog = loadRansomwareGroups()
  const aptProfiles = loadAptProfiles()
  const byGroup = new Map<string, { victim?: string; count: number }>()

  for (const p of posts.slice(-200)) {
    const raw = p.group_name ?? ""
    if (!raw) continue
    const norm = normalizeRansomGroup(raw)
    const cur = byGroup.get(norm) ?? { count: 0 }
    cur.count++
    if (!cur.victim) cur.victim = p.post_title
    byGroup.set(norm, cur)
  }

  const ranked = [...byGroup.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, limit)

  const actions: RansomTtpAction[] = []
  for (const [groupId, meta] of ranked) {
    const catalogHit = ransomCatalog.find(
      (g) => String(g.id ?? "").toLowerCase() === groupId
        || String(g.name ?? "").toLowerCase().replace(/\s+/g, "_") === groupId,
    )
    const aptHit = aptProfiles.find((p) => p.id === groupId || p.aliases.some((a) => normalizeRansomGroup(a) === groupId))
    const playbook = loadAptPlaybookMappings()[groupId]
    const techniques = [
      ...(catalogHit?.techniques as string[] ?? []),
      ...(aptHit?.techniques ?? []),
      ...(playbook?.techniqueChain ?? []),
    ].filter((t, i, arr) => arr.indexOf(t) === i).slice(0, 4)

    const modules = [
      ...(catalogHit?.tools as string[] ?? []),
      ...(aptHit?.tools ?? []),
      ...(playbook?.modules ?? []),
    ].filter((m, i, arr) => arr.indexOf(m) === i).slice(0, 5)

    if (!modules.length) {
      modules.push("ransomware_assess", "postex_harvest", "nuclei_scan")
    }
    if (!techniques.length) techniques.push("T1486")

    actions.push({
      group: String(catalogHit?.name ?? aptHit?.name ?? groupId),
      techniques,
      modules,
      recentVictim: meta.victim?.slice(0, 60),
    })
  }
  return actions
}

/** Exploit-DB + gh_grep PoC query stubs (no live MCP call — agent uses gh_grep tool). */
export async function buildPocHints(
  cves: StackCveMatch[],
  signals: StackSignal[],
  live: boolean,
): Promise<PocHint[]> {
  const hints: PocHint[] = []
  const top = cves.slice(0, 3)

  for (const c of top) {
    hints.push({
      source: "gh_grep",
      query: `${c.cve} exploit OR poc language:python`,
      cve: c.cve,
      product: c.product,
    })
    hints.push({
      source: "gh_grep",
      query: `"${c.product}" CVE ${c.cve} proof`,
      cve: c.cve,
      product: c.product,
    })
  }

  const product = top[0]?.product ?? signals[0]?.product
  if (product) {
    const edb = await searchExploitDB(`${product} ${top[0]?.cve ?? ""}`.trim(), { live })
    for (const hit of edb.slice(0, 2)) {
      hints.push({
        source: "exploit-db",
        query: hit.title,
        product,
        title: hit.title,
        exploitId: hit.id,
      })
    }
    if (!edb.length) {
      hints.push({
        source: "gh_grep",
        query: `${product} exploit poc site:github.com`,
        product,
      })
    }
  }

  const seen = new Set<string>()
  return hints.filter((h) => {
    const k = `${h.source}|${h.query}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  }).slice(0, 8)
}

function resolveProfile(
  persona: TargetPersona,
  objective: FlowObjective,
  aptHint?: string,
): AptProfile | null {
  return resolveAptProfile(aptHint ?? "")
    ?? profileForPersona(persona, objective)
}

/** When KEV hits exist, prioritize zero-day fuzzer for n-day validation. */
export function prioritizeKevFuzzerModules(
  modules: string[],
  kevHits: string[],
): string[] {
  if (!kevHits.length) return modules
  const fuzzer = "ares_zero_day_fuzzer"
  if (!isExecutableModule(fuzzer)) return modules
  const rest = modules.filter((m) => normalizeModuleKey(m) !== fuzzer)
  return [fuzzer, ...rest].slice(0, 16)
}

function mergeModules(
  profile: AptProfile | null,
  techniques: TechniqueRef[],
  stackCves: StackCveMatch[],
  ransomActions: RansomTtpAction[],
  kevHits: string[] = [],
): string[] {
  const mappings = loadAptPlaybookMappings()
  const seen = new Set<string>()
  const out: string[] = []

  const push = (m: string) => {
    const key = normalizeModuleKey(m)
    if (!m || seen.has(key)) return
    if (!isExecutableModule(key) && !isExecutableModule(m)) return
    seen.add(key)
    out.push(key)
  }

  if (profile) {
    for (const m of mappings[profile.id]?.modules ?? []) push(m)
    for (const m of profile.tools) push(m)
  }
  for (const t of techniques) for (const m of t.modules) push(m)
  for (const c of stackCves) for (const m of c.tools) push(m)
  for (const r of ransomActions) for (const m of r.modules) push(m)

  return prioritizeKevFuzzerModules(out, kevHits)
}

export function buildIntelDigest(opts: {
  objective: FlowObjective
  profileName?: string
  profileId?: string
  techniques: TechniqueRef[]
  kevHits: string[]
  stackCves: StackCveMatch[]
  ransomActions: RansomTtpAction[]
  pocHints: PocHint[]
  modules?: string[]
  iabStage?: string
  extortionOnly?: boolean
  staleWarning?: string | null
}): string {
  const actor = (opts.profileName ?? opts.profileId ?? opts.objective).split(/[\s_-]/)[0]!.slice(0, 12)
  const stage = opts.iabStage
    ? compressIabStage(opts.iabStage)
    : opts.techniques[0]?.id?.slice(0, 6) ?? "T1595"
  const nextMods = (opts.modules ?? opts.ransomActions[0]?.modules ?? []).slice(0, 2).join(",")
    || opts.stackCves[0]?.tools?.[0]
    || "recon"
  const kevPart = opts.kevHits.length
    ? `kev:${opts.kevHits.length}`
    : opts.stackCves.filter((c) => c.inKev).length
      ? `kev:${opts.stackCves.filter((c) => c.inKev).length}`
      : undefined

  const parts = [actor, stage, nextMods, kevPart].filter(Boolean)
  let digest = parts.join("|")

  const meta = compressIntelMeta({
    iabStage: opts.iabStage,
    extortionOnly: opts.extortionOnly,
    staleWarning: opts.staleWarning,
  })
  const metaSuffix = Object.entries(meta).map(([k, v]) => `${k}:${v}`).join("|")
  if (metaSuffix) digest = `${digest}|${metaSuffix}`

  return digest.slice(0, 120)
}

export function buildIntelNextActions(
  prefetch: Pick<IntelPrefetchResult, "target" | "objective" | "stackCves" | "ransomActions" | "pocHints" | "modules">,
  startStep = 1,
  extortionOnly = false,
): PlanAction[] {
  const actions: PlanAction[] = []
  let step = startStep

  for (const r of prefetch.ransomActions.slice(0, 2)) {
    const mod = r.modules[0]
    if (!mod) continue
    const code = resolveIntelActionCode(mod, "ares_dispatch", extortionOnly)
    actions.push({
      step: step++,
      label: `Ransom TTP: ${r.group}`,
      tool: "ares_dispatch",
      args: { module: mod, target: prefetch.target, objective: prefetch.objective },
      mitre: r.techniques[0],
      phase: mod.includes("ransom") || mod.includes("esxi") ? "post_ex" : "exploit",
      rationale: r.recentVictim
        ? `ransomwatch: ${r.group} active — ${r.recentVictim}`
        : `ransomwatch TTP chain for ${r.group}`,
      code,
    })
  }

  for (const c of prefetch.stackCves.filter((x) => x.inKev).slice(0, 2)) {
    const mod = c.tools[0] ?? "nuclei_scan"
    actions.push({
      step: step++,
      label: `KEV ${c.cve}`,
      tool: "ares_dispatch",
      args: { module: mod, target: prefetch.target, cve: c.cve },
      mitre: "T1190",
      phase: "exploit",
      rationale: `CISA KEV + ${c.product} stack match`,
      code: resolveIntelActionCode(mod, "ares_dispatch"),
    })
  }

  const kevCount = prefetch.stackCves.filter((x) => x.inKev).length
  if (kevCount > 0 && isExecutableModule("ares_zero_day_fuzzer")) {
    actions.unshift({
      step: startStep,
      label: "KEV-prioritized fuzzer",
      tool: "ares_dispatch",
      args: {
        module: "ares_zero_day_fuzzer",
        target: prefetch.target,
        rounds: 32,
        kev_cves: prefetch.stackCves.filter((x) => x.inKev).map((x) => x.cve).slice(0, 3),
      },
      mitre: "T1190",
      phase: "exploit",
      rationale: `KEV cache (${kevCount} hit(s)) — prioritize n-day fuzz targets`,
      code: resolveIntelActionCode("ares_zero_day_fuzzer", "ares_dispatch"),
    })
    for (const a of actions) a.step = (a.step ?? 0) + 1
  }

  for (const hint of prefetch.pocHints.filter((p) => p.source === "gh_grep").slice(0, 1)) {
    actions.push({
      step: step++,
      label: "GitHub PoC hunt",
      tool: "gh_grep",
      args: { query: hint.query },
      phase: "exploit",
      rationale: hint.cve
        ? `PoC research for ${hint.cve} — use gh_grep MCP`
        : `PoC research for ${hint.product}`,
      code: "poc:grep",
    })
  }

  for (const hint of prefetch.pocHints.filter((p) => p.source === "exploit-db" && p.exploitId).slice(0, 1)) {
    const mod = prefetch.stackCves[0]?.tools[0] ?? "web_exploit"
    actions.push({
      step: step++,
      label: `Exploit-DB #${hint.exploitId}`,
      tool: "ares_dispatch",
      args: { module: mod, target: prefetch.target },
      phase: "exploit",
      rationale: hint.title?.slice(0, 80) ?? "exploit-db hit",
      code: resolveIntelActionCode(mod, "ares_dispatch"),
    })
  }

  if (!actions.length && prefetch.modules.length) {
    const mod = prefetch.modules[0]!
    actions.push({
      step: step++,
      label: `Actor module: ${mod}`,
      tool: "ares_dispatch",
      args: { module: mod, target: prefetch.target, objective: prefetch.objective },
      phase: "recon",
      rationale: "Autonomous intel prefetch — profile-mapped module",
      code: resolveIntelActionCode(mod, "ares_dispatch"),
    })
  }

  return actions.slice(0, 4)
}

/** Primary entry: autonomous prefetch for engagement_slice + ares_threat_intel. */
export async function runIntelPrefetch(
  target: string,
  persona: TargetPersona,
  opts: {
    objective?: FlowObjective
    aptHint?: string
    live?: boolean
    graph?: AttackSurfaceGraph
    hint?: string
  } = {},
): Promise<IntelPrefetchResult> {
  const hint = opts.hint ?? opts.aptHint ?? target
  const flow = buildFlowProfile(target, undefined, hint)
  const fromApt = opts.aptHint ? (await import("./apt_intel_feed.ts")).objectiveFromAptName(opts.aptHint) : null
  const effectiveObjective = (opts.objective ?? fromApt ?? (flow.persona === "hybrid_it_ot" ? "hybrid_it_ot" : "standard")) as FlowObjective

  const refresh = intelRefreshEnabled()
  const live = refresh || (opts.live ?? false)

  let graph = opts.graph
  if (!graph) {
    graph = new ASG(target)
  }

  const profile = resolveProfile(persona, effectiveObjective, opts.aptHint)
  const kev = await fetchKevCache(live)
  await fetchRansomwatch(live)

  const stackSignals = [
    ...extractStackFromGraph(graph),
    ...extractStackFromHint(target, opts.hint ?? opts.aptHint),
  ]
  const stackCves = matchStackCves(stackSignals, kev)
  const kevHits = stackCves.filter((c) => c.inKev).map((c) => c.cve)
  if (profile?.cvePriority?.length) {
    for (const c of profile.cvePriority) {
      if (kev.includes(c) && !kevHits.includes(c)) kevHits.push(c)
    }
  }

  const techniques = preloadTechniquesForPersona({
    persona,
    objective: effectiveObjective,
    aptHint: opts.aptHint ?? profile?.name,
    count: 5,
  })

  const ransomActions = mapRansomTtps()
  const pocHints = await buildPocHints(stackCves, stackSignals, live)
  const modules = mergeModules(profile, techniques, stackCves, ransomActions, kevHits)

  const extortionOnly = extortionModeFromEnv().enabled
    || effectiveObjective === "extortion_only"
  const staleWarn = intelStalenessWarning()

  let iabStage: string | undefined
  if (persona === "enterprise_ad" && effectiveObjective === "identity_first") {
    const { iabModulesForHint } = await import("./iab_intel.ts")
    const iabMods = iabModulesForHint(hint)
    if (iabMods.length) {
      for (const m of iabMods) {
        if (!modules.includes(m)) modules.unshift(m)
      }
      iabStage = /vpn|citrix|cookie/i.test(hint) ? "initial_access" : "stealer_log"
    }
  }

  const intelDigest = buildIntelDigest({
    objective: effectiveObjective,
    profileName: profile?.name,
    profileId: profile?.id,
    techniques,
    kevHits,
    stackCves,
    ransomActions,
    pocHints,
    modules,
    iabStage,
    extortionOnly,
    staleWarning: staleWarn,
  })

  const { aitmAwarenessForStack } = await import("./aitm_playbook.ts")
  const aitmHints = aitmAwarenessForStack([
    ...stackSignals.map((s) => s.product),
    hint,
  ])
  let digestWithAwareness = intelDigest
  if (aitmHints.length && digestWithAwareness.length < 110) {
    digestWithAwareness = `${digestWithAwareness}|aitm`
  }

  const identityAwareness = simSwapAwareness(persona, effectiveObjective, hint)
  if (identityAwareness.length && digestWithAwareness.length < 115) {
    digestWithAwareness = `${digestWithAwareness}|sim`
  }

  const recommendedNextActions = buildIntelNextActions({
    target,
    objective: effectiveObjective,
    stackCves,
    ransomActions,
    pocHints,
    modules,
  }, 1, extortionOnly)
  const actionCodes = recommendedNextActions.map((a) => a.code).filter(Boolean) as string[]

  const intelMeta = compressIntelMeta({
    iabStage,
    extortionOnly,
    staleWarning: staleWarn,
  })

  const payload = {
    target,
    persona,
    objective: effectiveObjective,
    profileId: profile?.id,
    profileName: profile?.name,
    intelDigest: digestWithAwareness,
    techniques,
    modules,
    kevHits,
    stackSignals,
    stackCves,
    ransomActions,
    pocHints,
    recommendedNextActions,
    actionCodes,
    iabStage,
    extortionOnly,
    intelMeta,
    staleWarning: staleWarn,
    refreshEnabled: refresh,
    cachedAt: new Date().toISOString(),
  }

  const artifactId = writeArtifact("intel_prefetch", payload)

  return {
    target,
    persona,
    objective: effectiveObjective,
    profileId: profile?.id,
    profileName: profile?.name,
    intelDigest: digestWithAwareness,
    artifactId,
    techniques,
    modules,
    kevHits,
    stackSignals,
    stackCves,
    ransomActions,
    pocHints,
    recommendedNextActions,
    actionCodes,
    cachedAt: payload.cachedAt,
    identityAwareness,
    iabStage,
    extortionOnly,
    intelMeta,
  }
}

/** Re-export profile resolver for tests — 10+ actor→module mappings via apt_playbook_modules.json. */
export function actorModuleMap(): Record<string, { modules: string[]; techniques: string[] }> {
  const mappings = loadAptPlaybookMappings()
  const out: Record<string, { modules: string[]; techniques: string[] }> = {}
  for (const [id, m] of Object.entries(mappings)) {
    out[id] = { modules: m.modules, techniques: m.techniqueChain }
  }
  return out
}

export default {
  runIntelPrefetch,
  intelRefreshEnabled,
  matchStackCves,
  mapRansomTtps,
  buildPocHints,
  buildIntelDigest,
  buildIntelNextActions,
  simSwapAwareness,
  intelStalenessWarning,
  actorModuleMap,
  INTEL_ACTION_CODES,
  resolveIntelActionCode,
}
