/**
 * @module institutional_hints
 * Sector-specific attack surface hints for institutional targets.
 * Taxonomy: packages/security/data/intel/institutional_sectors.json
 */
import * as fs from "node:fs"
import * as net from "node:net"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import { hostFromTarget } from "./agent_tools.ts"
import { resolveDryRun } from "./exec_options.ts"
import { writeArtifact } from "./mcp_artifacts.ts"
import {
  detectOtVertical,
  modulesForVertical,
  portsForVertical,
  READ_ONLY_SAFETY_NOTE,
  type OtVertical,
} from "./ot_verticals.ts"

export type SectorPersona =
  | "enterprise_ad"
  | "web_app"
  | "cloud_saas"
  | "ot_scada_plant"
  | "iot_device"
  | "wireless_perimeter"
  | "telecom_carrier"
  | "generic_ip"

export type SectorObjective =
  | "standard"
  | "identity_first"
  | "ot_ics"
  | "telecom"
  | "proximity_physical"

const SECTORS_JSON = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel/institutional_sectors.json",
)

export interface SectorPortHint {
  port: number
  protocol: string
  service: string
  note: string
}

export interface SectorFindingTemplate {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detail: string
  ports?: number[]
}

export interface SectorDefinition {
  label: string
  examples: string[]
  hintPattern: string
  ports: SectorPortHint[]
  modules: string[]
  aptProfileId: string
  persona: SectorPersona
  objective: SectorObjective
  finding: SectorFindingTemplate
}

interface SectorsFile {
  detectionPriority: string[]
  sectors: Record<string, SectorDefinition>
}

let _cached: SectorsFile | null = null
const _regexCache = new Map<string, RegExp>()

export function loadInstitutionalSectors(): SectorsFile {
  if (_cached) return _cached
  _cached = JSON.parse(fs.readFileSync(SECTORS_JSON, "utf8")) as SectorsFile
  return _cached
}

export type InstitutionalSector = keyof SectorsFile["sectors"] & string

export function allInstitutionalSectors(): InstitutionalSector[] {
  return Object.keys(loadInstitutionalSectors().sectors) as InstitutionalSector[]
}

function sectorRegex(sector: InstitutionalSector): RegExp {
  const cached = _regexCache.get(sector)
  if (cached) return cached
  const def = loadInstitutionalSectors().sectors[sector]
  const re = new RegExp(def.hintPattern, "i")
  _regexCache.set(sector, re)
  return re
}

export function sectorHintRegex(sector: InstitutionalSector): RegExp {
  return sectorRegex(sector)
}

/** Backward-compatible hint exports for modules that import named patterns. */
export const HEALTHCARE_HINTS = sectorHintRegex("healthcare")
export const BANKING_HINTS = sectorHintRegex("banking")
export const FINANCE_HINTS = BANKING_HINTS
export const UNIVERSITY_HINTS = sectorHintRegex("university")
export const K12_HINTS = sectorHintRegex("k12_school")
export const EDUCATION_HINTS = /\b(eduroam|campus|\.edu\b|ldap|radius|802\.1x.?campus|university|college|k-?12|school.?district|student.?info)\b/i
export const GOVERNMENT_HINTS = sectorHintRegex("government")
export const CORPORATE_OFFICE_HINTS = sectorHintRegex("corporate_office")
export const INSURANCE_HINTS = sectorHintRegex("insurance")
export const LEGAL_HINTS = sectorHintRegex("legal")
export const TELECOM_OFFICE_HINTS = sectorHintRegex("telecom_office")
export const NGO_HINTS = sectorHintRegex("ngo")
export const CRITICAL_INFRA_HINTS = sectorHintRegex("critical_infra")
export const SAAS_HINTS = sectorHintRegex("saas")
export const CAMPUS_WIFI_HINTS = /\b(eduroam|campus.?wifi|802\.1x|school.?district|k-?12)\b/i

export function getSectorDefinition(sector: InstitutionalSector): SectorDefinition {
  return loadInstitutionalSectors().sectors[sector]
}

export interface InstitutionalFinding {
  id: string
  sector: InstitutionalSector
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detail: string
  ports?: number[]
}

export interface InstitutionalReconResult {
  sector: InstitutionalSector
  target: string
  dryRun: boolean
  portHints: SectorPortHint[]
  findings: InstitutionalFinding[]
  modules: string[]
  summary: string
  otVertical?: OtVertical | null
  safetyNote?: string
  artifactId?: string
}

/** Detect institutional sector from hint + target strings. Priority order from JSON taxonomy. */
export function detectInstitutionalSector(hint?: string, target?: string): InstitutionalSector | null {
  const h = `${hint ?? ""} ${target ?? ""}`.toLowerCase()
  if (!h.trim()) return null
  const { detectionPriority } = loadInstitutionalSectors()
  for (const sector of detectionPriority) {
    if (sectorRegex(sector as InstitutionalSector).test(h)) {
      return sector as InstitutionalSector
    }
  }
  return null
}

export function sectorPortHeuristics(sector: InstitutionalSector): SectorPortHint[] {
  return getSectorDefinition(sector)?.ports ?? []
}

export function modulesForSector(sector: InstitutionalSector): string[] {
  return getSectorDefinition(sector)?.modules ?? []
}

export function aptProfileIdForSector(sector: InstitutionalSector): string | null {
  return getSectorDefinition(sector)?.aptProfileId ?? null
}

export function personaForSector(sector: InstitutionalSector): SectorPersona {
  return getSectorDefinition(sector)?.persona ?? "generic_ip"
}

export function objectiveForSector(sector: InstitutionalSector): SectorObjective {
  return getSectorDefinition(sector)?.objective ?? "standard"
}

/** Engagement policy boost modules — first two sector modules plus institutional_recon when applicable. */
export function prioritizeModulesForSector(sector: InstitutionalSector): string[] {
  const mods = modulesForSector(sector)
  const out = [...mods.slice(0, 2)]
  if (!out.includes("institutional_recon") && sector !== "saas") {
    out.unshift("institutional_recon")
  }
  return [...new Set(out)]
}

function dryRunFindings(sector: InstitutionalSector, target: string): InstitutionalFinding[] {
  const def = getSectorDefinition(sector)
  const ports = sectorPortHeuristics(sector)
  const findings: InstitutionalFinding[] = [{
    id: `inst-${sector}-ports`,
    sector,
    severity: "info",
    title: `${def.label} port heuristics`,
    detail: `Read-only recon targets ${ports.length} common service port(s) for ${sector}`,
    ports: ports.map((p) => p.port),
  }]

  if (def.finding) {
    findings.push({
      ...def.finding,
      sector,
    })
  }
  return findings
}

async function tcpProbe(host: string, port: number, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    sock.setTimeout(timeoutMs)
    sock.once("connect", () => { sock.destroy(); resolve(true) })
    sock.once("error", () => { sock.destroy(); resolve(false) })
    sock.once("timeout", () => { sock.destroy(); resolve(false) })
    sock.connect(port, host)
  })
}

/** Live read-only TCP connect scan for sector port heuristics. */
export async function probeSectorPorts(
  target: string,
  portHints: SectorPortHint[],
): Promise<{ openPorts: number[]; probed: number }> {
  const host = hostFromTarget(target)
  const openPorts: number[] = []
  let probed = 0
  for (const hint of portHints) {
    if (hint.protocol !== "tcp") continue
    probed++
    if (await tcpProbe(host, hint.port)) openPorts.push(hint.port)
  }
  return { openPorts, probed }
}

/** Read-only institutional recon — dry-run returns heuristics; live probes sector ports. */
export async function reconInstitutionalSector(
  sector: InstitutionalSector,
  target: string,
  opts: { live?: boolean; dryRun?: boolean } = {},
): Promise<InstitutionalReconResult> {
  const dryRun = resolveDryRun(opts)
  const otVertical = sector === "critical_infra" ? detectOtVertical(target, target) : null
  const portHints = otVertical
    ? portsForVertical(otVertical).map((p) => ({
      port: p.port,
      protocol: p.protocol,
      service: p.service,
      note: p.note,
    }))
    : sectorPortHeuristics(sector)
  const modules = otVertical
    ? [...new Set([...modulesForSector(sector), ...modulesForVertical(otVertical)])]
    : modulesForSector(sector)
  const def = getSectorDefinition(sector)
  const findings: InstitutionalFinding[] = dryRun
    ? dryRunFindings(sector, target)
    : [{
      id: `inst-${sector}-meta`,
      sector,
      severity: "info",
      title: `${def.label} sector metadata`,
      detail: `Live recon targeting ${portHints.length} port hint(s) on ${hostFromTarget(target)}${otVertical ? ` (${otVertical})` : ""}`,
      ports: portHints.map((p) => p.port),
    }]

  if (dryRun && otVertical) {
    const vPorts = portsForVertical(otVertical)
    findings.push({
      id: `inst-infra-${otVertical}`,
      sector,
      severity: "high",
      title: `${otVertical.replace(/_/g, " ")} OT vertical`,
      detail: `${READ_ONLY_SAFETY_NOTE} — ${vPorts.map((p) => `${p.service}:${p.port}`).join(", ")}`,
      ports: vPorts.map((p) => p.port),
    })
  }

  if (!dryRun) {
    const { openPorts, probed } = await probeSectorPorts(target, portHints)
    if (openPorts.length) {
      findings.push({
        id: `inst-${sector}-live-open`,
        sector,
        severity: openPorts.some((p) => [104, 502, 102, 8087].includes(p)) ? "high" : "medium",
        title: `Live sector port(s) open on ${hostFromTarget(target)}`,
        detail: `TCP connect confirmed ${openPorts.join(", ")} (${probed} probed)`,
        ports: openPorts,
      })
    } else if (probed > 0) {
      findings.push({
        id: `inst-${sector}-live-closed`,
        sector,
        severity: "info",
        title: "Sector port sweep — no common ports open",
        detail: `Probed ${probed} TCP port(s); target may be filtered or off-segment`,
        ports: [],
      })
    }
  }

  const result: InstitutionalReconResult = {
    sector,
    target,
    dryRun,
    portHints,
    findings,
    modules,
    otVertical,
    safetyNote: sector === "critical_infra" ? READ_ONLY_SAFETY_NOTE : undefined,
    summary: dryRun
      ? `dry-run: ${sector} recon${otVertical ? ` (${otVertical})` : ""} — ${portHints.length} port hint(s), ${findings.length} finding(s)`
      : `${sector} live recon${otVertical ? ` (${otVertical})` : ""}: ${findings.filter((f) => f.id.includes("live")).length ? "I/O complete" : "probed"} — ${findings.length} finding(s)`,
  }

  const artifactId = writeArtifact("institutional", {
    ...result,
    cachedAt: new Date().toISOString(),
  })
  result.artifactId = artifactId
  return result
}

export default {
  loadInstitutionalSectors,
  detectInstitutionalSector,
  sectorPortHeuristics,
  modulesForSector,
  prioritizeModulesForSector,
  personaForSector,
  objectiveForSector,
  aptProfileIdForSector,
  reconInstitutionalSector,
}
