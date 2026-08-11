/**
 * @module attack_navigator
 * Export findings → MITRE ATT&CK Navigator layer JSON; coverage vs APT profile.
 */

export interface NavigatorTechnique {
  techniqueID: string
  tactic: string
  color: string
  comment: string
  enabled: boolean
  metadata: Array<{ name: string; value: string }>
  score: number
}

export interface NavigatorLayer {
  name: string
  versions: { attack: string; navigator: string; layer: string }
  domain: string
  description: string
  techniques: NavigatorTechnique[]
  gradient: { colors: string[]; minValue: number; maxValue: number }
  legendItems: Array<{ label: string; color: string }>
  metadata: Array<{ name: string; value: string }>
}

export interface FindingLike {
  technique_id?: string
  mitreId?: string
  title?: string
  severity?: string
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ff0000",
  high: "#ff7f0e",
  medium: "#ffcc00",
  low: "#1f77b4",
  info: "#aec7e8",
}

export function findingsToTechniques(findings: FindingLike[]): Map<string, NavigatorTechnique> {
  const map = new Map<string, NavigatorTechnique>()
  for (const f of findings) {
    const tid = String(f.technique_id ?? f.mitreId ?? "").trim()
    if (!tid || !tid.startsWith("T")) continue
    const sev = (f.severity ?? "info").toLowerCase()
    const existing = map.get(tid)
    const score = (existing?.score ?? 0) + (sev === "critical" ? 4 : sev === "high" ? 3 : sev === "medium" ? 2 : 1)
    map.set(tid, {
      techniqueID: tid,
      tactic: "enterprise-attack",
      color: SEVERITY_COLOR[sev] ?? SEVERITY_COLOR.info,
      comment: String(f.title ?? tid),
      enabled: true,
      metadata: [{ name: "severity", value: sev }],
      score,
    })
  }
  return map
}

export function exportNavigatorLayer(
  findings: FindingLike[],
  opts: { name?: string; profileTechniques?: string[] } = {},
): NavigatorLayer {
  const techMap = findingsToTechniques(findings)
  const techniques = [...techMap.values()]
  return {
    name: opts.name ?? "OurMine Campaign Coverage",
    versions: { attack: "15", navigator: "5.0.0", layer: "4.5" },
    domain: "enterprise-attack",
    description: "ATT&CK Navigator layer exported from OurMine findings",
    techniques,
    gradient: { colors: ["#ffffff", "#ff0000"], minValue: 0, maxValue: 10 },
    legendItems: [
      { label: "Observed", color: "#ff7f0e" },
      { label: "Critical", color: "#ff0000" },
    ],
    metadata: [{ name: "generator", value: "ourmine-attack_navigator" }],
  }
}

export function coverageScore(
  findings: FindingLike[],
  profileTechniques: string[],
): { covered: number; total: number; percent: number; missing: string[] } {
  const observed = new Set<string>()
  for (const f of findings) {
    const tid = String(f.technique_id ?? f.mitreId ?? "")
    if (tid.startsWith("T")) observed.add(tid)
  }
  const missing = profileTechniques.filter((t) => !observed.has(t))
  const covered = profileTechniques.length - missing.length
  const total = profileTechniques.length
  const percent = total ? Math.round((covered / total) * 100) : 0
  return { covered, total, percent, missing }
}

export default { exportNavigatorLayer, coverageScore, findingsToTechniques }
