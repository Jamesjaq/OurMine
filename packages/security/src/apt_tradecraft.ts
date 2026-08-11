/**
 * @module apt_tradecraft
 * 2025–2026 APT tradecraft mapping — maps real-world adversary TTPs to agent tools.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import type { Phase } from "./pentestgpt_agent.ts"
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { hostFromTarget } from "./agent_tools.ts"
import { isKaliLinux, requireLiveMode } from "./exec_options.ts"

export { isKaliLinux, requireLiveMode }

/** Minimal intel brief shape to avoid circular import with intel_feeds */
export interface TargetIntelBriefLite {
  host?: string
  activeProfiles?: AptProfile[]
  recommendedTools?: string[]
}

export interface AptOpsecProfile {
  maxRpm: number
  preferLotL: boolean
  avoidSignatures: string[]
}

export interface AptProfile {
  id: string
  name: string
  aliases: string[]
  origin: string
  focus: string[]
  tools: string[]
  techniques: string[]
  vxFamilies?: string[]
  cvePriority?: string[]
  intelFeeds?: string[]
  opsecProfile?: AptOpsecProfile
}

const INTEL_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../data/intel")

let _cachedProfiles: AptProfile[] | null = null

export function loadAptProfiles(): AptProfile[] {
  if (_cachedProfiles) return _cachedProfiles
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(INTEL_DIR, "apt_profiles.json"), "utf8")) as AptProfile[]
    _cachedProfiles = raw
    return raw
  } catch {
    _cachedProfiles = FALLBACK_PROFILES
    return FALLBACK_PROFILES
  }
}

/** @deprecated use loadAptProfiles() */
export const APT_PROFILES: AptProfile[] = loadAptProfiles()

const FALLBACK_PROFILES: AptProfile[] = [
  {
    id: "scattered_spider",
    name: "Scattered Spider",
    aliases: ["UNC3944"],
    origin: "eCrime",
    focus: ["identity"],
    tools: ["identity_attack", "evilginx_lab"],
    techniques: ["T1566"],
  },
]

export interface TradecraftRecommendation {
  tool: string
  reason: string
  priority: number
  profile?: string
  technique?: string
}

export function recommendFromTradecraft(
  graph: AttackSurfaceGraph,
  target: string,
  phase: Phase,
  profiles: AptProfile[] = loadAptProfiles(),
  intelBrief?: TargetIntelBriefLite,
): TradecraftRecommendation[] {
  const host = hostFromTarget(target)
  const summary = graph.summary()
  const recs: TradecraftRecommendation[] = []
  const active = intelBrief?.activeProfiles ?? profiles

  if (intelBrief?.recommendedTools?.length) {
    for (const tool of intelBrief.recommendedTools.slice(0, 5)) {
      recs.push({
        tool,
        reason: `Intel brief priority tool for ${intelBrief.host}`,
        priority: 0,
        profile: active[0]?.id,
      })
    }
  }

  if (phase === "recon" || phase === "scan") {
    recs.push({ tool: "intel_enrich", reason: "Pre-stage threat intel enrichment", priority: 1, technique: "T1595" })
    recs.push({ tool: "cloud_enum", reason: "LotC: cloud metadata & IAM", priority: 1, profile: "unc4899", technique: "T1552.001" })
    recs.push({ tool: "lockfile_scan", reason: "npm worm / supply chain poison scan", priority: 1, profile: "team_pcp", technique: "T1195.002" })
    recs.push({ tool: "supply_chain_audit", reason: "Dependency audit", priority: 2, profile: "apt38", technique: "T1195.002" })
    recs.push({ tool: "ai_surface_scan", reason: "Langflow/Nacos/n8n exposure (JADEPUFFER/knaithe)", priority: 1, profile: "jadepuffer", technique: "T1190" })
    recs.push({ tool: "edge_audit", reason: "Edge appliance audit (Salt/Volt Typhoon)", priority: 2, profile: "volt_typhoon", technique: "T1190" })
    recs.push({ tool: "cicd_audit", reason: "CI/CD pipeline audit (TeamPCP/APT33)", priority: 2, profile: "team_pcp", technique: "T1195" })
  }

  if (summary.services > 0) {
    recs.push({ tool: "identity_attack", reason: "Identity-first (Scattered Spider)", priority: 1, profile: "scattered_spider", technique: "T1558.003" })
    recs.push({ tool: "postex_pivot", reason: "crackmapexec/netexec pivot", priority: 1, technique: "T1021" })
    recs.push({ tool: "cred_spray", reason: "Password spray", priority: 2, technique: "T1110.003" })
    recs.push({ tool: "social_eng_assess", reason: "Helpdesk/vishing readiness", priority: 2, profile: "scattered_spider", technique: "T1566" })
  }

  if (summary.endpoints.total > 0 || summary.services > 0) {
    recs.push({ tool: "web_exploit", reason: "Web exploitation", priority: 1, profile: "apt28", technique: "T1190" })
    recs.push({ tool: "sqlmap_scan", reason: "SQLi validation", priority: 2, technique: "T1190" })
    recs.push({ tool: "cpanel_audit", reason: "cPanel CVE-2026-41940 probe", priority: 2, profile: "sorry_ransom", technique: "T1190" })
    recs.push({ tool: "evilginx_lab", reason: "AiTM MFA bypass lab", priority: 3, profile: "scattered_spider", technique: "T1557" })
    recs.push({ tool: "ai_agent_audit", reason: "LLM guardrail audit", priority: 2, profile: "gtg_1002", technique: "T1059" })
    recs.push({ tool: "idp_audit", reason: "OAuth/IdP audit (ShinyHunters/Storm-0501)", priority: 2, profile: "shinyhunters", technique: "T1550" })
  }

  const asset = (graph.toJSON() as { assets?: Record<string, { services?: Record<string, { port: number }> }> }).assets?.[host]
  const ports = Object.values(asset?.services ?? {}).map((s) => s.port)
  if (ports.includes(445) || ports.includes(389) || ports.includes(636)) {
    recs.push({ tool: "ad_exploit", reason: "AD: DCSync/BloodHound path", priority: 1, profile: "apt28", technique: "T1003.006" })
    recs.push({ tool: "live_ad_attack", reason: "Impacket Kerberoast/AS-REP", priority: 2, technique: "T1558" })
    recs.push({ tool: "enum4linux_scan", reason: "SMB/LDAP enum", priority: 3, technique: "T1087" })
  }

  if (summary.vulns.confirmed > 0 || summary.vulns.bySeverity.critical > 0) {
    recs.push({ tool: "postex_pivot", reason: "Auto-pivot on confirmed access", priority: 1, technique: "T1021" })
    recs.push({ tool: "postex_harvest", reason: "Credential harvest", priority: 2, profile: "medusa", technique: "T1003" })
    recs.push({ tool: "privesc_check", reason: "Privesc enum", priority: 2, technique: "T1068" })
    recs.push({ tool: "lateral_move", reason: "Lateral movement", priority: 3, technique: "T1021" })
    recs.push({ tool: "container_audit", reason: "Container/K8s escape", priority: 4, profile: "unc4899", technique: "T1611" })
    recs.push({ tool: "esxi_audit", reason: "ESXi hypervisor audit", priority: 3, profile: "akira", technique: "T1486" })
    recs.push({ tool: "ransomware_assess", reason: "Backup/snapshot readiness (T1490)", priority: 3, profile: "storm_0501", technique: "T1490" })
    recs.push({ tool: "atlas_ml_audit", reason: "ML asset exposure", priority: 4, profile: "jadepuffer", technique: "T1486" })
    recs.push({ tool: "impact_assess", reason: "Wiper/recovery gap (Sandworm)", priority: 4, profile: "sandworm", technique: "T1485" })
  }

  for (const p of active) {
    for (const tool of p.tools) {
      if (!recs.some((r) => r.tool === tool)) {
        recs.push({ tool, reason: `${p.name} tradecraft`, priority: 5, profile: p.id })
      }
    }
  }

  const seen = new Set<string>()
  return recs
    .sort((a, b) => a.priority - b.priority)
    .filter((r) => {
      if (seen.has(r.tool)) return false
      seen.add(r.tool)
      return true
    })
}

export function shouldEscalatePostExploit(graph: AttackSurfaceGraph): {
  escalate: boolean
  reason: string
  suggestedTools: string[]
} {
  const summary = graph.summary()
  const paths = graph.analyzeAttackPaths()
  const criticalPaths = paths.filter((p) => p.severity === "critical" || p.severity === "high")
  const confirmedCritical = summary.vulns.bySeverity.critical > 0 && summary.vulns.confirmed > 0

  if (confirmedCritical || criticalPaths.length > 0) {
    return {
      escalate: true,
      reason: `${summary.vulns.confirmed} confirmed vulns, ${criticalPaths.length} critical/high attack paths`,
      suggestedTools: [
        "postex_pivot", "postex_harvest", "privesc_check", "lateral_move",
        "container_audit", "cred_spray", "evilginx_lab", "esxi_audit",
        "ransomware_assess", "impact_assess",
      ],
    }
  }
  return { escalate: false, reason: "no confirmed critical findings", suggestedTools: [] }
}

export default { loadAptProfiles, APT_PROFILES, recommendFromTradecraft, shouldEscalatePostExploit, isKaliLinux }
