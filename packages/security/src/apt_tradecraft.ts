/**
 * @module apt_tradecraft
 * 2025–2026 APT tradecraft mapping — maps real-world adversary TTPs to agent tools.
 * Sources: MITRE ATT&CK v18/v19, CrowdStrike 2026, Trend Micro H1 2026, CSA UNC4899 LotC.
 */
import * as fs from "node:fs"
import type { Phase } from "./pentestgpt_agent.ts"
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { hostFromTarget } from "./agent_tools.ts"

export interface AptProfile {
  id: string
  name: string
  aliases: string[]
  origin: string
  focus: string[]
  /** Primary agent tools this group uses */
  tools: string[]
  /** MITRE techniques */
  techniques: string[]
}

/** Curated profiles from 2025–2026 threat intel */
export const APT_PROFILES: AptProfile[] = [
  {
    id: "apt28",
    name: "APT28 (Fancy Bear)",
    aliases: ["Forest Blizzard", "Sofacy", "GRU Unit 26165"],
    origin: "Russia",
    focus: ["government", "defense", "cloud_c2", "llm_payloads"],
    tools: ["recon", "nuclei_scan", "web_exploit", "identity_attack", "ad_exploit", "cloud_enum"],
    techniques: ["T1190", "T1110", "T1071.001", "T1557", "T1003"],
  },
  {
    id: "unc4899",
    name: "UNC4899 (TraderTraitor / Jade Sleet)",
    aliases: ["Slow Pisces", "Lazarus subgroup"],
    origin: "DPRK",
    focus: ["devops", "supply_chain", "cloud_lotc", "crypto"],
    tools: ["supply_chain_audit", "cloud_enum", "container_audit", "cred_spray", "lateral_move"],
    techniques: ["T1195.002", "T1078.004", "T1021", "T1048", "T1552.001"],
  },
  {
    id: "scattered_spider",
    name: "Scattered Spider",
    aliases: ["UNC3944", "Octo Tempest"],
    origin: "eCrime",
    focus: ["identity", "okta", "aws", "vishing", "mfa_bypass"],
    tools: ["identity_attack", "cloud_enum", "cred_spray", "evilginx_lab", "lateral_move", "postex_harvest"],
    techniques: ["T1566", "T1078", "T1556", "T1531", "T1021"],
  },
  {
    id: "earth_krahang",
    name: "Earth Krahang / Flax Typhoon",
    aliases: ["PRC nexus"],
    origin: "China",
    focus: ["ai_agents", "cloud_c2", "edge_devices", "graph_api"],
    tools: ["recon", "live_recon", "nmap_scan", "web_exploit", "cloud_enum", "ad_exploit"],
    techniques: ["T1190", "T1071", "T1027", "T1059", "T1082"],
  },
  {
    id: "apt38",
    name: "APT38 (Sapphire Sleet)",
    aliases: ["BlueNoroff"],
    origin: "DPRK",
    focus: ["supply_chain", "npm", "financial", "crypto"],
    tools: ["supply_chain_audit", "recon", "web_exploit", "cred_spray"],
    techniques: ["T1195.002", "T1566", "T1071", "T1048"],
  },
  {
    id: "medusa",
    name: "Medusa / Qilin Ransomware",
    aliases: ["G1051", "Embargo"],
    origin: "eCrime",
    focus: ["backup_discovery", "esxi", "double_extortion"],
    tools: ["nmap_scan", "nuclei_scan", "privesc_check", "postex_harvest", "lateral_move"],
    techniques: ["T1486", "T1490", "T1518.002", "T1021", "T1078"],
  },
]

export interface TradecraftRecommendation {
  tool: string
  reason: string
  priority: number
  profile?: string
  technique?: string
}

/** Map attack surface state to APT-style next actions */
export function recommendFromTradecraft(
  graph: AttackSurfaceGraph,
  target: string,
  phase: Phase,
  profiles: AptProfile[] = APT_PROFILES,
): TradecraftRecommendation[] {
  const host = hostFromTarget(target)
  const summary = graph.summary()
  const recs: TradecraftRecommendation[] = []

  // LotC / cloud-first (UNC4899, Scattered Spider)
  if (phase === "recon" || phase === "scan") {
    recs.push({ tool: "cloud_enum", reason: "LotC: enumerate cloud metadata & IAM (UNC4899/Scattered Spider)", priority: 1, profile: "unc4899", technique: "T1552.001" })
    recs.push({ tool: "lockfile_scan", reason: "STARDUST CHOLLI: scan package-lock.json for npm worm poison (APT38)", priority: 1, profile: "apt38", technique: "T1195.002" })
    recs.push({ tool: "supply_chain_audit", reason: "Supply chain: npm/pypi typosquat & dependency audit", priority: 2, profile: "apt38", technique: "T1195.002" })
  }

  // Identity is the new perimeter (79% malware-free per CrowdStrike 2026)
  if (summary.services > 0) {
    recs.push({ tool: "identity_attack", reason: "Identity-first: Kerberoast/AS-REP before exploit (Scattered Spider playbook)", priority: 1, profile: "scattered_spider", technique: "T1558.003" })
    recs.push({ tool: "postex_pivot", reason: "Auto-pivot via crackmapexec/netexec + MSF on confirmed access", priority: 1, technique: "T1021" })
    recs.push({ tool: "cred_spray", reason: "Password spray against discovered services (T1110.003)", priority: 2, technique: "T1110.003" })
  }

  // Web + AI agent abuse surface
  if (summary.endpoints.total > 0 || summary.services > 0) {
    recs.push({ tool: "web_exploit", reason: "Full web scan: SQLi/XSS/SSRF/SSTI (APT28/Earth Krahang web TTPs)", priority: 1, profile: "apt28", technique: "T1190" })
    recs.push({ tool: "sqlmap_scan", reason: "Deep SQLi validation via sqlmap (real exploitation path)", priority: 2, technique: "T1190" })
    recs.push({ tool: "evilginx_lab", reason: "Scattered Spider AiTM MFA bypass lab (T1557)", priority: 3, profile: "scattered_spider", technique: "T1557" })
  }

  // AD path when SMB/LDAP detected
  const asset = (graph.toJSON() as { assets?: Record<string, { services?: Record<string, { service: string; port: number }> }> }).assets?.[host]
  const ports = Object.values(asset?.services ?? {}).map((s) => s.port)
  if (ports.includes(445) || ports.includes(389) || ports.includes(636)) {
    recs.push({ tool: "ad_exploit", reason: "AD surface: DCSync/BloodHound when SMB/LDAP open", priority: 1, profile: "apt28", technique: "T1003.006" })
    recs.push({ tool: "live_ad_attack", reason: "Real impacket Kerberoast/AS-REP against DC", priority: 2, technique: "T1558" })
    recs.push({ tool: "enum4linux_scan", reason: "SMB/LDAP enumeration via enum4linux", priority: 3, technique: "T1087" })
  }

  // Post-exploit when confirmed critical/high
  if (summary.vulns.confirmed > 0 || summary.vulns.bySeverity.critical > 0) {
    recs.push({ tool: "postex_pivot", reason: "crackmapexec/netexec + MSF auto-pivot on confirmed access", priority: 1, technique: "T1021" })
    recs.push({ tool: "postex_harvest", reason: "Post-ex: credential harvest & sensitive file discovery", priority: 2, profile: "medusa", technique: "T1003" })
    recs.push({ tool: "privesc_check", reason: "Privesc enumeration (SUID/sudo/caps/kernel)", priority: 2, technique: "T1068" })
    recs.push({ tool: "lateral_move", reason: "Lateral movement via SSH/SMB pivot", priority: 3, technique: "T1021" })
    recs.push({ tool: "container_audit", reason: "Container/K8s escape if DevOps target (UNC4899 LotC)", priority: 4, profile: "unc4899", technique: "T1611" })
  }

  // Merge profile tool preferences for current phase
  for (const p of profiles) {
    for (const tool of p.tools) {
      if (!recs.some((r) => r.tool === tool)) {
        recs.push({ tool, reason: `${p.name} tradecraft`, priority: 5, profile: p.id })
      }
    }
  }

  return recs.sort((a, b) => a.priority - b.priority)
}

/** Trigger post-exploit escalation when attack paths reach confirmed critical/high */
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
      suggestedTools: ["postex_pivot", "postex_harvest", "privesc_check", "lateral_move", "container_audit", "cred_spray", "evilginx_lab"],
    }
  }
  return { escalate: false, reason: "no confirmed critical findings", suggestedTools: [] }
}

/** Detect if running on Kali — auto-enable live mode */
export function isKaliLinux(): boolean {
  try {
    const osRelease = fs.readFileSync("/etc/os-release", "utf8")
    return /kali/i.test(osRelease)
  } catch {
    return false
  }
}

export default { APT_PROFILES, recommendFromTradecraft, shouldEscalatePostExploit, isKaliLinux }
