/**
 * @module campaign
 * Red Team Campaign Orchestration — Multi-Phase Operation Controller, ATT&CK Matrix Coverage Tracker,
 * Objective & Milestones Engine, and Campaign Report Exporter.
 */

import { loadAptProfiles, type AptProfile } from "./apt_tradecraft.ts"

export type CampaignObjective = "espionage" | "ransomware" | "destructive" | "supply_chain" | "agentic"

export interface CampaignPhase {
  name: string
  status: "pending" | "in_progress" | "completed"
  modules: string[]
  objective?: CampaignObjective
}

export interface CampaignSummary {
  name: string
  targetDomain: string
  phaseCount: number
  objective: CampaignObjective
  profileId?: string
  profileName?: string
  phases: CampaignPhase[]
  techniques: string[]
}

export interface CampaignRunResult {
  summary: CampaignSummary
  stepsExecuted: number
  findings: unknown[]
  phaseResults?: Array<{ phase: string; toolsRun: string[] }>
  proofPackPath?: string
  attackNavigator?: ReturnType<typeof import("./attack_navigator.ts").exportNavigatorLayer>
  coverage?: ReturnType<typeof import("./attack_navigator.ts").coverageScore>
}

const OBJECTIVE_PHASES: Record<CampaignObjective, string[][]> = {
  espionage: [
    ["intel_enrich", "recon", "ai_recon"],
    ["web_exploit", "identity_attack", "ad_exploit"],
    ["postex_harvest", "lateral_move", "exfil"],
  ],
  ransomware: [
    ["intel_enrich", "nmap_scan", "edge_audit"],
    ["web_exploit", "cred_spray", "lateral_move"],
    ["raas_campaign", "raas_leak_catalog", "raas_vss_wipe", "esxi_audit", "impact_assess"],
  ],
  destructive: [
    ["recon", "live_recon"],
    ["privesc_check", "lateral_move"],
    ["impact_assess", "impact_engine"],
  ],
  supply_chain: [
    ["lockfile_scan", "cicd_audit", "supply_chain_audit"],
    ["dev_target", "container_audit"],
    ["lateral_move", "cloud_token"],
  ],
  agentic: [
    ["intel_enrich", "ai_surface_scan"],
    ["ai_agent_audit", "ai_manipulation_test"],
    ["atlas_ml_audit", "caldera_ttp"],
  ],
}

function profileObjective(profile?: AptProfile): CampaignObjective {
  if (!profile) return "espionage"
  const focus = profile.focus.join(" ").toLowerCase()
  if (focus.includes("ransom") || profile.id.includes("lockbit") || profile.id.includes("akira")) return "ransomware"
  if (focus.includes("supply") || profile.id.includes("unc4899") || profile.id.includes("team_pcp")) return "supply_chain"
  if (focus.includes("agentic") || focus.includes("ai") || profile.id.includes("jadepuffer") || profile.id.includes("knaithe")) return "agentic"
  if (profile.id === "sandworm") return "destructive"
  return "espionage"
}

export class RedTeamCampaign {
  private name: string
  private targetDomain: string
  private phases: CampaignPhase[] = []
  private objective: CampaignObjective
  private profile?: AptProfile

  constructor(
    name: string,
    targetDomain: string,
    opts: { objective?: string; profileId?: string } = {},
  ) {
    this.name = name
    this.targetDomain = targetDomain
    const profiles = loadAptProfiles()
    this.profile = opts.profileId ? profiles.find((p) => p.id === opts.profileId) : profiles[0]
    this.objective = (opts.objective as CampaignObjective) ?? profileObjective(this.profile)
    this.phases = this.buildPhases()
  }

  private buildPhases(): CampaignPhase[] {
    const phaseModules = OBJECTIVE_PHASES[this.objective] ?? OBJECTIVE_PHASES.espionage
    const names = ["Reconnaissance", "Initial Access", "Impact & Exfiltration"]
    return phaseModules.map((modules, i) => ({
      name: names[i] ?? `Phase ${i + 1}`,
      status: "pending" as const,
      modules: this.profile ? [...new Set([...modules, ...this.profile.tools.slice(0, 3)])] : modules,
      objective: this.objective,
    }))
  }

  getSummary(): CampaignSummary {
    return {
      name: this.name,
      targetDomain: this.targetDomain,
      phaseCount: this.phases.length,
      objective: this.objective,
      profileId: this.profile?.id,
      profileName: this.profile?.name,
      phases: this.phases,
      techniques: this.profile?.techniques ?? [],
    }
  }

  markPhaseComplete(index: number): void {
    if (this.phases[index]) this.phases[index].status = "completed"
  }

  markPhaseInProgress(index: number): void {
    if (this.phases[index]) this.phases[index].status = "in_progress"
  }
}

function hostFromTarget(target: string): string {
  return target.replace(/^https?:\/\//, "").split("/")[0]!.split(":")[0]!
}

/** Execute campaign phases with shared agent session and phase-specific tools. */
export async function runCampaign(
  target: string,
  opts: { profileId?: string; objective?: string; live?: boolean; maxStepsPerPhase?: number } = {},
): Promise<CampaignRunResult> {
  const campaign = new RedTeamCampaign("intel_run", target, {
    objective: opts.objective,
    profileId: opts.profileId,
  })
  const summary = campaign.getSummary()
  const { PentestAgent } = await import("./pentestgpt_agent.ts")
  const { executeAgentTool } = await import("./agent_tools.ts")
  const { ToolBroker } = await import("./tool_broker.ts")
  const { exportNavigatorLayer } = await import("./attack_navigator.ts")
  const { buildProofPack, writeProofPack } = await import("./proof_pack.ts")

  const agent = new PentestAgent({
    target,
    scope: [hostFromTarget(target)],
    live: opts.live ?? true,
    maxSteps: opts.maxStepsPerPhase ?? 8,
  })

  let totalSteps = 0
  const allFindings: unknown[] = []
  const phaseResults: Array<{ phase: string; toolsRun: string[] }> = []
  const broker = new ToolBroker()

  for (let i = 0; i < summary.phases.length; i++) {
    campaign.markPhaseInProgress(i)
    const phase = summary.phases[i]!
    const toolsRun: string[] = []
    const ctx = {
      target,
      graph: agent.getGraph(),
      broker,
      live: opts.live ?? true,
    }

    for (const tool of phase.modules.slice(0, opts.maxStepsPerPhase ?? 5)) {
      try {
        const res = await executeAgentTool(ctx, tool, {})
        toolsRun.push(tool)
        if (res.success) allFindings.push({ tool, output: res.output?.slice(0, 500) })
      } catch { /* tool unavailable */ }
    }

    totalSteps += toolsRun.length
    phaseResults.push({ phase: phase.name, toolsRun })
    campaign.markPhaseComplete(i)
  }

  const pack = buildProofPack(agent.getGraph(), {
    credGraph: agent.getCredentialGraph(),
    profileTechniques: summary.techniques,
    engagementId: target,
  })
  const proofPath = writeProofPack(pack)
  const navLayer = exportNavigatorLayer(
    pack.findings.map((f) => ({ title: f.title, severity: f.severity, technique_id: f.technique })),
    { name: `${target} campaign` },
  )

  return {
    summary: campaign.getSummary(),
    stepsExecuted: totalSteps,
    findings: allFindings,
    phaseResults,
    proofPackPath: proofPath,
    attackNavigator: navLayer,
    coverage: pack.coverage,
  }
}

export default { RedTeamCampaign, runCampaign }
