import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"
import { hostFromTarget } from "../agent_tools.ts"
import { result, agentToolBridge } from "./_shared.ts"

export const identity_bridge = {
  hybrid_ad_audit: async (ctx, params) => {
    const { hybridADAttackChain } = await import("../hybrid_ad_entra.ts")
    const domain = String(params.domain ?? hostFromTarget(ctx.target))
    const r = await hybridADAttackChain({ domain, dryRun: !ctx.live })
    return result("hybrid_ad_audit", "hybridADAttackChain", ctx, r)
  },
  oauth_audit: async (ctx, params) => {
    const mod = await import("../oauth_chain.ts")
    const raw = String(params.target ?? ctx.target)
    const target = raw.startsWith("http") ? raw : `https://${raw}/oauth/callback`
    const audit = ctx.live
      ? await mod.auditOAuthChainAsync(target, { dryRun: false })
      : mod.auditOAuthChain(target, { dryRun: true })
    return result("oauth_audit", "auditOAuthChain", ctx, audit)
  },
  webmail_audit: async (ctx, params) => {
    const { auditWebmailPersistence } = await import("../webmail_exploit.ts")
    const target = String(params.target ?? ctx.target)
    const r = await auditWebmailPersistence({ target, dryRun: !ctx.live })
    return result("webmail_audit", "auditWebmailPersistence", ctx, r)
  },
  adcs_audit: async (ctx, params) => {
    const { auditADCS } = await import("../adcs_audit.ts")
    const domain = String(params.domain ?? hostFromTarget(ctx.target))
    const r = auditADCS({ domain, dcIp: String(params.dcIp ?? domain) }, { live: ctx.live })
    return result("adcs_audit", "auditADCS", ctx, r)
  },
  cred_dump: async (ctx) => {
    const { CredentialDumpingEngine } = await import("../cred_dump.ts")
    const engine = new CredentialDumpingEngine()
    const r = await engine.dump({ dryRun: !ctx.live })
    return result("cred_dump", "CredentialDumpingEngine.dump", ctx, r)
  },
  identity_chain: async (ctx, params) => {
    const { runIdentityChain } = await import("../identity_chain.ts")
    const target = String(params.target ?? ctx.target)
    const r = await runIdentityChain(target, { live: ctx.live })
    return result("identity_chain", "runIdentityChain", ctx, r, r.steps.some((s) => s.success))
  },
  tier1_validation: async (ctx, params) => {
    const { runTier1ValidationSuite } = await import("../tier1_validation.ts")
    const url = String(params.target_url ?? params.url ?? `http://${hostFromTarget(ctx.target)}:8080`)
    const r = await runTier1ValidationSuite(url, { live: ctx.live })
    return result("tier1_validation", "runTier1ValidationSuite", ctx, r, r.idor.proven || r.fuzz.l3BypassProven || !ctx.live)
  },
  identity_playbooks: async (ctx, params) => {
    const {
      runFullIdentityPlaybook,
      runAiAgentAbuseChain,
      runMfaFatigueProbe,
      runVishingPlaybook,
    } = await import("../identity_playbooks.ts")
    const target = String(params.target ?? ctx.target)
    const playbook = String(params.playbook ?? "")
    if (playbook === "ai_agent") {
      const r = await runAiAgentAbuseChain(target, { live: ctx.live })
      return result("identity_playbooks", "runAiAgentAbuseChain", ctx, r, r.findings.length > 0 || !ctx.live)
    }
    if (playbook === "mfa_fatigue") {
      const r = await runMfaFatigueProbe(target, { live: ctx.live })
      return result("identity_playbooks", "runMfaFatigueProbe", ctx, r, r.findings.length > 0 || r.steps.some((s) => s.success) || !ctx.live)
    }
    if (playbook === "vishing" || playbook === "vishing_playbook" || playbook === "vishing_spearphish") {
      const domain = target.replace(/^https?:\/\//, "").split("/")[0] ?? target
      const r = await runVishingPlaybook(domain, { live: ctx.live })
      return result("identity_playbooks", "runVishingPlaybook", ctx, r, r.steps.some((s) => s.success) || !ctx.live)
    }
    const r = await runFullIdentityPlaybook(target, { live: ctx.live })
    return result("identity_playbooks", "runFullIdentityPlaybook", ctx, r, r.chain.steps.some((s) => s.success) || !ctx.live)
  },
  voip_vishing: async (ctx, params) => {
    const { auditHelpdeskSocial } = await import("../helpdesk_social_auto.ts")
    const r = await auditHelpdeskSocial(String(params.target ?? ctx.target), {
      live: ctx.live,
      actor: (params.actor as string | undefined) ?? "scattered_spider",
    })
    return result("voip_vishing", "auditHelpdeskSocial", ctx, r, r.scenarios.length > 0)
  },
  cred_access_auto: async (ctx, params) => {
    const { runAutonomousCredAccess } = await import("../cred_access_auto.ts")
    const { CredentialGraph } = await import("../credential_graph.ts")
    const credGraph = CredentialGraph.load()
    if (process.env.OURMINE_TIER1 === "1") process.env.OURMINE_AUTONOMOUS_PIVOT = "1"
    const r = await runAutonomousCredAccess({
      target: hostFromTarget(ctx.target),
      domain: params.domain as string | undefined,
      live: ctx.live,
      credGraph,
      methods: params.methods as string[] | undefined,
    })
    return result("cred_access_auto", "runAutonomousCredAccess", ctx, r, r.some((x) => x.success) || !ctx.live)
  },
  citrix_audit: async (ctx, params) => {
    const { auditCitrixEdge } = await import("../citrix_audit.ts")
    const r = await auditCitrixEdge(String(params.target ?? ctx.target), { live: ctx.live })
    return result("citrix_audit", "auditCitrixEdge", ctx, r, r.findings.length > 0 || r.dryRun)
  },
  helpdesk_social_auto: async (ctx, params) => {
    const { auditHelpdeskSocial } = await import("../helpdesk_social_auto.ts")
    const r = await auditHelpdeskSocial(String(params.target ?? ctx.target), {
      live: ctx.live,
      actor: params.actor as string | undefined,
    })
    return result("helpdesk_social_auto", "auditHelpdeskSocial", ctx, r, r.scenarios.length > 0)
  },
  oauth_consent_audit: async (ctx, params) => {
    const { auditOAuthConsent } = await import("../oauth_consent_audit.ts")
    const r = await auditOAuthConsent(String(params.target ?? ctx.target), {
      live: ctx.live,
      provider: params.provider as "entra" | "google" | "okta" | undefined,
    })
    return result("oauth_consent_audit", "auditOAuthConsent", ctx, r, r.findings.length > 0 || r.dryRun)
  },
} as const
