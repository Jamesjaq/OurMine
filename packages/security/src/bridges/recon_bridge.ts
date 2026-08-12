import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"
import { hostFromTarget } from "../agent_tools.ts"
import { result, agentToolBridge } from "./_shared.ts"

export const recon_bridge = {
  strix_web: async (ctx, params) => {
    const { StrixCoordinator } = await import("../strix_engine.ts")
    const url = String(params.url ?? params.target_url ?? ctx.target)
    const coord = new StrixCoordinator({ live: ctx.live })
    const attack = String(params.attack ?? "form_fuzz") as "xss_reflection" | "csrf_test" | "sqli_probe" | "form_fuzz" | "auth_bypass"
    coord.queue(url, attack)
    const jobs = await coord.runAll()
    return result("strix_web", "StrixCoordinator.runAll", ctx, { url, jobs: jobs.length, results: jobs })
  },
  app_security_engine: async (ctx, params) => {
    const { ApplicationSecurityEngine } = await import("../app_security_engine.ts")
    const raw = String(params.url ?? params.target ?? ctx.target)
    const targetUrl = raw.startsWith("http") ? raw : `https://${raw}`
    const engine = new ApplicationSecurityEngine(targetUrl)
    let schema = null as Awaited<ReturnType<ApplicationSecurityEngine["discoverOpenApiSchema"]>>
    if (ctx.live) {
      schema = await engine.discoverOpenApiSchema()
    }
    let ingested = 0
    if (schema && ctx.graph) {
      const u = new URL(targetUrl)
      const port = u.port ? parseInt(u.port, 10) : (u.protocol === "https:" ? 443 : 80)
      engine.ingestSchemaToGraph(ctx.graph, u.hostname, port, schema)
      ingested = schema.endpoints.length
    }
    return result(
      "app_security_engine",
      "ApplicationSecurityEngine.discoverOpenApiSchema",
      ctx,
      { title: schema?.title, endpoints: ingested, dryRun: !ctx.live },
      !!schema || !ctx.live,
    )
  },
  cloud_enum: async (ctx) => {
    const { runCloudEnum } = await import("../agent_tools.ts")
    return runCloudEnum(ctx)
  },
  counter_intel: async (ctx, params) => {
    const { auditDefenses } = await import("../counter_intel.ts")
    return result("counter_intel", "auditDefenses", ctx, auditDefenses({ live: ctx.live, check: String(params.check ?? "all") }))
  },
  attack_navigator: async (ctx) => {
    const { exportNavigatorLayer, findingsToTechniques } = await import("../attack_navigator.ts")
    const findings = Object.values(ctx.graph.toJSON().assets ?? {}).flatMap((a) =>
      Object.values((a as { services?: Record<string, { vulns?: { id?: string; title?: string; severity?: string }[] }> }).services ?? {})
        .flatMap((s) => s.vulns ?? [])
        .map((v) => ({ id: v.id ?? "", title: v.title ?? "", severity: v.severity ?? "info" })),
    )
    const techniques = [...findingsToTechniques(findings).keys()]
    const layer = exportNavigatorLayer(findings, { name: ctx.target })
    return result("attack_navigator", "exportNavigatorLayer", ctx, { techniques, layerName: layer.name })
  },
  institutional_recon: async (ctx, params) => {
    const { detectInstitutionalSector, reconInstitutionalSector } = await import("../institutional_hints.ts")
    const target = String(params.target ?? ctx.target)
    const hint = String(params.hint ?? params.objective ?? ctx.target)
    const sector = detectInstitutionalSector(hint, target)
    if (!sector) {
      return result("institutional_recon", "reconInstitutionalSector", ctx, { error: "no institutional sector detected", hint }, false)
    }
    const r = await reconInstitutionalSector(sector, target, { live: ctx.live })
    return result("institutional_recon", "reconInstitutionalSector", ctx, r, r.findings.length > 0)
  },
  auto_research: async (ctx, params) => {
    const { researchCve } = await import("../auto_research.ts")
    const cveId = String(params.cve_id ?? params.cveId ?? "CVE-2021-44228")
    const r = await researchCve({ cveId, repoUrl: params.repoUrl as string | undefined, patchCommitHash: params.patchCommitHash as string | undefined }, { dryRun: !ctx.live })
    return result("auto_research", "researchCve", ctx, r)
  },
  mobile_audit: async (ctx, params) => {
    const { listADBDevices } = await import("../mobile.ts")
    const devices = listADBDevices(ctx.live)
    return result("mobile_audit", "listADBDevices", ctx, { devices, apk_path: params.apk_path ?? null })
  },
  passive_intel: async (ctx, params) => {
    const { runPassiveIntel } = await import("../passive_intel.ts")
    const target = String(params.target ?? ctx.target)
    const r = await runPassiveIntel(target, { live: ctx.live })
    return result("passive_intel", "runPassiveIntel", ctx, r, r.enabled)
  },
  http_state_fuzz: async (ctx, params) => {
    const { runStateMachineFlow, defaultAuthBypassFlow, defaultSessionFlow } = await import("../http_state_fuzzer.ts")
    const url = String(params.target_url ?? params.url ?? `http://${hostFromTarget(ctx.target)}:8080`)
    const flowName = String(params.flow ?? "session")
    const flow = flowName === "auth-bypass" ? defaultAuthBypassFlow(url) : defaultSessionFlow(url)
    const r = await runStateMachineFlow(flow, { live: ctx.live })
    return result("http_state_fuzz", "runStateMachineFlow", ctx, r, r.steps.some((s) => s.passed))
  },
  exploit_adapter: async (ctx, params) => {
    const { recommendAndRun, listExploitModules } = await import("../exploit_adapter.ts")
    if (params.list === true || params.list === "true") {
      return result("exploit_adapter", "listExploitModules", ctx, listExploitModules({ service: params.service as string, cve: params.cve as string }))
    }
    const target = String(params.target ?? ctx.target)
    const r = await recommendAndRun(target, { service: params.service as string, cve: params.cve as string }, { live: ctx.live })
    return result("exploit_adapter", "recommendAndRun", ctx, r ?? { note: "no module matched" })
  },
  runtime_capability: async (ctx) => {
    const { assessRuntimeCapabilities, resolveScanCommand } = await import("../runtime_capability.ts")
    const host = hostFromTarget(ctx.target)
    const scan = resolveScanCommand(host, 8080)
    const report = await assessRuntimeCapabilities()
    return result("runtime_capability", "assessRuntimeCapabilities", ctx, { ...report, recommendedScan: scan })
  },
  exploit_synthesis: async (ctx, params) => {
    const { synthesizeFromIndicator, adaptiveModuleRank } = await import("../exploit_synthesis.ts")
    if (params.rank === true) {
      return result("exploit_synthesis", "adaptiveModuleRank", ctx, adaptiveModuleRank())
    }
    const indicator = String(params.indicator ?? params.error_body ?? "java.lang.NullPointerException")
    const r = await synthesizeFromIndicator(String(params.target ?? ctx.target), indicator, { live: ctx.live })
    return result("exploit_synthesis", "synthesizeFromIndicator", ctx, r, r.errorHints.length > 0)
  },
  dry_run_simulator: async (ctx, params) => {
    const { simulateEngagement } = await import("../dry_run_simulator.ts")
    const r = await simulateEngagement(ctx.target, { profileId: params.profile_id as string | undefined, graph: ctx.graph })
    return result("dry_run_simulator", "simulateEngagement", ctx, r)
  },
  tier1_depth: async (ctx) => {
    const { collectTier1Metrics, formatTier1Metrics } = await import("../tier1_depth_metrics.ts")
    const m = await collectTier1Metrics()
    return result("tier1_depth", "collectTier1Metrics", ctx, { metrics: m, formatted: formatTier1Metrics(m) })
  },
  multi_cloud_asm: async (ctx, params) => {
    const { fuseMultiCloudAsm } = await import("../multi_cloud_asm.ts")
    const r = await fuseMultiCloudAsm(ctx.graph, { live: ctx.live, target: String(params.target ?? ctx.target) })
    return result("multi_cloud_asm", "fuseMultiCloudAsm", ctx, r, r.fusedCount >= 0)
  },
} as const
