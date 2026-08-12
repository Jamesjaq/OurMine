import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"
import { hostFromTarget } from "../agent_tools.ts"
import { result, agentToolBridge } from "./_shared.ts"

export const audit_bridge = {
  lolbins_audit: async (ctx) => {
    const { auditLOLBins } = await import("../lolbins_audit.ts")
    return result("lolbins_audit", "auditLOLBins", ctx, auditLOLBins({ live: ctx.live }))
  },
  ebpf_audit: async (ctx) => {
    const { auditEBPFAndPersistence } = await import("../ebpf_audit.ts")
    return result("ebpf_audit", "auditEBPFAndPersistence", ctx, auditEBPFAndPersistence({ dryRun: !ctx.live }))
  },
  uefi_audit: async (ctx) => {
    const { auditUEFIAndBootkit } = await import("../uefi_bootkit_audit.ts")
    return result("uefi_audit", "auditUEFIAndBootkit", ctx, auditUEFIAndBootkit({ live: ctx.live }))
  },
  net_device_audit: async (ctx, params) => {
    const { auditNetworkDevice } = await import("../net_device.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const hint = String(params.hint ?? params.objective ?? ctx.target)
    return result("net_device_audit", "auditNetworkDevice", ctx, auditNetworkDevice(host, { live: ctx.live, hint }))
  },
  persistence_install: async (ctx, params) => {
    const { PersistenceEngine } = await import("../persistence.ts")
    const engine = new PersistenceEngine()
    const r = await engine.installPersistence(String(params.mechanism ?? "cron job"), {
      live: ctx.live,
      targetOs: String(params.os ?? ""),
      payloadPath: String(params.payload ?? ""),
    })
    return result("persistence_install", "PersistenceEngine.installPersistence", ctx, r)
  },
  opsec_review: async (ctx, params) => {
    const { gateExecution } = await import("../opsec_gate.ts")
    const command = String(params.command ?? "id")
    const tool = String(params.tool ?? "bash")
    const review = await gateExecution({ tool, command, live: ctx.live, profile: String(params.profile ?? "default") })
    return result("opsec_review", "gateExecution", ctx, review)
  },
  proof_export: async (ctx) => {
    const { buildProofPack, writeProofPack } = await import("../proof_pack.ts")
    const pack = buildProofPack(ctx.graph)
    const dir = String(process.env.OURMINE_PROOF_DIR ?? ".ourmine/proof")
    const file = writeProofPack(pack, dir)
    return result("proof_export", "writeProofPack", ctx, { path: file, merkleRoot: pack.merkleRoot })
  },
  engagement_report: async (ctx, params) => {
    const { buildEngagementGraph } = await import("../engagement_graph.ts")
    const { exportEngagementReport } = await import("../engagement_report.ts")
    const { CredentialGraph } = await import("../credential_graph.ts")
    const credGraph = ctx.credGraph ?? CredentialGraph.load()
    const eg = buildEngagementGraph({
      target: String(params.target ?? ctx.target),
      graph: ctx.graph,
      credGraph,
      objective: String(params.objective ?? "standard"),
      live: ctx.live,
    })
    const report = exportEngagementReport(eg, { phasesCompleted: params.phases ? String(params.phases).split(",") : undefined })
    return result("engagement_report", "exportEngagementReport", ctx, report, true)
  },
  supply_chain_exec: async (ctx, params) => {
    const { executeSupplyChainChain } = await import("../supply_chain_exec.ts")
    const r = await executeSupplyChainChain({
      package: String(params.package ?? "lodash"),
      ecosystem: String(params.registry ?? "npm"),
      projectDir: String(params.project_dir ?? process.cwd()),
      live: ctx.live,
    })
    return result("supply_chain_exec", "executeSupplyChainChain", ctx, r, r.compromiseIndicators.length > 0 || !ctx.live)
  },
  engagement_memory: async (ctx, params) => {
    const { EngagementMemory } = await import("../engagement_memory.ts")
    const mem = EngagementMemory.loadForTarget(ctx.target)
    if (params.phase) mem.setPhase(String(params.phase))
    if (params.record_host) mem.recordHost(String(params.record_host))
    if (params.record_failure) {
      mem.recordFailedAttempt(String(params.tool ?? "unknown"), ctx.target, String(params.reason ?? ""))
    }
    const throttle = mem.shouldThrottleTool(String(params.check_tool ?? "cred_spray"))
    return result("engagement_memory", "EngagementMemory.snapshot", ctx, { snapshot: mem.snapshot(), throttle })
  },
  edr_feedback_loop: async (ctx) => {
    const { runEdrFeedbackLoop } = await import("../edr_feedback_loop.ts")
    const r = await runEdrFeedbackLoop({ live: ctx.live })
    return result("edr_feedback_loop", "runEdrFeedbackLoop", ctx, r, r.iterations.length > 0)
  },
  privesc_chains: async (ctx, params) => {
    const { runPrivescChains } = await import("../privesc_chains.ts")
    const r = await runPrivescChains({ live: ctx.live, domain: params.domain as string | undefined, dc: params.dc as string | undefined })
    return result("privesc_chains", "runPrivescChains", ctx, r, r.proven || r.steps.length > 0)
  },
  ares_zero_day_fuzzer: async (ctx, params) => {
    const { runZeroDayFuzzer } = await import("../ares/zero_day_fuzzer.ts")
    const r = await runZeroDayFuzzer({
      target: String(params.target ?? "echo"),
      live: ctx.live,
      seedFile: params.seed_file as string | undefined,
      rounds: Number(params.rounds ?? 32),
    })
    return result("ares_zero_day_fuzzer", "runZeroDayFuzzer", ctx, r, r.crashes.length >= 0)
  },
  ares_fileless_implant: async (ctx) => {
    const { buildFilelessImplant } = await import("../ares/fileless_implant.ts")
    const r = await buildFilelessImplant({ live: ctx.live })
    return result("ares_fileless_implant", "buildFilelessImplant", ctx, r, r.artifacts.length > 0)
  },
  ares_firmware_implant: async (ctx, params) => {
    const { deployFirmwareImplant } = await import("../ares/firmware_implant.ts")
    const r = await deployFirmwareImplant({ live: ctx.live, target: params.target as string | undefined, keyId: params.key_id as string | undefined })
    return result("ares_firmware_implant", "deployFirmwareImplant", ctx, r, r.deployed || r.uefiDriver.length > 0)
  },
  ares_hypervisor_rootkit: async (ctx, params) => {
    const { deployHypervisorRootkit } = await import("../ares/hypervisor_rootkit.ts")
    const r = await deployHypervisorRootkit({ live: ctx.live, esxiHost: params.esxi_host as string | undefined, keyId: params.key_id as string | undefined })
    return result("ares_hypervisor_rootkit", "deployHypervisorRootkit", ctx, r, r.artifacts.length > 0)
  },
  ares_airgap_bridge: async (ctx, params) => {
    const { runAirgapBridge } = await import("../ares/airgap_bridge.ts")
    const r = await runAirgapBridge({ live: ctx.live, payload: params.payload as string | undefined, channel: params.channel as "usb" | "rf" | "acoustic" | "all" | undefined })
    return result("ares_airgap_bridge", "runAirgapBridge", ctx, r, r.channels.length > 0)
  },
  ares_rat_builder: async (ctx, params) => {
    const { buildRat } = await import("../ares/rat_builder.ts")
    const r = await buildRat({ live: ctx.live, protocol: params.protocol as "custom_binary" | "https" | "dns" | "websocket" | undefined, c2Host: params.c2_host as string | undefined, c2Port: Number(params.c2_port ?? 8443) })
    return result("ares_rat_builder", "buildRat", ctx, r, r.artifacts.length > 0)
  },
  ares_supply_chain_implant: async (ctx, params) => {
    const { runSupplyChainImplant } = await import("../ares/supply_chain_implant.ts")
    const r = await runSupplyChainImplant({ live: ctx.live, package: params.package as string | undefined, projectDir: params.project_dir as string | undefined, ecosystem: params.ecosystem as string | undefined })
    return result("ares_supply_chain_implant", "runSupplyChainImplant", ctx, r, r.steps.some((s) => s.success))
  },
  ares_evasion_engine: async (ctx, params) => {
    const { runEvasionEngine } = await import("../ares/evasion_engine.ts")
    const r = await runEvasionEngine({ live: ctx.live, targetEdr: params.target_edr as string | undefined })
    return result("ares_evasion_engine", "runEvasionEngine", ctx, r, r.techniques.length > 0)
  },
  ares_satellite_c2: async (ctx, params) => {
    const { deploySatelliteC2 } = await import("../ares/satellite_c2.ts")
    const r = await deploySatelliteC2({ live: ctx.live, vsatHost: params.vsat_host as string | undefined, frontDomain: params.front_domain as string | undefined })
    return result("ares_satellite_c2", "deploySatelliteC2", ctx, r, r.artifacts.length > 0)
  },
  ares_ss7_exploit: async (ctx, params) => {
    const { runSs7Exploit } = await import("../ares/ss7_exploit.ts")
    const r = await runSs7Exploit({ live: ctx.live, msisdn: params.msisdn as string | undefined, gt: params.gt as string | undefined })
    return result("ares_ss7_exploit", "runSs7Exploit", ctx, r, r.operations.length > 0)
  },
  ares_hardware_implant: async (ctx, params) => {
    const { deployHardwareImplant } = await import("../ares/hardware_implant.ts")
    const r = await deployHardwareImplant({ live: ctx.live, type: params.type as "usb" | "rf" | "sdr" | "all" | undefined })
    return result("ares_hardware_implant", "deployHardwareImplant", ctx, r, r.artifacts.length > 0)
  },
  ares_kerberos_advanced: async (ctx, params) => {
    const { runKerberosAdvanced } = await import("../ares/kerberos_advanced.ts")
    const r = await runKerberosAdvanced({ live: ctx.live, domain: params.domain as string | undefined, domainSid: params.domain_sid as string | undefined, krbtgtHash: params.krbtgt_hash as string | undefined, dcMachineHash: params.dc_machine_hash as string | undefined })
    return result("ares_kerberos_advanced", "runKerberosAdvanced", ctx, r, r.techniques.length > 0)
  },
  ares_persistence_advanced: async (ctx, params) => {
    const { installAdvancedPersistence } = await import("../ares/persistence_advanced.ts")
    const r = await installAdvancedPersistence({ live: ctx.live, os: params.os as "windows" | "linux" | undefined, payload: params.payload as string | undefined })
    return result("ares_persistence_advanced", "installAdvancedPersistence", ctx, r, r.mechanisms.length > 0)
  },
  ares_lateral_scale: async (ctx, params) => {
    const { runLateralScale } = await import("../ares/lateral_scale.ts")
    const r = await runLateralScale({ live: ctx.live, target: String(params.target ?? hostFromTarget(ctx.target)), domain: params.domain as string | undefined, username: params.username as string | undefined, password: params.password as string | undefined })
    return result("ares_lateral_scale", "runLateralScale", ctx, r, r.steps.some((s) => s.success))
  },
  ares_anti_forensics_advanced: async (ctx, params) => {
    const { runAntiForensicsAdvanced } = await import("../ares/anti_forensics_advanced.ts")
    const r = await runAntiForensicsAdvanced({ live: ctx.live, pathsToTimestomp: params.paths as string[] | undefined })
    return result("ares_anti_forensics_advanced", "runAntiForensicsAdvanced", ctx, r, r.actions.length > 0)
  },
  ares_network_exploit: async (ctx, params) => {
    const { runNetworkExploit } = await import("../ares/network_exploit.ts")
    const r = await runNetworkExploit({ live: ctx.live, interface: params.interface as string | undefined, targetNetwork: params.network as string | undefined })
    return result("ares_network_exploit", "runNetworkExploit", ctx, r, r.attacks.length > 0)
  },
  ares_cloud_native: async (ctx, params) => {
    const { runCloudNativeAttack } = await import("../ares/cloud_native.ts")
    const r = await runCloudNativeAttack({ live: ctx.live, tenant: params.tenant as string | undefined, subscription: params.subscription as string | undefined })
    return result("ares_cloud_native", "runCloudNativeAttack", ctx, r, r.platforms.length > 0)
  },
  ares_ai_ml_attacks: async (ctx, params) => {
    const { runAiMlAttacks } = await import("../ares/ai_ml_attacks.ts")
    const r = await runAiMlAttacks({ live: ctx.live, targetUrl: params.target_url as string | undefined, llmEndpoint: params.llm_endpoint as string | undefined })
    return result("ares_ai_ml_attacks", "runAiMlAttacks", ctx, r, r.steps.some((s) => s.success) || r.capabilities.length > 0)
  },
  ares_orchestrator: async (ctx, params) => {
    const { runAresOrchestrator } = await import("../ares/orchestrator.ts")
    const r = await runAresOrchestrator({
      live: ctx.live,
      target: String(params.target ?? hostFromTarget(ctx.target)),
      domain: params.domain as string | undefined,
      projectDir: params.project_dir as string | undefined,
      autoChain: params.auto_chain !== false && params.auto_chain !== "false",
    })
    return result("ares_orchestrator", "runAresOrchestrator", ctx, r, r.succeeded > 0)
  },
  ares_auto_chain: async (ctx, params) => {
    const { runAresAutoChain } = await import("../ares/_chain.ts")
    const { CredentialGraph } = await import("../credential_graph.ts")
    const r = await runAresAutoChain({
      live: ctx.live,
      target: String(params.target ?? hostFromTarget(ctx.target)),
      domain: params.domain as string | undefined,
      credGraph: ctx.credGraph ?? CredentialGraph.load(),
      skipHarvest: params.skip_harvest === true || params.skip_harvest === "true",
    })
    return result("ares_auto_chain", "runAresAutoChain", ctx, r, r.phases.some((p) => p.success && !p.skipped))
  },
  ares_dispatch: async (ctx, params) => {
    const module = String(params.module ?? params.action ?? "")
    if (!module) {
      return result("ares_dispatch", "route", ctx, { error: "module required" }, false)
    }
    const { MODULE_BRIDGE } = await import("./index.ts")
    const candidates = [module, module.startsWith("ares_") ? module : `ares_${module}`, module.replace(/^ares_/, "")]
    for (const name of [...new Set(candidates)]) {
      const fn = MODULE_BRIDGE[name]
      if (fn) {
        const r = await fn(ctx, params)
        return { ...r, tool: "ares_dispatch", command: `→${name}` }
      }
    }
    const { normalizeModuleKey } = await import("../module_registry.ts")
    const { executeAgentTool } = await import("../agent_tools.ts")
    const agentKey = normalizeModuleKey(module)
    const agentResult = await executeAgentTool(ctx, agentKey, params)
    if (!agentResult.error?.includes("unknown tool")) {
      return result("ares_dispatch", `→${agentKey}`, ctx, agentResult, agentResult.success)
    }
    return result("ares_dispatch", "route", ctx, { error: `unknown module: ${module}` }, false)
  },
  ares_phase: async (ctx, params) => {
    const { runAresPhase } = await import("../ares/phase_runner.ts")
    const phase = String(params.phase ?? "recon") as import("../mcp_efficiency.ts").AresPhase
    const r = await runAresPhase({
      phase,
      target: String(params.target ?? hostFromTarget(ctx.target)),
      live: ctx.live,
      domain: params.domain as string | undefined,
      objective: params.objective as string | undefined,
      graph: ctx.graph,
      credGraph: ctx.credGraph,
    })
    return result("ares_phase", `phase:${phase}`, ctx, r, r.succeeded > 0)
  },
  ares_engagement_slice: async (ctx, params) => {
    const { runEngagementSlice } = await import("../engagement_slice.ts")
    const r = await runEngagementSlice({
      target: String(params.target ?? hostFromTarget(ctx.target)),
      live: ctx.live,
      scope: params.scope as string | undefined,
      objective: params.objective as string | undefined,
      phase: params.phase as import("../mcp_efficiency.ts").AresPhase | undefined,
    })
    return result("ares_engagement_slice", "runEngagementSlice", ctx, r, r.phaseResult.succeeded > 0)
  },
  ares_engagement_continue: async (ctx, params) => {
    const { runEngagementContinue } = await import("../engagement_slice.ts")
    const token = String(params.resumeToken ?? params.resume_token ?? "")
    if (!token) {
      return result("ares_engagement_continue", "runEngagementContinue", ctx, {
        error: "resumeToken required",
        summary: "missing resumeToken",
      }, false)
    }
    const r = await runEngagementContinue({
      resumeToken: token,
      phase: params.phase as import("../mcp_efficiency.ts").AresPhase | undefined,
    })
    return result("ares_engagement_continue", "runEngagementContinue", ctx, r, r.phaseResult.succeeded > 0)
  },
  ares_autopilot: async (ctx, params) => {
    const { runEngagementAutopilot } = await import("../engagement_autopilot.ts")
    const r = await runEngagementAutopilot({
      target: String(params.target ?? hostFromTarget(ctx.target)),
      scope: params.scope as string | undefined,
      maxPhases: params.maxPhases != null ? Number(params.maxPhases) : undefined,
      live: ctx.live,
    })
    return result("ares_autopilot", "runEngagementAutopilot", ctx, r, r.phasesRun > 0)
  },
  ares_exfil: async (ctx, params) => agentToolBridge(ctx, "exfil", params, "ares_exfil"),
  ares_ad_exploit: async (ctx, params) => agentToolBridge(ctx, "ad_exploit", params, "ares_ad_exploit"),
  edge_audit: async (ctx, params) => agentToolBridge(ctx, "edge_audit", params, "edge_audit"),
  esxi_audit: async (ctx, params) => agentToolBridge(ctx, "esxi_audit", params, "esxi_audit"),
  supply_chain_audit: async (ctx, params) => agentToolBridge(ctx, "supply_chain_audit", params, "supply_chain_audit"),
  lockfile_scan: async (ctx, params) => agentToolBridge(ctx, "lockfile_scan", params, "lockfile_scan"),
  cicd_audit: async (ctx, params) => agentToolBridge(ctx, "cicd_audit", params, "cicd_audit"),
  ai_agent_audit: async (ctx, params) => agentToolBridge(ctx, "ai_agent_audit", params, "ai_agent_audit"),
  rmm_audit: async (ctx, params) => {
    const { auditRmmAbuse } = await import("../rmm_audit.ts")
    const r = await auditRmmAbuse(String(params.target ?? ctx.target), { live: ctx.live })
    return result("rmm_audit", "auditRmmAbuse", ctx, r, r.findings.length > 0 || r.dryRun)
  },
  device_code_audit: async (ctx, params) => {
    const { auditDeviceCodeFlowAsync, auditDeviceCodeFlow } = await import("../device_code_phish.ts")
    const domain = String(params.target ?? ctx.target)
    const r = ctx.live
      ? await auditDeviceCodeFlowAsync(domain, { live: true, provider: params.provider as "entra" | "okta" | "google" | undefined })
      : auditDeviceCodeFlow(domain, { dryRun: !ctx.live, provider: params.provider as "entra" | "okta" | "google" | undefined })
    return result("device_code_audit", "auditDeviceCodeFlow", ctx, r, r.findings.length > 0 || r.dryRun)
  },
  chaindrop_oidc: async (ctx, params) => {
    const { auditChainDropOidc } = await import("../chaindrop_oidc.ts")
    const r = auditChainDropOidc(String(params.target ?? ctx.target), {
      dryRun: !ctx.live,
      repoPath: params.repoPath as string | undefined,
    })
    return result("chaindrop_oidc", "auditChainDropOidc", ctx, r, r.findings.length > 0 || r.dryRun)
  },
  aitm_playbook: async (ctx, params) => {
    const { buildAitmPlaybook } = await import("../aitm_playbook.ts")
    const r = buildAitmPlaybook(String(params.target ?? ctx.target), { dryRun: !ctx.live })
    return result("aitm_playbook", "buildAitmPlaybook", ctx, r, r.steps.length > 0)
  },
  iab_handoff_sim: async (ctx, params) => {
    const { runIabChain, applyIabChainToGraph } = await import("../iab_handoff_sim.ts")
    const { CredentialGraph } = await import("../credential_graph.ts")
    const chain = runIabChain(String(params.target ?? ctx.target), params.artifacts as string[] | undefined)
    const graph = new CredentialGraph()
    applyIabChainToGraph(graph, chain)
    return result("iab_handoff_sim", "runIabChain", ctx, { ...chain, graphNodes: graph.listCredentials().length }, true)
  },
} as const
