/**
 * @module ares/index
 * ARES APT-parity engine registry.
 */
export { runZeroDayFuzzer } from "./zero_day_fuzzer.ts"
export { buildFilelessImplant } from "./fileless_implant.ts"
export { deployFirmwareImplant } from "./firmware_implant.ts"
export { deployHypervisorRootkit } from "./hypervisor_rootkit.ts"
export { runAirgapBridge } from "./airgap_bridge.ts"
export { buildRat } from "./rat_builder.ts"
export { runSupplyChainImplant } from "./supply_chain_implant.ts"
export { runEvasionEngine } from "./evasion_engine.ts"
export { deploySatelliteC2 } from "./satellite_c2.ts"
export { runSs7Exploit } from "./ss7_exploit.ts"
export { deployHardwareImplant } from "./hardware_implant.ts"
export { runKerberosAdvanced } from "./kerberos_advanced.ts"
export { installAdvancedPersistence } from "./persistence_advanced.ts"
export { runLateralScale } from "./lateral_scale.ts"
export { runAntiForensicsAdvanced } from "./anti_forensics_advanced.ts"
export { runNetworkExploit } from "./network_exploit.ts"
export { runCloudNativeAttack } from "./cloud_native.ts"
export { runAiMlAttacks } from "./ai_ml_attacks.ts"
export { runInnovationEngine } from "./innovation_engine.ts"
export { runSelfHealing } from "./self_healing.ts"
export { runSelfImprovement } from "./self_improvement.ts"
export { runSpecializedImpact } from "./specialized_impact.ts"
export { runGhostAutonomy } from "./ghost_autonomy.ts"
export { runLateralMovement } from "./lateral_movement.ts"
export { runLiveVector01 } from "./custom_live_vector_01.ts"
export { runLotapiNotionC2 } from "./custom_lotapi_notion_c2.ts"
export { runShadowOrganization } from "./shadow_org.ts"
export { runSyndicateSpawn } from "./syndicate_spawn.ts"
export { runAntiForensics } from "./anti_forensics.ts"
export { runRansomwareEngagement as runRaasAdvanced } from "../raas_advanced.ts"
export { runMalwareFactory } from "./malware_factory.ts"
export { runFinancialWarfare } from "./financial_warfare.ts"
export { runCognitiveOps } from "./cognitive_ops.ts"
export { runSupplyChainCell as runSupplyChain } from "./supply_chain.ts"
export { runDeceptionEngine as runDeceptionNoise } from "./deception_noise.ts"
export { runC2Resilience } from "./c2_resilience.ts"

export { runAresOrchestrator } from "./orchestrator.ts"

export const ARES_MODULE_NAMES = [
  "ares_zero_day_fuzzer",
  "ares_fileless_implant",
  "ares_firmware_implant",
  "ares_hypervisor_rootkit",
  "ares_airgap_bridge",
  "ares_rat_builder",
  "ares_supply_chain_implant",
  "ares_evasion_engine",
  "ares_satellite_c2",
  "ares_ss7_exploit",
  "ares_hardware_implant",
  "ares_kerberos_advanced",
  "ares_persistence_advanced",
  "ares_lateral_scale",
  "ares_anti_forensics_advanced",
  "ares_network_exploit",
  "ares_cloud_native",
  "ares_ai_ml_attacks",
  "ares_innovation_engine",
  "ares_self_healing",
  "ares_self_improvement",
  "ares_specialized_impact",
  "ares_ghost_autonomy",
  "ares_lateral_movement",
  "ares_custom_live_vector_01",
  "ares_custom_lotapi_notion_c2",
  "ares_shadow_organization",
  "ares_syndicate_spawn",
  "ares_anti_forensics",
  "ares_raas_advanced",
  "ares_malware_factory",
  "ares_financial_warfare",
  "ares_cognitive_ops",
  "ares_supply_chain",
  "ares_deception_noise",
  "ares_satellite_c2",
  "ares_zero_day_fuzzer",
  "ares_fileless_implant",
  "ares_firmware_implant",
  "ares_hypervisor_rootkit",
  "ares_airgap_bridge",
  "ares_c2_resilience",
] as const

export type AresModuleName = (typeof ARES_MODULE_NAMES)[number]

export default { ARES_MODULE_NAMES }
