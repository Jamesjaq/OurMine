/**
 * @module module_registry
 * Central resolution for playbook / intel module keys → bridge, agent, MCP, or external.
 */
import { MODULE_BRIDGE, bridgedToolNames } from "./module_bridge.ts"
import { AGENT_TOOL_NAMES } from "./agent_tools.ts"

/** Normalize legacy / MCP-prefixed keys to executable module names. */
export const MODULE_ALIASES: Record<string, string> = {
  ares_recon: "recon",
  ares_ad_exploit: "ad_exploit",
  ares_exfil: "exfil",
  ares_strix_web: "strix_web",
  ares_bountyhunter: "recon",
  bountyhunter: "recon",
  // apt_playbook_infra.json — infra + fallback chain keys
  backup_discovery: "raas_leak_catalog",
  cicd_token: "cicd_audit",
  cloud_lotc: "cloud_token",
  covert_c2: "c2_autonomous",
  dead_drop_dns_txt: "exfil",
  domain_front_cdn: "c2_infra",
  edge_implant: "ares_hardware_implant",
  exfil_staging: "collection_engine",
  mfa_fatigue: "identity_playbooks",
  npm_typosquat: "supply_chain_audit",
  redirector_vps: "c2_infra",
  tor_payment: "raas_payment",
  vishing_playbook: "helpdesk_social_auto",
  voip_vishing: "helpdesk_social_auto",
  device_code_phish: "device_code_audit",
  device_code_audit: "device_code_audit",
}

/** Tools routed outside MODULE_BRIDGE / agent_tools by design (MCP-only or HITL). */
export const EXTERNAL_MODULES_BY_DESIGN = new Set([
  "gh_grep",
  "aitm_proxy",
])

/** MCP-native tool names (handled in mcp_server.ts / mcp_dispatch.ts). */
export const MCP_NATIVE_TOOLS = new Set([
  "ares_recon",
  "ares_bountyhunter",
  "ares_scanner_parse",
  "ares_vuln_research",
  "ares_auto_research",
  "ares_identity",
  "ares_ad_exploit",
  "ares_hybrid_ad_entra",
  "ares_strix_web",
  "ares_oauth_chain",
  "ares_webmail_exploit",
  "ares_cloud_token",
  "ares_container_escape",
  "ares_audit_host",
  "ares_exfil",
  "ares_pivot_tunnel",
  "ares_c2",
  "ares_social_eng",
  "ares_payload_gen",
  "ares_malware_dev",
  "ares_yara_scan",
  "ares_iot_scada",
  "ares_mobile",
  "ares_firmware",
  "ares_counter_intel",
  "ares_pentest_plan",
  "ares_engagement_slice",
  "ares_engagement_continue",
  "ares_autopilot",
  "ares_artifact_get",
  "ares_pentest_run",
  "ares_caldera_ttp",
  "ares_atlas_ml",
  "ares_dev_target",
  "ares_supply_chain",
  "ares_campaign",
  "ares_skills_list",
  "ares_adcs_audit",
  "ares_esxi_audit",
  "ares_lolbins_audit",
  "ares_ebpf_audit",
  "ares_ai_agent_audit",
  "ares_edge_appliance_audit",
  "ares_idp_oauth_audit",
  "ares_uefi_bootkit_audit",
  "ares_cicd_k8s_audit",
  "ares_opsec_throttle",
  "ares_agent_resilience",
  "ares_intel_feed",
  "ares_threat_intel",
  "ares_intel_watch",
  "ares_vx_lookup",
  "ares_ai_surface",
  "ares_stix_ingest",
  "ares_device_code_audit",
  "ares_lateral_pathfinding",
  "ares_self_healing_check",
  "ares_technique_discovery",
])

export type ModuleResolutionKind = "bridge" | "agent" | "mcp" | "external" | "unresolved"

export interface ModuleResolution {
  kind: ModuleResolutionKind
  key: string
  resolved?: string
  note?: string
}

const bridgeSet = new Set(bridgedToolNames())
const agentSet = new Set(AGENT_TOOL_NAMES)

export function normalizeModuleKey(name: string): string {
  return MODULE_ALIASES[name] ?? name
}

export function resolveExecutableModule(name: string): ModuleResolution {
  const key = name.trim()
  if (!key) return { kind: "unresolved", key: name }
  const resolved = normalizeModuleKey(key)

  if (MODULE_BRIDGE[resolved]) return { kind: "bridge", key, resolved }
  if (agentSet.has(resolved)) return { kind: "agent", key, resolved }
  if (EXTERNAL_MODULES_BY_DESIGN.has(resolved)) {
    return { kind: "external", key, resolved, note: "MCP or HITL-only tool" }
  }
  if (MCP_NATIVE_TOOLS.has(key) || MCP_NATIVE_TOOLS.has(resolved)) {
    return { kind: "mcp", key, resolved: key }
  }
  if (key.startsWith("ares_")) return { kind: "mcp", key, resolved: key }
  return { kind: "unresolved", key }
}

export function isExecutableModule(name: string): boolean {
  const r = resolveExecutableModule(name)
  return r.kind === "bridge" || r.kind === "agent" || r.kind === "mcp"
}

/** Collect unresolved module keys from playbook / intel JSON sources. */
export function findUnresolvedModules(modules: string[]): string[] {
  const bad = new Set<string>()
  for (const m of modules) {
    const r = resolveExecutableModule(m)
    if (r.kind === "unresolved") bad.add(m)
  }
  return [...bad].sort()
}

/** SCADA actions advertised by ares_iot_scada MCP schema. */
export const MCP_SCADA_ACTIONS = ["enumerate", "read", "write", "fuzz", "exploit"] as const

/** Actions executeScadaAction handles (including aliases). */
export const SCADA_IMPLEMENTED_ACTIONS = new Set([
  "enumerate", "read", "read_registers", "read_holding", "write", "write_coil", "write_register",
  "fuzz", "exploit", "probe", "connect", "whois", "discover", "identify", "read_property", "validate",
])

export function scadaActionImplemented(action: string): boolean {
  return SCADA_IMPLEMENTED_ACTIONS.has(action.toLowerCase())
}

/** Firmware actions advertised by ares_firmware MCP schema. */
export const MCP_FIRMWARE_ACTIONS = [
  "extract", "entropy", "strings", "credentials", "patch", "uart_detect",
] as const

/** Actions executeFirmwareAction handles. */
export const FIRMWARE_IMPLEMENTED_ACTIONS = new Set([
  "extract", "entropy", "strings", "credentials", "patch", "uart_detect",
])

export function firmwareActionImplemented(action: string): boolean {
  return FIRMWARE_IMPLEMENTED_ACTIONS.has(action.toLowerCase())
}

export function listBridgedModuleKeys(): string[] {
  return [...bridgeSet].sort()
}

export default {
  MODULE_ALIASES,
  EXTERNAL_MODULES_BY_DESIGN,
  MCP_NATIVE_TOOLS,
  MCP_SCADA_ACTIONS,
  SCADA_IMPLEMENTED_ACTIONS,
  normalizeModuleKey,
  resolveExecutableModule,
  isExecutableModule,
  findUnresolvedModules,
  scadaActionImplemented,
  MCP_FIRMWARE_ACTIONS,
  FIRMWARE_IMPLEMENTED_ACTIONS,
  firmwareActionImplemented,
  listBridgedModuleKeys,
}
