/**
 * @module target_flow
 * Adversarial flow routing: target persona → phases → modules.
 * Used by pentest_plan_builder and ares/phase_runner.
 */
import type { AresPhase } from "./mcp_efficiency.ts"
import type { TargetKind } from "./pentest_plan_builder.ts"
import {
  detectInstitutionalSector,
  type InstitutionalSector,
  HEALTHCARE_HINTS,
  BANKING_HINTS,
  FINANCE_HINTS,
  UNIVERSITY_HINTS,
  K12_HINTS,
  EDUCATION_HINTS,
  GOVERNMENT_HINTS,
  CORPORATE_OFFICE_HINTS,
  INSURANCE_HINTS,
  LEGAL_HINTS,
  TELECOM_OFFICE_HINTS,
  NGO_HINTS,
  CRITICAL_INFRA_HINTS,
  SAAS_HINTS,
  CAMPUS_WIFI_HINTS,
  sectorHintRegex,
  personaForSector,
  objectiveForSector,
} from "./institutional_hints.ts"
import {
  detectOtVertical,
  modulesForVertical,
  personaForVertical,
  type OtVertical,
} from "./ot_verticals.ts"

export type TargetPersona =
  | "enterprise_ad"
  | "web_app"
  | "cloud_saas"
  | "ot_plc"
  | "ot_scada_plant"
  | "iot_device"
  | "physical_usb"
  | "wireless_perimeter"
  | "telecom_carrier"
  | "esxi_hypervisor"
  | "container_k8s"
  | "ai_agent_surface"
  | "supply_chain_repo"
  | "hybrid_it_ot"
  | "generic_ip"

export type FlowObjective =
  | "standard"
  | "identity_first"
  | "ai_agent"
  | "supply_chain"
  | "cloud_ransom"
  | "ot_ics"
  | "telecom"
  | "ransomware_impact"
  | "extortion_only"
  | "hybrid_it_ot"
  | "proximity_physical"

export interface FlowProfile {
  target: string
  kind: TargetKind
  persona: TargetPersona
  isPrivate: boolean
  isAdLikely: boolean
  isWebLikely: boolean
  isOtLikely: boolean
  isTelecomLikely: boolean
  isEsxiLikely: boolean
  isAiLikely: boolean
  isUsbLikely: boolean
  isWirelessLikely: boolean
  isBleLikely: boolean
  institutionalSector: InstitutionalSector | null
  otVertical: OtVertical | null
  scope: string[]
}

const PRIVATE_IP = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/

const OT_HINTS = /\b(modbus|scada|plc|bacnet|dnp3|ics|ot\b|hmi|s7|profinet|mqtt|47808|502|iec61850|61850|mms|goose)\b/i
const TELECOM_HINTS = /\b(ss7|sip|diameter|carrier|telco|5g|lte|msc|hlr|smsc|sigtran)\b/i
const ESXI_HINTS = /\b(esxi|vcenter|vmware|hypervisor|vmdk)\b/i
const AI_HINTS = /\b(llm|langflow|nacos|n8n|minio|agentic|openai|rag)\b/i
const OT_HOST_HINTS = /\b(plc|hmi|scada|rtu|dcs|sensor|gateway|iot)\b/i
const USB_HINTS = /\b(usb|badusb|rubber ducky|physical|hid|ducky|lobby drop)\b/i
const WIFI_HINTS = /\b(wifi|wlan|wireless|802\.11|ssid|evil.?twin|perimeter)\b/i
const BLE_HINTS = /\b(ble|bluetooth|smart lock|beacon|gatt)\b/i

export function classifyTargetKind(target: string): TargetKind {
  const t = target.trim()
  if (/^https?:\/\//i.test(t)) return "url"
  if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(t)) return "cidr"
  if (/^\d+\.\d+\.\d+\.\d+$/.test(t)) return "ip"
  if (t.includes(".") && /^[a-z0-9.-]+$/i.test(t)) return "domain"
  return "hostname"
}

export function buildFlowProfile(target: string, scope?: string, hint?: string): FlowProfile {
  const kind = classifyTargetKind(target)
  const h = (hint ?? target).toLowerCase()
  const isPrivate = kind === "ip" && PRIVATE_IP.test(target)
  const isAdLikely = kind === "domain" && !target.endsWith(".local") && target.split(".").length >= 2
    && !OT_HOST_HINTS.test(target) && !TELECOM_HINTS.test(h)
    && !USB_HINTS.test(h) && !WIFI_HINTS.test(h) && !BLE_HINTS.test(h)
  const isWebLikely = kind === "url" || (kind === "domain" && !OT_HOST_HINTS.test(target))
  const isTelecomLikely = TELECOM_HINTS.test(h) || TELECOM_HINTS.test(target)
  // Private IP alone is NOT OT — require explicit OT hints or CIDR plant scope.
  const isOtLikely = OT_HINTS.test(h) || OT_HOST_HINTS.test(target)
    || kind === "cidr"
  const isEsxiLikely = ESXI_HINTS.test(h)
  const isAiLikely = AI_HINTS.test(h) || (isWebLikely && AI_HINTS.test(target))
  const isUsbLikely = USB_HINTS.test(h)
  const isWirelessLikely = WIFI_HINTS.test(h) || CAMPUS_WIFI_HINTS.test(h)
  const isBleLikely = BLE_HINTS.test(h) || (isOtLikely && BLE_HINTS.test(h))
  const institutionalSector = detectInstitutionalSector(hint, target)
  const otVertical = detectOtVertical(hint, target)
  const scopeList = scope
    ? scope.split(",").map((s) => s.trim()).filter(Boolean)
    : [target]

  let persona: TargetPersona = "generic_ip"
  if (isUsbLikely) persona = "physical_usb"
  else if (isWirelessLikely) persona = "wireless_perimeter"
  else if (isBleLikely && !isOtLikely) persona = "iot_device"
  else if (isBleLikely || BLE_HINTS.test(h)) persona = "iot_device"
  else if (isOtLikely && isTelecomLikely) persona = "hybrid_it_ot"
  else if (isOtLikely) persona = OT_HOST_HINTS.test(target) ? "ot_plc" : "ot_scada_plant"
  else if (isTelecomLikely) persona = "telecom_carrier"
  else if (isEsxiLikely) persona = "esxi_hypervisor"
  else if (isAiLikely) persona = "ai_agent_surface"
  else if (isAdLikely) persona = "enterprise_ad"
  else if (isWebLikely) persona = kind === "url" ? "web_app" : "cloud_saas"
  else if (kind === "ip" && isPrivate) persona = "generic_ip"
  else if (kind === "cidr") persona = "ot_scada_plant"

  if (h.includes("k8s") || h.includes("kubernetes") || h.includes("docker")) persona = "container_k8s"
  if (h.includes("npm") || h.includes("github") || h.includes("supply")) persona = "supply_chain_repo"
  if (institutionalSector) {
    const sectorRe = sectorHintRegex(institutionalSector)
    if (sectorRe.test(h)) {
      const sectorPersona = personaForSector(institutionalSector)
      if (institutionalSector === "healthcare" && (HEALTHCARE_HINTS.test(h) || /\b(medical|pacs|dicom)\b/.test(h))) {
        persona = isOtLikely ? "ot_plc" : "iot_device"
      } else if (institutionalSector === "university" || institutionalSector === "k12_school") {
        persona = "wireless_perimeter"
      } else if (institutionalSector === "telecom_office") {
        persona = "telecom_carrier"
      } else if (institutionalSector === "legal") {
        persona = "web_app"
      } else if (institutionalSector === "critical_infra") {
        persona = otVertical ? personaForVertical(otVertical) : "ot_scada_plant"
      } else if (sectorPersona === "enterprise_ad" && isAdLikely) {
        persona = "enterprise_ad"
      } else if (sectorPersona !== "generic_ip") {
        persona = sectorPersona
      }
    }
  }
  if (h === "proximity_physical" || h.includes("proximity_physical")) {
    if (persona === "generic_ip" || persona === "cloud_saas" || persona === "web_app") {
      if (isUsbLikely) persona = "physical_usb"
      else if (isWirelessLikely) persona = "wireless_perimeter"
      else if (isBleLikely) persona = "iot_device"
    }
  }

  if (otVertical && (institutionalSector === "critical_infra" || isOtLikely)) {
    persona = personaForVertical(otVertical)
  }

  return {
    target, kind, persona, isPrivate, isAdLikely, isWebLikely,
    isOtLikely, isTelecomLikely, isEsxiLikely, isAiLikely,
    isUsbLikely, isWirelessLikely, isBleLikely, institutionalSector, otVertical, scope: scopeList,
  }
}

export function inferFlowObjective(profile: FlowProfile, hint?: string): FlowObjective {
  const h = (hint ?? "").toLowerCase()
  if (profile.isUsbLikely || profile.isWirelessLikely || profile.isBleLikely
    || h.includes("proximity") || h.includes("physical access")) return "proximity_physical"
  if (h.includes("hybrid") || h.includes("it-ot") || h.includes("volt") || /\bpivot\b/.test(h)) return "hybrid_it_ot"
  if (/\b(ics|scada|modbus|plc|dnp3|bacnet|iec61850|61850|mms)\b/.test(h) || h.includes("ot_ics")) return "ot_ics"
  if (profile.institutionalSector) {
    if (!hint?.trim() || sectorHintRegex(profile.institutionalSector).test(h) || h.includes(profile.institutionalSector)) {
      return objectiveForSector(profile.institutionalSector)
    }
  }
  if (CRITICAL_INFRA_HINTS.test(h)) return "ot_ics"
  if (SAAS_HINTS.test(h)) return "identity_first"
  if (UNIVERSITY_HINTS.test(h) || K12_HINTS.test(h) || EDUCATION_HINTS.test(h)) return "proximity_physical"
  if (BANKING_HINTS.test(h) || FINANCE_HINTS.test(h)) return "identity_first"
  if (GOVERNMENT_HINTS.test(h)) return "identity_first"
  if (CORPORATE_OFFICE_HINTS.test(h)) return "identity_first"
  if (INSURANCE_HINTS.test(h)) return "identity_first"
  if (LEGAL_HINTS.test(h)) return "standard"
  if (TELECOM_OFFICE_HINTS.test(h)) return "telecom"
  if (NGO_HINTS.test(h)) return "identity_first"
  if (HEALTHCARE_HINTS.test(h)) return "ot_ics"
  if (h.includes("telecom") || h.includes("ss7") || h.includes("sip")) return "telecom"
  if (h.includes("extortion") && !h.includes("encrypt")) return "extortion_only"
  if (h.includes("ransom") || h.includes("encrypt") || h.includes("raas")) return "ransomware_impact"
  if (/\b(identity|entra)\b/.test(h) || /\bad\b/.test(h)) return "identity_first"
  if (h.includes("supply") || h.includes("ci/cd") || h.includes("npm")) return "supply_chain"
  if (h.includes("esxi") || h.includes("cloud")) return "cloud_ransom"
  if (h.includes("ai") || h.includes("llm") || h.includes("agent")) return "ai_agent"

  if (profile.persona === "physical_usb" || profile.persona === "wireless_perimeter") return "proximity_physical"
  if (profile.persona === "hybrid_it_ot") return "hybrid_it_ot"
  if (profile.persona === "ot_plc" || profile.persona === "ot_scada_plant") return "ot_ics"
  if (profile.persona === "telecom_carrier") return "telecom"
  if (profile.persona === "esxi_hypervisor") return "cloud_ransom"
  if (profile.persona === "ai_agent_surface") return "ai_agent"
  if (profile.persona === "enterprise_ad") return "identity_first"
  if (profile.persona === "supply_chain_repo") return "supply_chain"
  if (profile.isAdLikely) return "identity_first"
  if (profile.isWebLikely && !profile.isPrivate) return "ai_agent"
  return "standard"
}

export function phasesForObjective(objective: FlowObjective): AresPhase[] {
  switch (objective) {
    case "ot_ics": return ["recon", "exploit", "post_ex", "apt"]
    case "hybrid_it_ot": return ["recon", "exploit", "post_ex", "apt"]
    case "telecom": return ["recon", "exploit", "post_ex", "apt"]
    case "ransomware_impact": return ["recon", "exploit", "post_ex", "apt"]
    case "extortion_only": return ["recon", "exploit", "post_ex", "apt"]
    case "identity_first": return ["recon", "identity", "exploit", "post_ex"]
    case "supply_chain": return ["recon", "exploit", "post_ex"]
    case "cloud_ransom": return ["recon", "exploit", "post_ex", "apt"]
    case "ai_agent": return ["recon", "exploit", "post_ex"]
    case "proximity_physical": return ["recon", "exploit", "post_ex", "apt"]
    default: return ["recon", "identity", "exploit", "post_ex"]
  }
}

/** Server-side module names for ares_phase (bridge keys). */
export function modulesForPhase(phase: AresPhase, profile: FlowProfile, objective: FlowObjective): string[] {
  const isCloudPersona = profile.persona === "cloud_saas"
    || profile.persona === "container_k8s"
    || profile.persona === "esxi_hypervisor"
    || objective === "cloud_ransom"
  const isWebPersona = profile.persona === "web_app"
    || profile.persona === "ai_agent_surface"
    || (profile.isWebLikely && objective === "ai_agent")
  const isAdPersona = (profile.persona === "enterprise_ad" || objective === "identity_first" || profile.isAdLikely)
    && profile.persona !== "web_app"
    && profile.institutionalSector !== "legal"

  switch (phase) {
    case "recon":
      if (objective === "proximity_physical" || profile.isUsbLikely || profile.isWirelessLikely || profile.isBleLikely) {
        const mods = ["ares_intel_feed"]
        if (profile.isUsbLikely || profile.persona === "physical_usb") mods.push("usb_audit")
        if (profile.isWirelessLikely || profile.persona === "wireless_perimeter") mods.push("wifi_audit")
        if (profile.isBleLikely || profile.persona === "iot_device") mods.push("ble_audit")
        if (profile.institutionalSector === "university" || profile.institutionalSector === "k12_school") {
          mods.unshift("institutional_recon")
        }
        if (mods.length === 1) mods.push("proximity_audit")
        mods.push("ares_recon", "net_device_audit")
        return mods
      }
      if (objective === "hybrid_it_ot") {
        return ["ares_intel_feed", "ares_recon", "net_device_audit", "ares_vuln_research"]
      }
      if (objective === "ot_ics" || profile.isOtLikely) {
        const mods = ["ares_intel_feed", "ot_scan", "net_device_audit", "ares_vuln_research"]
        if (profile.kind === "cidr" || profile.target.includes("/")) mods.unshift("ot_batch_scan")
        if (profile.institutionalSector === "critical_infra") mods.unshift("institutional_recon")
        if (profile.otVertical) {
          for (const m of modulesForVertical(profile.otVertical)) {
            if (!mods.includes(m)) mods.unshift(m)
          }
        }
        if (profile.institutionalSector === "healthcare") mods.push("institutional_recon")
        return mods
      }
      if (objective === "telecom" || profile.isTelecomLikely) {
        return ["ares_intel_feed", "telecom_audit", "net_device_audit", "ares_recon", "ares_vuln_research"]
      }
      if (objective === "supply_chain" || profile.persona === "supply_chain_repo") {
        return [
          "ares_intel_feed", "supply_chain_exec", "ares_supply_chain_implant",
          "cicd_audit", "lockfile_scan", "supply_chain_audit", "ares_recon",
        ]
      }
      if (isCloudPersona) {
        const mods = ["ares_intel_feed", "cloud_enum", "ares_cloud_native", "ares_recon", "ares_vuln_research"]
        if (profile.institutionalSector === "saas") mods.unshift("institutional_recon")
        return mods
      }
      if (objective === "cloud_ransom" || profile.isEsxiLikely) {
        return ["ares_intel_feed", "cloud_enum", "ares_cloud_native", "ares_recon", "edge_audit", "ares_esxi_audit"]
      }
      if (isAdPersona) {
        const mods = ["ares_intel_feed", "ares_recon", "net_device_audit", "ares_bountyhunter", "ares_vuln_research"]
        if (
          profile.institutionalSector === "banking"
          || profile.institutionalSector === "government"
          || profile.institutionalSector === "corporate_office"
          || profile.institutionalSector === "insurance"
        ) {
          mods.unshift("institutional_recon")
        }
        return mods
      }
      if (isWebPersona) {
        const mods = ["ares_intel_feed", "ares_recon", "ares_bountyhunter", "ares_vuln_research"]
        if (profile.institutionalSector === "legal") mods.unshift("institutional_recon", "app_security_engine")
        return mods
      }
      return ["ares_intel_feed", "ares_recon", "ares_bountyhunter", "ares_vuln_research", "net_device_audit"]

    case "identity":
      if (skipAdAutoChain(profile, objective)) return []
      if (!isAdPersona) return []
      return ["cred_access_auto", "ares_kerberos_advanced", "ares_lateral_scale"]

    case "exploit":
      if (objective === "proximity_physical" || profile.persona === "physical_usb" || profile.persona === "wireless_perimeter") {
        const mods = ["ares_network_exploit"]
        if (profile.isUsbLikely || profile.persona === "physical_usb") mods.unshift("ares_hardware_implant")
        if (profile.isWirelessLikely || profile.persona === "wireless_perimeter") mods.unshift("wifi_audit")
        if (profile.isBleLikely) mods.unshift("ble_audit")
        return mods
      }
      if (objective === "hybrid_it_ot") {
        return ["strix_web", "ares_ad_exploit", "iot_scada", "ares_network_exploit"]
      }
      if (objective === "ot_ics" || profile.isOtLikely) {
        return ["iot_scada", "telecom_audit", "ares_network_exploit", "strix_web"]
      }
      if (objective === "telecom") {
        return ["telecom_audit", "ares_ss7_exploit", "ares_network_exploit"]
      }
      if (objective === "supply_chain" || profile.persona === "supply_chain_repo") {
        return ["ares_supply_chain_implant", "supply_chain_exec", "exploit_adapter", "strix_web"]
      }
      if (objective === "extortion_only") {
        return ["collection_engine", "raas_leak_catalog", "raas_tor_portal", "impact_assess"]
      }
      if (objective === "ransomware_impact" || objective === "cloud_ransom") {
        return ["ares_evasion_engine", "ares_cloud_native", "strix_web", "ares_network_exploit", "esxi_audit"]
      }
      if (isWebPersona) {
        return ["app_security_engine", "strix_web", "ares_network_exploit"]
      }
      if (isCloudPersona) {
        return ["ares_cloud_native", "cloud_enum", "strix_web", "ares_network_exploit"]
      }
      if (isAdPersona) {
        return ["ares_evasion_engine", "strix_web", "ares_network_exploit", "ares_ad_exploit"]
      }
      return ["ares_evasion_engine", "strix_web", "ares_network_exploit", "ares_ad_exploit"]

    case "post_ex":
      if (objective === "ot_ics" || (profile.isOtLikely && !profile.isAdLikely)) {
        return ["ics_impact_proof", "impact_assess", "ares_exfil", "ares_anti_forensics_advanced"]
      }
      if (objective === "hybrid_it_ot") {
        return ["ics_impact_proof", "impact_assess", "ares_exfil", "ares_anti_forensics_advanced", "segment_tunnel"]
      }
      if (objective === "supply_chain" || profile.persona === "supply_chain_repo") {
        return ["campaign_loop", "collection_engine", "impact_assess", "ares_exfil"]
      }
      if (objective === "extortion_only") {
        return ["collection_engine", "raas_leak_catalog", "raas_tor_portal", "impact_assess"]
      }
      if (objective === "ransomware_impact" || objective === "cloud_ransom") {
        return ["raas_campaign", "esxi_audit", "impact_assess", "ares_anti_forensics_advanced"]
      }
      if (isWebPersona || isCloudPersona) {
        return ["impact_assess", "ares_exfil", "ares_anti_forensics_advanced"]
      }
      if (isAdPersona) {
        return ["ares_auto_chain", "ares_anti_forensics_advanced"]
      }
      return ["impact_assess", "ares_exfil", "ares_anti_forensics_advanced"]

    case "apt":
      if (objective === "proximity_physical" || profile.isUsbLikely) {
        return ["ares_hardware_implant", "ares_airgap_bridge", "ares_orchestrator"]
      }
      if (objective === "ot_ics" || profile.isOtLikely) {
        return ["ares_firmware_implant", "ares_airgap_bridge", "ares_hardware_implant", "ares_orchestrator"]
      }
      if (objective === "telecom") {
        return ["ares_ss7_exploit", "ares_satellite_c2", "ares_orchestrator"]
      }
      if (isCloudPersona || objective === "cloud_ransom") {
        return ["ares_cloud_native", "ares_orchestrator"]
      }
      return ["ares_orchestrator"]
  }
}

export function skipAdAutoChain(profile: FlowProfile, objective: FlowObjective): boolean {
  return (profile.isOtLikely && !profile.isAdLikely)
    || objective === "ot_ics"
    || objective === "hybrid_it_ot"
    || objective === "telecom"
    || objective === "ai_agent"
    || profile.persona === "ot_plc"
    || profile.persona === "iot_device"
    || profile.persona === "web_app"
    || profile.persona === "cloud_saas"
    || profile.persona === "container_k8s"
    || profile.persona === "ai_agent_surface"
    || profile.persona === "telecom_carrier"
    || profile.persona === "physical_usb"
    || profile.persona === "wireless_perimeter"
    || objective === "proximity_physical"
}

export default {
  buildFlowProfile,
  inferFlowObjective,
  phasesForObjective,
  modulesForPhase,
  skipAdAutoChain,
}
