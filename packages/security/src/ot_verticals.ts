/**
 * @module ot_verticals
 * Critical infrastructure OT verticals — read-only live probes + semantic impact only.
 * DO NOT claim control; no write/command actions outside authorized lab restore paths.
 */
import type { TargetPersona } from "./target_flow.ts"

export type OtVertical =
  | "power_generation"
  | "power_grid"
  | "water_wastewater"
  | "chemical_process"
  | "rail_transport"
  | "oil_gas_pipeline"
  | "dam_flood_control"
  | "transport_port"
  | "telecom_backbone"

export const READ_ONLY_SAFETY_NOTE =
  "Read-only live probes + semantic impact narrative only — no control writes or operational commands."

export const XENOTIME_SAFETY_NOTE =
  "TRISIS-adjacent safety-system awareness only — read-only semantic probes; never attempt SIS/TRICONEX control logic writes."

export interface VerticalPortHint {
  port: number
  protocol: string
  service: string
  note: string
}

export interface OtVerticalDef {
  id: OtVertical
  label: string
  hints: RegExp
  persona: TargetPersona
  modules: string[]
  ports: VerticalPortHint[]
  safetyNote: string
  aptPlaybookId?: string
}

const BASE_SAFETY = READ_ONLY_SAFETY_NOTE

export const OT_VERTICALS: Record<OtVertical, OtVerticalDef> = {
  power_generation: {
    id: "power_generation",
    label: "Power generation plant",
    hints: /\b(power.?plant|generation.?plant|thermal.?plant|nuclear.?plant|boiler|turbine.?control|iec61850|61850|mms)\b/i,
    persona: "ot_scada_plant",
    modules: ["ot_batch_scan", "iot_scada", "institutional_recon"],
    ports: [
      { port: 102, protocol: "tcp", service: "IEC61850-MMS", note: "IEC 61850 MMS association (read-only probe)" },
      { port: 502, protocol: "tcp", service: "Modbus", note: "Plant RTU/PLC register read" },
      { port: 20000, protocol: "tcp", service: "DNP3", note: "DNP3 outstation read" },
    ],
    safetyNote: BASE_SAFETY,
    aptPlaybookId: "utility_scada",
  },
  power_grid: {
    id: "power_grid",
    label: "Power grid / substation",
    hints: /\b(substation|power.?grid|transmission.?grid|goose|sv\b|relay.?protection|switchyard|feeder)\b/i,
    persona: "ot_scada_plant",
    modules: ["profinet_l2", "ot_scan", "institutional_recon"],
    ports: [
      { port: 102, protocol: "tcp", service: "IEC61850-MMS", note: "Substation MMS / GOOSE-adjacent (L2 hints via profinet_l2)" },
      { port: 2404, protocol: "tcp", service: "IEC60870-5-104", note: "Telecontrol IEC-104" },
      { port: 20000, protocol: "tcp", service: "DNP3", note: "DNP3 validation / app read" },
    ],
    safetyNote: BASE_SAFETY,
    aptPlaybookId: "sandworm",
  },
  water_wastewater: {
    id: "water_wastewater",
    label: "Water / wastewater treatment",
    hints: /\b(water.?scada|wastewater|water.?treatment|sewage|pump.?station|bacnet.?bms|utility.?water)\b/i,
    persona: "ot_scada_plant",
    modules: ["ot_scan", "ics_impact_proof", "institutional_recon"],
    ports: [
      { port: 502, protocol: "tcp", service: "Modbus", note: "Pump/valve PLC — modbus semantic read" },
      { port: 47808, protocol: "udp", service: "BACnet", note: "BMS BACnet read-property / whois" },
      { port: 20000, protocol: "tcp", service: "DNP3", note: "SCADA outstation" },
    ],
    safetyNote: BASE_SAFETY,
    aptPlaybookId: "utility_scada",
  },
  chemical_process: {
    id: "chemical_process",
    label: "Chemical / process plant",
    hints: /\b(chemical.?plant|process.?plant|refinery|petrochemical|opc.?ua|sis\b|triconex|safety.?instrumented)\b/i,
    persona: "ot_plc",
    modules: ["ics_impact_proof", "institutional_recon"],
    ports: [
      { port: 4840, protocol: "tcp", service: "OPC-UA", note: "OPC-UA discovery / browse (read-only hints)" },
      { port: 502, protocol: "tcp", service: "Modbus", note: "Process PLC register semantic map" },
    ],
    safetyNote: XENOTIME_SAFETY_NOTE,
    aptPlaybookId: "xenotime",
  },
  rail_transport: {
    id: "rail_transport",
    label: "Rail / signaling",
    hints: /\b(rail.?signal|etcs|signaling|train.?control|metro.?scada|modbus.?rtu)\b/i,
    persona: "ot_scada_plant",
    modules: ["institutional_recon"],
    ports: [
      { port: 502, protocol: "tcp", service: "Modbus-RTU-TCP", note: "Wayside RTU read-only port map" },
      { port: 2404, protocol: "tcp", service: "IEC60870-5-104", note: "Signaling telecontrol" },
    ],
    safetyNote: BASE_SAFETY,
    aptPlaybookId: "utility_scada",
  },
  oil_gas_pipeline: {
    id: "oil_gas_pipeline",
    label: "Oil / gas pipeline",
    hints: /\b(pipeline|oil.?gas|gas.?transmission|compressor.?station|hart\b|midstream|upstream)\b/i,
    persona: "ot_scada_plant",
    modules: ["ot_batch_scan", "institutional_recon"],
    ports: [
      { port: 502, protocol: "tcp", service: "Modbus", note: "Compressor/valve RTU" },
      { port: 20000, protocol: "tcp", service: "DNP3", note: "Pipeline SCADA outstation" },
      { port: 5094, protocol: "udp", service: "HART-IP", note: "HART-IP field device hints (discovery only)" },
    ],
    safetyNote: BASE_SAFETY,
    aptPlaybookId: "utility_scada",
  },
  dam_flood_control: {
    id: "dam_flood_control",
    label: "Dam / flood control",
    hints: /\b(dam\b|flood.?control|reservoir|spillway|hydro.?dam|outstation)\b/i,
    persona: "ot_plc",
    modules: ["ot_scan", "institutional_recon"],
    ports: [
      { port: 20000, protocol: "tcp", service: "DNP3", note: "DNP3 outstation app read (existing ot_scan path)" },
      { port: 502, protocol: "tcp", service: "Modbus", note: "Gate/penstock PLC read" },
    ],
    safetyNote: BASE_SAFETY,
    aptPlaybookId: "utility_scada",
  },
  transport_port: {
    id: "transport_port",
    label: "Airport / port transport",
    hints: /\b(airport|port.?authority|seaport|harbor|terminal.?scada|baggage.?handling)\b/i,
    persona: "ot_scada_plant",
    modules: ["ot_batch_scan", "institutional_recon", "iot_scada"],
    ports: [
      { port: 502, protocol: "tcp", service: "Modbus", note: "Terminal automation PLC" },
      { port: 47808, protocol: "udp", service: "BACnet", note: "Building/HVAC BMS" },
    ],
    safetyNote: BASE_SAFETY,
    aptPlaybookId: "utility_scada",
  },
  telecom_backbone: {
    id: "telecom_backbone",
    label: "Telecom backbone",
    hints: /\b(telecom.?backbone|carrier.?core|backbone.?router|mpls.?core|sigtran|ss7.?gateway)\b/i,
    persona: "telecom_carrier",
    modules: ["telecom_audit", "net_device_audit", "institutional_recon"],
    ports: [
      { port: 5060, protocol: "udp", service: "SIP", note: "VoIP/SIP gateway hints" },
      { port: 443, protocol: "tcp", service: "NMS-HTTPS", note: "Network management plane" },
    ],
    safetyNote: BASE_SAFETY,
    aptPlaybookId: "salt_typhoon",
  },
}

/** Aggregate hint regex covering all critical-infra OT verticals. */
export const ALL_OT_VERTICAL_HINTS = new RegExp(
  Object.values(OT_VERTICALS).map((v) => v.hints.source).join("|"),
  "i",
)

const VERTICAL_PRIORITY: OtVertical[] = [
  "chemical_process",
  "power_grid",
  "power_generation",
  "dam_flood_control",
  "water_wastewater",
  "oil_gas_pipeline",
  "rail_transport",
  "transport_port",
  "telecom_backbone",
]

/** Detect OT vertical from hint + target strings. First match by priority. */
export function detectOtVertical(hint?: string, target?: string): OtVertical | null {
  const h = `${hint ?? ""} ${target ?? ""}`.trim()
  if (!h) return null
  for (const id of VERTICAL_PRIORITY) {
    if (OT_VERTICALS[id].hints.test(h)) return id
  }
  return null
}

export function verticalDef(id: OtVertical): OtVerticalDef {
  return OT_VERTICALS[id]
}

export function modulesForVertical(id: OtVertical): string[] {
  return [...OT_VERTICALS[id].modules]
}

export function portsForVertical(id: OtVertical): VerticalPortHint[] {
  return OT_VERTICALS[id].ports
}

export function personaForVertical(id: OtVertical): TargetPersona {
  return OT_VERTICALS[id].persona
}

export function aptPlaybookForVertical(id: OtVertical): string | undefined {
  return OT_VERTICALS[id].aptPlaybookId
}

/** True when target is a CIDR scoped to critical-infra OT (vertical or generic infra hint). */
export function isInfraCidrTarget(target: string, hint?: string): boolean {
  if (!target.includes("/")) return false
  return detectOtVertical(hint, target) != null || ALL_OT_VERTICAL_HINTS.test(`${hint ?? ""} ${target}`)
}

export default {
  detectOtVertical,
  verticalDef,
  modulesForVertical,
  portsForVertical,
  personaForVertical,
  aptPlaybookForVertical,
  isInfraCidrTarget,
  OT_VERTICALS,
  READ_ONLY_SAFETY_NOTE,
  XENOTIME_SAFETY_NOTE,
}
