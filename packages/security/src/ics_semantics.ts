/**
 * @module ics_semantics
 * Map raw Modbus/coils to process semantics (valve, interlock, setpoint) for impact narrative.
 */

export interface RegisterSemantic {
  address: number
  kind: "coil" | "holding" | "discrete" | "input"
  label: string
  unit?: string
  safetyCritical: boolean
}

/** Common SCADA address conventions (vendor-agnostic heuristics). */
export const DEFAULT_SEMANTICS: RegisterSemantic[] = [
  { address: 0, kind: "holding", label: "process_setpoint", unit: "raw", safetyCritical: false },
  { address: 1, kind: "holding", label: "process_feedback", unit: "raw", safetyCritical: false },
  { address: 100, kind: "coil", label: "main_valve", safetyCritical: true },
  { address: 101, kind: "coil", label: "aux_pump", safetyCritical: true },
  { address: 102, kind: "coil", label: "safety_interlock", safetyCritical: true },
  { address: 200, kind: "discrete", label: "e_stop_status", safetyCritical: true },
  { address: 201, kind: "discrete", label: "high_level_alarm", safetyCritical: true },
]

export interface SemanticProcessState {
  host: string
  observations: Array<{
    address: number
    label: string
    rawValue: number
    interpreted: string
    safetyCritical: boolean
  }>
  safetyInterlocks: string[]
  valveStates: string[]
  impactNarrative: string
  mitre: string
}

export function interpretCoil(value: number): string {
  return value !== 0 ? "ENERGIZED/OPEN" : "DE-ENERGIZED/CLOSED"
}

export function interpretRegister(value: number, unit?: string): string {
  if (unit === "percent") return `${Math.min(100, value)}%`
  if (value === 0) return "zero/off"
  if (value >= 0xffff - 1) return "max/full-scale"
  return `raw=${value}`
}

export function buildSemanticProcessState(
  host: string,
  registers: Array<{ address: number; value: number }>,
  semantics: RegisterSemantic[] = DEFAULT_SEMANTICS,
): SemanticProcessState {
  const observations: SemanticProcessState["observations"] = []
  const safetyInterlocks: string[] = []
  const valveStates: string[] = []

  for (const reg of registers) {
    const sem = semantics.find((s) => s.address === reg.address)
    if (!sem) continue
    const interpreted = sem.kind === "coil" || sem.kind === "discrete"
      ? interpretCoil(reg.value)
      : interpretRegister(reg.value, sem.unit)
    observations.push({
      address: reg.address,
      label: sem.label,
      rawValue: reg.value,
      interpreted,
      safetyCritical: sem.safetyCritical,
    })
    if (sem.label.includes("interlock") || sem.label.includes("e_stop")) {
      safetyInterlocks.push(`${sem.label}=${interpreted}`)
    }
    if (sem.label.includes("valve")) {
      valveStates.push(`${sem.label}=${interpreted}`)
    }
  }

  const critical = observations.filter((o) => o.safetyCritical)
  const narrative = critical.length
    ? `Process observable on ${host}: ${critical.map((o) => `${o.label}(${o.interpreted})`).join("; ")}`
    : registers.length
      ? `Generic register state on ${host} — map addresses in OURMINE_OT_SEMANTICS JSON for plant-specific labels`
      : `No semantic mapping matched — raw Modbus only`

  return {
    host,
    observations,
    safetyInterlocks,
    valveStates,
    impactNarrative: narrative,
    mitre: safetyInterlocks.length ? "T0827" : "T0855",
  }
}

export default { buildSemanticProcessState, DEFAULT_SEMANTICS }
