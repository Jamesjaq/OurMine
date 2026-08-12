/**
 * @module ics_validation
 * ICS/SCADA finding validation — Modbus, BACnet, DNP3 read probes (non-destructive).
 */
import {
  readModbusHoldingRegisters, probeDnp3, bacnetWhoIs, bacnetValidateDevice,
  probeMqtt, probeCoap, probeS7,
} from "./iot_scada.ts"
import type { ValidationPlan, ValidationResult } from "./validation_planner.ts"
import { resolveLiveMode } from "./exec_options.ts"
import { dedupeProbe, probeFingerprint } from "./probe_dedupe.ts"

function baseUnavailable(plan: ValidationPlan, t0: number, msg: string): ValidationResult {
  return {
    planId: plan.planId,
    findingId: plan.findingId,
    outcome: "VALIDATION_UNAVAILABLE",
    evidence: msg,
    executionMs: Date.now() - t0,
    timestamp: new Date().toISOString(),
    reasoning: msg,
  }
}

function successResult(plan: ValidationPlan, t0: number, evidence: string, reasoning: string): ValidationResult {
  return {
    planId: plan.planId,
    findingId: plan.findingId,
    outcome: "VALIDATION_SUCCESS",
    evidence,
    executionMs: Date.now() - t0,
    timestamp: new Date().toISOString(),
    reasoning,
  }
}

function negativeResult(plan: ValidationPlan, t0: number, evidence: string, reasoning: string, timeout = false): ValidationResult {
  return {
    planId: plan.planId,
    findingId: plan.findingId,
    outcome: timeout ? "VALIDATION_TIMEOUT" : "VALIDATION_NEGATIVE",
    evidence,
    executionMs: Date.now() - t0,
    timestamp: new Date().toISOString(),
    reasoning,
  }
}

export async function modbusValidationProbe(
  plan: ValidationPlan,
  ip: string,
  port: number,
  t0: number,
): Promise<ValidationResult> {
  if (!resolveLiveMode()) return baseUnavailable(plan, t0, "live required for Modbus validation")

  const fp = probeFingerprint("modbus_validate", `${ip}:${port || 502}`)
  const { result } = await dedupeProbe(fp, async () => {
    try {
      const r = await readModbusHoldingRegisters(ip, port || 502, 1, 0, 4, true)
      const evidence = JSON.stringify({
        fc: r.fc,
        registerCount: r.data?.length ?? 0,
        registers: r.data?.slice(0, 8),
        success: r.success,
        error: r.error,
        dryRun: r.dryRun,
      })
      if (r.success && r.data && r.data.length > 0) {
        return successResult(plan, t0, evidence, `Modbus FC3 read returned ${r.data.length} register(s) on ${ip}:${port || 502}`)
      }
      return negativeResult(plan, t0, evidence, r.error ?? "Modbus read returned no registers", r.error?.includes("timeout"))
    } catch (err) {
      return negativeResult(plan, t0, String((err as Error).message), "Modbus validation threw")
    }
  })
  return result
}

export async function dnp3ValidationProbe(
  plan: ValidationPlan,
  ip: string,
  port: number,
  t0: number,
): Promise<ValidationResult> {
  if (!resolveLiveMode()) return baseUnavailable(plan, t0, "live required for DNP3 validation")

  try {
    const r = await probeDnp3(ip, port || 20000, true)
    const data = r.data as { linkAck?: boolean; appReadOk?: boolean; linkOnly?: boolean } | undefined
    const evidence = JSON.stringify({
      success: r.success,
      linkAck: data?.linkAck,
      appReadOk: data?.appReadOk,
      linkOnly: data?.linkOnly,
      rawHex: r.rawHex?.slice(0, 64),
      error: r.error,
    })
    if (r.success && data?.appReadOk) {
      return successResult(plan, t0, evidence, `DNP3 application-layer IIN read confirmed on ${ip}:${port || 20000}`)
    }
    if (data?.linkOnly) {
      return successResult(plan, t0, evidence, `DNP3 link-layer only on ${ip}:${port || 20000} — app read pending`)
    }
    if (r.success) {
      return successResult(plan, t0, evidence, `DNP3 probe responded on ${ip}:${port || 20000}`)
    }
    return negativeResult(plan, t0, evidence, r.error ?? "DNP3 no response", r.error?.includes("timeout"))
  } catch (err) {
    return negativeResult(plan, t0, String((err as Error).message), "DNP3 validation threw")
  }
}

export async function bacnetValidationProbe(
  plan: ValidationPlan,
  ip: string,
  port: number,
  t0: number,
): Promise<ValidationResult> {
  if (!resolveLiveMode()) return baseUnavailable(plan, t0, "live required for BACnet validation")

  try {
    const r = await bacnetValidateDevice(ip, port || 47808, true)
    const data = r.data as { whoisOk?: boolean; readPropertyOk?: boolean; deviceInstance?: number | null } | undefined
    const evidence = JSON.stringify({
      success: r.success,
      whoisOk: data?.whoisOk,
      readPropertyOk: data?.readPropertyOk,
      deviceInstance: data?.deviceInstance,
      rawHex: r.rawHex?.slice(0, 64),
      error: r.error,
    })
    if (r.success && data?.readPropertyOk) {
      return successResult(plan, t0, evidence, `BACnet Read Property (object-name) confirmed on ${ip}:${port || 47808}`)
    }
    const whois = await bacnetWhoIs(ip, port || 47808, true)
    const whoisEvidence = JSON.stringify({ whois: whois.success, validate: r.success, error: r.error ?? whois.error })
    if (whois.success) {
      return successResult(plan, t0, whoisEvidence, `BACnet Who-Is responded on ${ip}:${port || 47808} — Read Property pending`)
    }
    return negativeResult(plan, t0, evidence, r.error ?? whois.error ?? "BACnet no response", (r.error ?? whois.error)?.includes("timeout"))
  } catch (err) {
    return negativeResult(plan, t0, String((err as Error).message), "BACnet validation threw")
  }
}

export async function mqttValidationProbe(
  plan: ValidationPlan,
  ip: string,
  port: number,
  t0: number,
): Promise<ValidationResult> {
  if (!resolveLiveMode()) return baseUnavailable(plan, t0, "live required for MQTT validation")

  try {
    const r = await probeMqtt(ip, port || 1883, "ourmine_validate", true)
    const data = r.data as { connAck?: boolean; code?: number } | undefined
    const evidence = JSON.stringify({
      success: r.success,
      connAck: data?.connAck,
      code: data?.code,
      error: r.error,
    })
    if (r.success && data?.connAck) {
      return successResult(plan, t0, evidence, `MQTT CONNACK confirmed on ${ip}:${port || 1883}`)
    }
    return negativeResult(plan, t0, evidence, r.error ?? "MQTT no CONNACK", r.error?.includes("timeout"))
  } catch (err) {
    return negativeResult(plan, t0, String((err as Error).message), "MQTT validation threw")
  }
}

export async function coapValidationProbe(
  plan: ValidationPlan,
  ip: string,
  port: number,
  t0: number,
): Promise<ValidationResult> {
  if (!resolveLiveMode()) return baseUnavailable(plan, t0, "live required for CoAP validation")

  try {
    const r = await probeCoap(ip, port || 5683, true)
    const data = r.data as { bytes?: number; coapVer?: number; coapCode?: number } | undefined
    const evidence = JSON.stringify({
      success: r.success,
      coapVer: data?.coapVer,
      coapCode: data?.coapCode,
      bytes: data?.bytes,
      rawHex: r.rawHex?.slice(0, 64),
      error: r.error,
    })
    if (r.success) {
      return successResult(plan, t0, evidence, `CoAP /.well-known/core discovery confirmed on ${ip}:${port || 5683}`)
    }
    return negativeResult(plan, t0, evidence, r.error ?? "CoAP no response", r.error?.includes("timeout"))
  } catch (err) {
    return negativeResult(plan, t0, String((err as Error).message), "CoAP validation threw")
  }
}

export async function s7ValidationProbe(
  plan: ValidationPlan,
  ip: string,
  port: number,
  t0: number,
): Promise<ValidationResult> {
  if (!resolveLiveMode()) return baseUnavailable(plan, t0, "live required for S7 validation")

  try {
    const r = await probeS7(ip, port || 102, true)
    const data = r.data as { cotpOk?: boolean; setupCommOk?: boolean; tcpOnly?: boolean } | undefined
    const evidence = JSON.stringify({
      success: r.success,
      cotpOk: data?.cotpOk,
      setupCommOk: data?.setupCommOk,
      tcpOnly: data?.tcpOnly,
      rawHex: r.rawHex?.slice(0, 64),
      error: r.error,
    })
    if (r.success && data?.setupCommOk) {
      return successResult(plan, t0, evidence, `S7comm Setup Communication confirmed on ${ip}:${port || 102}`)
    }
    if (data?.cotpOk) {
      return successResult(plan, t0, evidence, `S7 COTP handshake on ${ip}:${port || 102} — Setup Comm pending`)
    }
    if (data?.tcpOnly) {
      return successResult(plan, t0, evidence, `S7 port open on ${ip}:${port || 102} — ISO-on-TCP pending`)
    }
    return negativeResult(plan, t0, evidence, r.error ?? "S7 no response", r.error?.includes("timeout"))
  } catch (err) {
    return negativeResult(plan, t0, String((err as Error).message), "S7 validation threw")
  }
}

export async function icsValidationProbe(
  plan: ValidationPlan,
  ip: string,
  port: number,
  t0: number,
): Promise<ValidationResult> {
  const svc = plan.serviceHint ?? ""
  if (/bacnet|47808/i.test(svc)) return bacnetValidationProbe(plan, ip, port, t0)
  if (/dnp3|20000/i.test(svc)) return dnp3ValidationProbe(plan, ip, port, t0)
  if (/mqtt|1883/i.test(svc)) return mqttValidationProbe(plan, ip, port, t0)
  if (/coap|5683/i.test(svc)) return coapValidationProbe(plan, ip, port, t0)
  if (/s7|siemens|profinet|\b102\b/i.test(svc)) return s7ValidationProbe(plan, ip, port, t0)
  return modbusValidationProbe(plan, ip, port, t0)
}

export default {
  modbusValidationProbe, dnp3ValidationProbe, bacnetValidationProbe,
  mqttValidationProbe, coapValidationProbe, s7ValidationProbe,
  icsValidationProbe,
}
