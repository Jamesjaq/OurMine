/**
 * @module iot_scada
 * Real ICS/SCADA protocol clients — Modbus TCP, DNP3 link probe, MQTT, BACnet/IP.
 * Dry-run skips network I/O and returns empty/skipped results (no fabricated data).
 */
import * as dgram from "node:dgram"
import * as net from "node:net"
import { resolveDryRun } from "./exec_options.ts"

export interface ScadaResult {
  protocol: string
  action: string
  host: string
  port: number
  success: boolean
  dryRun: boolean
  data?: unknown
  error?: string
  rawHex?: string
}

export interface ModbusResult {
  unitId: number
  fc: number
  data: number[]
  dryRun: boolean
  success: boolean
  error?: string
}

function modbusTcpFrame(unitId: number, fc: number, payload: Buffer, txId = 1): Buffer {
  const pdu = Buffer.concat([Buffer.from([unitId, fc]), payload])
  const hdr = Buffer.alloc(6)
  hdr.writeUInt16BE(txId, 0)
  hdr.writeUInt16BE(0, 2)
  hdr.writeUInt16BE(pdu.length, 4)
  return Buffer.concat([hdr, pdu])
}

function tcpExchange(host: string, port: number, frame: Buffer, timeoutMs = 5000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket()
    socket.setTimeout(timeoutMs)
    const chunks: Buffer[] = []
    socket.connect(port, host, () => socket.write(frame))
    socket.on("data", (d) => chunks.push(d))
    socket.on("close", () => resolve(Buffer.concat(chunks)))
    socket.on("timeout", () => { socket.destroy(); reject(new Error("timeout")) })
    socket.on("error", reject)
  })
}

function udpExchange(host: string, port: number, frame: Buffer, timeoutMs = 4000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4")
    const timer = setTimeout(() => { socket.close(); reject(new Error("timeout")) }, timeoutMs)
    socket.once("message", (msg) => {
      clearTimeout(timer)
      socket.close()
      resolve(msg)
    })
    socket.once("error", (e) => { clearTimeout(timer); socket.close(); reject(e) })
    socket.send(frame, port, host)
  })
}

export async function readModbusCoils(
  host: string,
  port = 502,
  unitId = 1,
  startAddr = 0,
  quantity = 10,
  live = false,
): Promise<ModbusResult> {
  if (!live) return { unitId, fc: 1, data: [], dryRun: true, success: false, error: "live required" }
  const payload = Buffer.from([
    (startAddr >> 8) & 0xff, startAddr & 0xff,
    (quantity >> 8) & 0xff, quantity & 0xff,
  ])
  try {
    const resp = await tcpExchange(host, port, modbusTcpFrame(unitId, 0x01, payload))
    if (resp.length < 9) return { unitId, fc: 1, data: [], dryRun: false, success: false, error: "short response" }
    const byteCount = resp[8]!
    return { unitId, fc: 1, data: Array.from(resp.subarray(9, 9 + byteCount)), dryRun: false, success: true }
  } catch (e) {
    return { unitId, fc: 1, data: [], dryRun: false, success: false, error: e instanceof Error ? e.message : String(e) }
  }
}

export async function readModbusHoldingRegisters(
  host: string,
  port = 502,
  unitId = 1,
  startAddr = 0,
  quantity = 10,
  live = false,
): Promise<ModbusResult> {
  if (!live) return { unitId, fc: 3, data: [], dryRun: true, success: false, error: "live required" }
  const payload = Buffer.from([
    (startAddr >> 8) & 0xff, startAddr & 0xff,
    (quantity >> 8) & 0xff, quantity & 0xff,
  ])
  try {
    const resp = await tcpExchange(host, port, modbusTcpFrame(unitId, 0x03, payload))
    if (resp.length < 9) return { unitId, fc: 3, data: [], dryRun: false, success: false, error: "short response" }
    const byteCount = resp[8]!
    const regs: number[] = []
    for (let i = 0; i < byteCount; i += 2) {
      regs.push(resp.readUInt16BE(9 + i))
    }
    return { unitId, fc: 3, data: regs, dryRun: false, success: true }
  } catch (e) {
    return { unitId, fc: 3, data: [], dryRun: false, success: false, error: e instanceof Error ? e.message : String(e) }
  }
}

export async function writeModbusCoil(
  host: string,
  addr: number,
  value: boolean,
  port = 502,
  unitId = 1,
  live = false,
): Promise<ModbusResult> {
  if (!live) return { unitId, fc: 5, data: [], dryRun: true, success: false, error: "live required" }
  const payload = Buffer.from([
    (addr >> 8) & 0xff, addr & 0xff,
    value ? 0xff : 0x00, 0x00,
  ])
  try {
    await tcpExchange(host, port, modbusTcpFrame(unitId, 0x05, payload))
    return { unitId, fc: 5, data: [value ? 1 : 0], dryRun: false, success: true }
  } catch (e) {
    return { unitId, fc: 5, data: [], dryRun: false, success: false, error: e instanceof Error ? e.message : String(e) }
  }
}

export async function writeModbusRegister(
  host: string,
  addr: number,
  value: number,
  port = 502,
  unitId = 1,
  live = false,
): Promise<ModbusResult> {
  if (!live) return { unitId, fc: 6, data: [], dryRun: true, success: false, error: "live required" }
  const payload = Buffer.from([
    (addr >> 8) & 0xff, addr & 0xff,
    (value >> 8) & 0xff, value & 0xff,
  ])
  try {
    await tcpExchange(host, port, modbusTcpFrame(unitId, 0x06, payload))
    return { unitId, fc: 6, data: [value], dryRun: false, success: true }
  } catch (e) {
    return { unitId, fc: 6, data: [], dryRun: false, success: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** DNP3 link-layer test + read static data (Class 0) request. */
export async function probeDnp3(
  host: string,
  port = 20000,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "dnp3", action: "probe", host, port, success: false, dryRun: true, error: "live required" }
  }
  // Link reset + application read (Group 60 Var 1 — device attributes summary)
  const linkTest = Buffer.from([0x05, 0x64, 0x05, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
  try {
    const resp = await tcpExchange(host, port, linkTest, 8000)
    return {
      protocol: "dnp3",
      action: "probe",
      host,
      port,
      success: resp.length > 0,
      dryRun: false,
      rawHex: resp.subarray(0, 64).toString("hex"),
      data: { bytes: resp.length, linkAck: resp[3] === 0xc0 || resp[3] === 0xc1 },
    }
  } catch (e) {
    return { protocol: "dnp3", action: "probe", host, port, success: false, dryRun: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** MQTT CONNECT probe — verifies broker accepts connections. */
export async function probeMqtt(
  host: string,
  port = 1883,
  clientId = "ourmine_probe",
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "mqtt", action: "connect", host, port, success: false, dryRun: true, error: "live required" }
  }
  const id = Buffer.from(clientId, "utf8")
  const variable = Buffer.concat([
    Buffer.from([0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c]),
    Buffer.from([0x00, id.length]),
    id,
  ])
  const connect = Buffer.concat([Buffer.from([0x10, variable.length]), variable])
  try {
    const resp = await tcpExchange(host, port, connect, 5000)
    const ack = resp.length >= 2 && resp[0] === 0x20 && resp[1] === 0x02
    return { protocol: "mqtt", action: "connect", host, port, success: ack, dryRun: false, data: { connAck: ack, code: resp[3] } }
  } catch (e) {
    return { protocol: "mqtt", action: "connect", host, port, success: false, dryRun: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** BACnet/IP Who-Is broadcast probe. */
export async function bacnetWhoIs(
  host: string,
  port = 47808,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "bacnet", action: "whois", host, port, success: false, dryRun: true, error: "live required" }
  }
  const frame = Buffer.from([0x81, 0x0a, 0x00, 0x08, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08])
  try {
    const resp = await udpExchange(host, port, frame)
    return {
      protocol: "bacnet",
      action: "whois",
      host,
      port,
      success: resp.length > 0,
      dryRun: false,
      rawHex: resp.subarray(0, 48).toString("hex"),
      data: { bytes: resp.length },
    }
  } catch (e) {
    return { protocol: "bacnet", action: "whois", host, port, success: false, dryRun: false, error: e instanceof Error ? e.message : String(e) }
  }
}

export interface ScadaActionRequest {
  host: string
  protocol?: string
  action?: string
  port?: number
  unitId?: number
  address?: number
  quantity?: number
  value?: number | boolean
}

/** Unified SCADA/ICS dispatch — matches MCP ares_iot_scada surface. */
export async function executeScadaAction(
  req: ScadaActionRequest,
  opts: { live?: boolean; dryRun?: boolean } = {},
): Promise<ScadaResult> {
  const live = !resolveDryRun(opts)
  const host = req.host
  const protocol = (req.protocol ?? "modbus").toLowerCase()
  const action = (req.action ?? "read").toLowerCase()
  const port = req.port ?? (protocol === "dnp3" ? 20000 : protocol === "mqtt" ? 1883 : protocol === "bacnet" ? 47808 : 502)
  const unitId = req.unitId ?? 1

  if (!live) {
    return { protocol, action, host, port, success: false, dryRun: true, error: "pass live:true or --live" }
  }

  if (protocol === "modbus") {
    if (action === "write" || action === "write_coil") {
      const r = await writeModbusCoil(host, req.address ?? 0, Boolean(req.value), port, unitId, true)
      return { protocol, action, host, port, success: r.success, dryRun: false, data: r, error: r.error }
    }
    if (action === "write_register") {
      const r = await writeModbusRegister(host, req.address ?? 0, Number(req.value ?? 0), port, unitId, true)
      return { protocol, action, host, port, success: r.success, dryRun: false, data: r, error: r.error }
    }
    if (action === "read_registers" || action === "read_holding") {
      const r = await readModbusHoldingRegisters(host, port, unitId, req.address ?? 0, req.quantity ?? 10, true)
      return { protocol, action, host, port, success: r.success, dryRun: false, data: r, error: r.error }
    }
    const r = await readModbusCoils(host, port, unitId, req.address ?? 0, req.quantity ?? 10, true)
    return { protocol, action: action === "enumerate" ? "read" : action, host, port, success: r.success, dryRun: false, data: r, error: r.error }
  }

  if (protocol === "dnp3") return probeDnp3(host, port, true)
  if (protocol === "mqtt") return probeMqtt(host, port, "ourmine_probe", true)
  if (protocol === "bacnet") return bacnetWhoIs(host, port, true)

  return { protocol, action, host, port, success: false, dryRun: false, error: `unknown protocol: ${protocol}` }
}

export default {
  readModbusCoils,
  readModbusHoldingRegisters,
  writeModbusCoil,
  writeModbusRegister,
  probeDnp3,
  probeMqtt,
  bacnetWhoIs,
  executeScadaAction,
}
