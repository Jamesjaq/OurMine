/**
 * @module iot_scada
 * Real ICS/SCADA protocol clients — Modbus TCP, DNP3 link probe, MQTT, BACnet/IP.
 * Dry-run skips network I/O and returns empty/skipped results (no fabricated data).
 */
import * as dgram from "node:dgram"
import * as net from "node:net"
import { resolveDryRun } from "./exec_options.ts"
import { dedupeProbe, probeFingerprint } from "./probe_dedupe.ts"

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
  probeCached?: boolean
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

/** Multi-frame TCP dialog on one connection (S7, MQTT subscribe chain). */
function tcpDialog(host: string, port: number, frames: Buffer[], timeoutMs = 5000): Promise<Buffer[]> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket()
    socket.setTimeout(timeoutMs)
    const responses: Buffer[] = []
    let sent = 0
    const sendNext = () => {
      if (sent < frames.length) {
        socket.write(frames[sent]!)
        sent++
      }
    }
    socket.connect(port, host, sendNext)
    socket.on("data", (d) => {
      responses.push(d)
      if (sent < frames.length) sendNext()
      else setTimeout(() => { socket.destroy(); resolve(responses) }, 250)
    })
    socket.on("close", () => resolve(responses))
    socket.on("timeout", () => { socket.destroy(); reject(new Error("timeout")) })
    socket.on("error", reject)
  })
}

function defaultScadaPort(protocol: string): number {
  switch (protocol) {
    case "dnp3": return 20000
    case "mqtt": return 1883
    case "bacnet": return 47808
    case "coap": return 5683
    case "profinet": return 34964
    case "s7": return 102
    default: return 502
  }
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

/** DNP3 CRC16 (DNP3 polynomial) for link-layer frames. */
function dnp3LinkCrc(data: Buffer): number {
  let crc = 0
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i]!
    for (let b = 0; b < 8; b++) {
      crc = crc & 1 ? (crc >> 1) ^ 0xa6bc : crc >> 1
    }
  }
  return ~crc & 0xffff
}

function buildDnp3LinkFrame(dest: number, src: number, payload: Buffer): Buffer {
  const hdr = Buffer.from([0x05, 0x64, 5 + payload.length, 0xc4, dest & 0xff, (dest >> 8) & 0xff, src & 0xff, (src >> 8) & 0xff])
  const hdrCrc = dnp3LinkCrc(hdr.subarray(2, 8))
  const bodyCrc = payload.length ? dnp3LinkCrc(payload) : 0xffff
  return Buffer.concat([
    hdr,
    Buffer.from([hdrCrc & 0xff, (hdrCrc >> 8) & 0xff]),
    payload,
    Buffer.from([bodyCrc & 0xff, (bodyCrc >> 8) & 0xff]),
  ])
}

/** Application-layer READ — Group 80 Var 1 (Internal Indications), read-only. */
export function buildDnp3ReadIinFrame(): Buffer {
  const app = Buffer.from([0xc0, 0xc0, 0x01, 0x50, 0x01, 0x00])
  return buildDnp3LinkFrame(1, 1024, app)
}

function dnp3AppReadSuccess(resp: Buffer): boolean {
  if (resp.length < 12) return false
  for (let i = 0; i < resp.length - 3; i++) {
    if (resp[i] === 0x81 || resp[i] === 0x82) return true
    if (resp[i] === 0xc0 && resp[i + 2] === 0x81) return true
  }
  return resp.length > 20
}

/** DNP3 link-layer test + application-layer read probe (IIN read, read-only). */
export async function probeDnp3(
  host: string,
  port = 20000,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "dnp3", action: "probe", host, port, success: false, dryRun: true, error: "live required" }
  }
  const linkTest = Buffer.from([0x05, 0x64, 0x05, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
  try {
    const linkResp = await tcpExchange(host, port, linkTest, 8000)
    const linkOk = linkResp.length > 0
    let appOk = false
    let appHex = ""
    if (linkOk) {
      const readFrame = buildDnp3ReadIinFrame()
      const appResp = await tcpExchange(host, port, readFrame, 8000)
      appHex = appResp.subarray(0, 64).toString("hex")
      appOk = dnp3AppReadSuccess(appResp)
    }
    return {
      protocol: "dnp3",
      action: "probe",
      host,
      port,
      success: linkOk && appOk,
      dryRun: false,
      rawHex: appHex || linkResp.subarray(0, 64).toString("hex"),
      data: {
        bytes: linkResp.length,
        linkAck: linkResp[3] === 0xc0 || linkResp[3] === 0xc1,
        appReadOk: appOk,
        linkOnly: linkOk && !appOk,
      },
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

/** CoAP GET /.well-known/core discovery (RFC 7252). */
export async function probeCoap(
  host: string,
  port = 5683,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "coap", action: "discover", host, port, success: false, dryRun: true, error: "live required" }
  }
  const frame = Buffer.from([
    0x40, 0x01, 0xab, 0xcd, 0xb4, 0x77, 0x65, 0x6c, 0x6c, 0x2d,
    0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x2f, 0x63, 0x6f, 0x72, 0x65,
  ])
  try {
    const resp = await udpExchange(host, port, frame, 5000)
    // CoAP ACK (ver=2) with 2.05 Content or 2.03 Valid — reject random UDP noise.
    const ver = resp.length >= 1 ? (resp[0]! >> 6) : 0
    const code = resp.length >= 2 ? resp[1]! : 0
    const tokenMatch = resp.length >= 4 && resp[2] === 0xab && resp[3] === 0xcd
    const ok = ver === 2 && tokenMatch && (code === 0x45 || code === 0x43 || code === 0x60)
    return {
      protocol: "coap",
      action: "discover",
      host,
      port,
      success: ok,
      dryRun: false,
      rawHex: resp.subarray(0, 64).toString("hex"),
      data: { bytes: resp.length, coapVer: ver, coapCode: code },
    }
  } catch (e) {
    return { protocol: "coap", action: "discover", host, port, success: false, dryRun: false, error: e instanceof Error ? e.message : String(e) }
  }
}

function buildS7CotpCr(): Buffer {
  return Buffer.from([
    0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
    0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02,
  ])
}

function buildS7SetupComm(): Buffer {
  return Buffer.from([
    0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 0x32, 0x01, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x01, 0x00,
    0x01, 0x01, 0xe0,
  ])
}

/** Read-only S7comm Read SZL — module identification (SZL-ID 0x001C). */
function buildS7ReadSzl(): Buffer {
  return Buffer.from([
    0x03, 0x00, 0x00, 0x29, 0x02, 0xf0, 0x80, 0x32, 0x07, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x01, 0x12, 0x04,
    0x11, 0x44, 0x01, 0x00, 0xff, 0x09, 0x00, 0x04, 0x00, 0x11, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ])
}

/** ISO-on-TCP COTP + S7comm Setup Communication (read-only, port 102). */
export async function probeS7(
  host: string,
  port = 102,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "s7", action: "probe", host, port, success: false, dryRun: true, error: "live required" }
  }
  try {
    const resps = await tcpDialog(host, port, [buildS7CotpCr(), buildS7SetupComm()], 6000)
    const merged = Buffer.concat(resps)
    const cotpOk = merged.length >= 22 && (merged[5] === 0xd0 || merged.includes(0xd0))
    const setupOk = merged.includes(0x32) && merged.includes(0x03)
    const tcpOnly = resps.length > 0 && !setupOk
    return {
      protocol: "s7",
      action: "probe",
      host,
      port,
      success: cotpOk && setupOk,
      dryRun: false,
      rawHex: merged.subarray(0, 64).toString("hex"),
      data: { cotpOk, setupCommOk: setupOk, tcpOnly, bytes: merged.length },
    }
  } catch (e) {
    return { protocol: "s7", action: "probe", host, port, success: false, dryRun: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** S7 CONNECT + Setup Comm + Read SZL — read-only CPU/module fingerprint. */
export async function exploitS7(
  host: string,
  port = 102,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "s7", action: "exploit", host, port, success: false, dryRun: true, error: "live required" }
  }
  try {
    const resps = await tcpDialog(host, port, [buildS7CotpCr(), buildS7SetupComm(), buildS7ReadSzl()], 8000)
    const merged = Buffer.concat(resps)
    const setupOk = merged.includes(0x32) && (merged.includes(0xd0) || merged.includes(0xf0))
    const szlOk = merged.length > 40 && merged.includes(0x32) && merged[17] !== 0x01
    return {
      protocol: "s7",
      action: "exploit",
      host,
      port,
      success: setupOk,
      dryRun: false,
      rawHex: merged.subarray(0, 96).toString("hex"),
      data: {
        setupCommOk: setupOk,
        szlResponse: szlOk,
        bytes: merged.length,
        semantic: setupOk
          ? szlOk
            ? "S7 PLC responds to anonymous Setup Comm + Read SZL (module info leak)"
            : "S7 Setup Comm accepted — SZL read inconclusive"
          : "No S7comm handshake",
        safetyNote: "Read-only S7comm SZL probe — no DB writes or program stop",
      },
    }
  } catch (e) {
    return { protocol: "s7", action: "exploit", host, port, success: false, dryRun: false, error: e instanceof Error ? e.message : String(e) }
  }
}

function buildMqttConnect(clientId = "ourmine_probe"): Buffer {
  const id = Buffer.from(clientId, "utf8")
  const variable = Buffer.concat([
    Buffer.from([0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c]),
    Buffer.from([0x00, id.length]),
    id,
  ])
  return Buffer.concat([Buffer.from([0x10, variable.length]), variable])
}

function buildMqttSubscribe(topic: string, packetId = 1): Buffer {
  const t = Buffer.from(topic, "utf8")
  const payload = Buffer.concat([Buffer.from([(t.length >> 8) & 0xff, t.length & 0xff]), t, Buffer.from([0x00])])
  const variable = Buffer.concat([Buffer.from([(packetId >> 8) & 0xff, packetId & 0xff]), payload])
  return Buffer.concat([Buffer.from([0x82, variable.length]), variable])
}

/** MQTT CONNECT + wildcard SUBSCRIBE — read-only broker abuse surface check. */
export async function exploitMqtt(
  host: string,
  port = 1883,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "mqtt", action: "exploit", host, port, success: false, dryRun: true, error: "live required" }
  }
  try {
    const resps = await tcpDialog(host, port, [buildMqttConnect(), buildMqttSubscribe("$SYS/#")], 5000)
    const merged = Buffer.concat(resps)
    const connAck = merged.length >= 4 && merged[0] === 0x20 && merged[1] === 0x02
    const subAck = merged.includes(0x90)
    return {
      protocol: "mqtt",
      action: "exploit",
      host,
      port,
      success: connAck,
      dryRun: false,
      rawHex: merged.subarray(0, 64).toString("hex"),
      data: {
        connAck,
        subscribeAccepted: subAck,
        semantic: connAck
          ? subAck
            ? "Broker accepts anonymous CONNECT + wildcard SUBSCRIBE ($SYS/#)"
            : "Broker accepts CONNECT — subscription policy unknown"
          : "No MQTT CONNACK",
        safetyNote: "Read-only MQTT probe — no PUBLISH injection",
      },
    }
  } catch (e) {
    return { protocol: "mqtt", action: "exploit", host, port, success: false, dryRun: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** CoAP discovery + GET /.well-known/core — read-only resource enumeration. */
export async function exploitCoap(
  host: string,
  port = 5683,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "coap", action: "exploit", host, port, success: false, dryRun: true, error: "live required" }
  }
  const discover = await probeCoap(host, port, true)
  if (!discover.success) return { ...discover, action: "exploit" }
  const getFrame = Buffer.from([
    0x40, 0x01, 0xef, 0x01, 0xb4, 0x77, 0x65, 0x6c, 0x6c, 0x2d,
    0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x2f, 0x63, 0x6f, 0x72, 0x65,
  ])
  try {
    const resp = await udpExchange(host, port, getFrame, 4000)
    const ok = resp.length >= 2 && (resp[0]! >> 6) === 2 && (resp[1]! === 0x45 || resp[1]! === 0x43)
    return {
      protocol: "coap",
      action: "exploit",
      host,
      port,
      success: discover.success && ok,
      dryRun: false,
      rawHex: resp.subarray(0, 64).toString("hex"),
      data: {
        discoverOk: discover.success,
        getOk: ok,
        semantic: ok ? "CoAP device exposes /.well-known/core resources without auth" : "Discovery OK — GET pending",
        safetyNote: "Read-only CoAP GET — no PUT/POST",
      },
    }
  } catch (e) {
    return {
      protocol: "coap",
      action: "exploit",
      host,
      port,
      success: discover.success,
      dryRun: false,
      rawHex: discover.rawHex,
      data: { discoverOk: discover.success, getOk: false, semantic: "CoAP discovery confirmed — GET failed" },
      error: e instanceof Error ? e.message : String(e),
    }
  }
}

async function fuzzMqtt(host: string, port: number): Promise<ScadaResult> {
  const anomalies: string[] = []
  const probes = [
    Buffer.from([0x10, 0x0a, 0x00, 0x04, 0x4d, 0x51, 0x58, 0x58, 0x04, 0x02, 0x00, 0x3c]),
    Buffer.from([0x10, 0xff, 0xff, 0xff]),
    buildMqttConnect("x".repeat(256)),
  ]
  for (let i = 0; i < probes.length; i++) {
    try {
      const resp = await tcpExchange(host, port, probes[i]!, 2000)
      anomalies.push(`p${i + 1}:bytes=${resp.length}`)
    } catch (e) {
      anomalies.push(`p${i + 1}:${e instanceof Error ? e.message : "err"}`)
    }
  }
  return {
    protocol: "mqtt",
    action: "fuzz",
    host,
    port,
    success: anomalies.length > 0,
    dryRun: false,
    data: { probes: anomalies.length, responses: anomalies },
  }
}

async function fuzzCoap(host: string, port: number): Promise<ScadaResult> {
  const anomalies: string[] = []
  const probes = [
    Buffer.from([0x00, 0x01, 0xab, 0xcd]),
    Buffer.from([0x50, 0xff, 0x00, 0x00]),
    Buffer.from([0x40, 0x05, 0x12, 0x34]),
  ]
  for (let i = 0; i < probes.length; i++) {
    try {
      const resp = await udpExchange(host, port, probes[i]!, 2000)
      anomalies.push(`p${i + 1}:bytes=${resp.length}`)
    } catch (e) {
      anomalies.push(`p${i + 1}:${e instanceof Error ? e.message : "err"}`)
    }
  }
  return {
    protocol: "coap",
    action: "fuzz",
    host,
    port,
    success: anomalies.length > 0,
    dryRun: false,
    data: { probes: anomalies.length, responses: anomalies },
  }
}

async function fuzzS7(host: string, port: number): Promise<ScadaResult> {
  const anomalies: string[] = []
  const probes = [
    Buffer.from([0x03, 0x00, 0x00, 0x07, 0x02, 0xf0, 0x00]),
    Buffer.from([0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0xff, 0xff, 0xff, 0xff]),
    Buffer.from([0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 0x32, 0x07, 0x00, 0x00]),
  ]
  for (let i = 0; i < probes.length; i++) {
    try {
      const resp = await tcpExchange(host, port, probes[i]!, 2000)
      anomalies.push(`p${i + 1}:bytes=${resp.length}`)
    } catch (e) {
      anomalies.push(`p${i + 1}:${e instanceof Error ? e.message : "err"}`)
    }
  }
  return {
    protocol: "s7",
    action: "fuzz",
    host,
    port,
    success: anomalies.length > 0,
    dryRun: false,
    data: { probes: anomalies.length, responses: anomalies },
  }
}

/** Profinet DCP Identify (UDP 34964) + S7 + optional L2 raw + nmap fallback. */
export async function probeProfinet(
  host: string,
  port = 34964,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "profinet", action: "identify", host, port, success: false, dryRun: true, error: "live required" }
  }
  const { probeProfinetFull } = await import("./profinet_l2.ts")
  const full = await probeProfinetFull(host, true)
  return {
    protocol: "profinet",
    action: "identify",
    host,
    port,
    success: full.udp34964 || full.s7Port102 || full.l2Raw || full.nmapDiscover,
    dryRun: false,
    rawHex: full.rawHex,
    data: {
      dcpResponse: full.udp34964,
      s7Port102: full.s7Port102,
      l2Raw: full.l2Raw,
      nmapDiscover: full.nmapDiscover,
      summary: full.summary,
    },
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
      data: { bytes: resp.length, deviceInstance: parseBacnetDeviceInstance(resp) },
    }
  } catch (e) {
    return { protocol: "bacnet", action: "whois", host, port, success: false, dryRun: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** Parse device instance from BACnet I-Am response (best-effort). */
export function parseBacnetDeviceInstance(resp: Buffer): number | null {
  for (let i = 0; i < resp.length - 6; i++) {
    if (resp[i] === 0x10 && resp[i + 1] === 0x00) {
      const oidStart = i + 2
      if (oidStart + 4 <= resp.length) {
        const raw = resp.readUInt32BE(oidStart)
        return raw & 0x3fffff
      }
    }
    if (resp[i] === 0xc4 && i + 5 < resp.length) {
      const raw = resp.readUInt32BE(i + 1)
      return raw & 0x3fffff
    }
  }
  return null
}

/** Encode BACnet object identifier (type << 22 | instance). */
function encodeObjectId(type: number, instance: number): Buffer {
  const id = ((type & 0x3ff) << 22) | (instance & 0x3fffff)
  const buf = Buffer.alloc(4)
  buf.writeUInt32BE(id, 0)
  return buf
}

/** BACnet Read Property — object-name (77) on device object, read-only validation. */
export async function bacnetReadProperty(
  host: string,
  port = 47808,
  deviceInstance = 0,
  propertyId = 77,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "bacnet", action: "read_property", host, port, success: false, dryRun: true, error: "live required" }
  }
  const invokeId = 1
  const oid = encodeObjectId(8, deviceInstance)
  const apdu = Buffer.concat([
    Buffer.from([0x00, 0x05, invokeId, 0x0c]),
    Buffer.from([0x0c]),
    oid,
    Buffer.from([0x19, propertyId & 0xff]),
  ])
  const npduLen = 2 + apdu.length
  const frame = Buffer.concat([
    Buffer.from([0x81, 0x0a]),
    Buffer.from([(npduLen + 4) >> 8, (npduLen + 4) & 0xff]),
    Buffer.from([0x01, 0x04]),
    apdu,
  ])
  try {
    const resp = await udpExchange(host, port, frame)
    const complexAck = resp.includes(0x0c) || resp.includes(0x3e) || resp.length > 16
    return {
      protocol: "bacnet",
      action: "read_property",
      host,
      port,
      success: complexAck,
      dryRun: false,
      rawHex: resp.subarray(0, 64).toString("hex"),
      data: { bytes: resp.length, deviceInstance, propertyId, complexAck },
    }
  } catch (e) {
    return { protocol: "bacnet", action: "read_property", host, port, success: false, dryRun: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** Who-Is then Read Property object-name — stronger BACnet CONFIRMED than Who-Is alone. */
export async function bacnetValidateDevice(
  host: string,
  port = 47808,
  live = false,
): Promise<ScadaResult> {
  if (!live) {
    return { protocol: "bacnet", action: "validate", host, port, success: false, dryRun: true, error: "live required" }
  }
  const whois = await bacnetWhoIs(host, port, true)
  const instance = (whois.data as { deviceInstance?: number | null })?.deviceInstance ?? 0
  const read = await bacnetReadProperty(host, port, instance ?? 0, 77, true)
  return {
    protocol: "bacnet",
    action: "validate",
    host,
    port,
    success: whois.success && read.success,
    dryRun: false,
    rawHex: read.rawHex ?? whois.rawHex,
    data: { whoisOk: whois.success, readPropertyOk: read.success, deviceInstance: instance },
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

async function fuzzModbus(host: string, port: number, unitId: number): Promise<ScadaResult> {
  const anomalies: string[] = []
  for (let txId = 1; txId <= 4; txId++) {
    const badFc = modbusTcpFrame(unitId, 0x7f, Buffer.from([0x00, 0x01, 0x00, 0x01]), txId)
    try {
      const resp = await tcpExchange(host, port, badFc, 2000)
      if (resp.length) anomalies.push(`tx${txId}:exception=${resp[7]?.toString(16) ?? "?"}`)
    } catch (e) {
      anomalies.push(`tx${txId}:${e instanceof Error ? e.message : "err"}`)
    }
  }
  return {
    protocol: "modbus",
    action: "fuzz",
    host,
    port,
    success: anomalies.length > 0,
    dryRun: false,
    data: { probes: anomalies.length, responses: anomalies },
  }
}

async function exploitScada(req: ScadaActionRequest, port: number, unitId: number): Promise<ScadaResult> {
  const protocol = (req.protocol ?? "modbus").toLowerCase()
  if (protocol === "modbus") {
    const { proveIcsImpact } = await import("./ics_impact_proof.ts")
    const proof = await proveIcsImpact({ host: req.host, port, live: true })
    return {
      protocol,
      action: "exploit",
      host: req.host,
      port,
      success: proof.success,
      dryRun: false,
      data: { proofType: proof.proofType, semantic: proof.semantic, safetyNote: proof.safetyNote },
    }
  }
  if (protocol === "dnp3") return probeDnp3(req.host, port, true)
  if (protocol === "bacnet") return bacnetValidateDevice(req.host, port, true)
  if (protocol === "profinet") return probeProfinet(req.host, port, true)
  if (protocol === "mqtt") return exploitMqtt(req.host, port, true)
  if (protocol === "coap") return exploitCoap(req.host, port, true)
  if (protocol === "s7") return exploitS7(req.host, port, true)
  return { protocol, action: "exploit", host: req.host, port, success: false, dryRun: false, error: `exploit not implemented for ${protocol}` }
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
  const port = req.port ?? defaultScadaPort(protocol)
  const unitId = req.unitId ?? 1

  if (!live) {
    return { protocol, action, host, port, success: false, dryRun: true, error: "pass live:true or --live" }
  }

  const cacheable = ["read", "read_registers", "read_holding", "probe", "connect", "whois", "discover", "identify"].includes(action)
  if (cacheable) {
    const fp = probeFingerprint(`scada_${protocol}_${action}`, `${host}:${port}`, String(unitId))
    const { result, cached } = await dedupeProbe(fp, async () =>
      executeScadaActionUncached(req, { live, dryRun: opts.dryRun }, { host, protocol, action, port, unitId }),
    )
    if (cached && result.success) return { ...result, probeCached: true } as ScadaResult
    return result
  }

  return executeScadaActionUncached(req, { live, dryRun: opts.dryRun }, { host, protocol, action, port, unitId })
}

async function executeScadaActionUncached(
  req: ScadaActionRequest,
  opts: { live?: boolean; dryRun?: boolean },
  ctx: { host: string; protocol: string; action: string; port: number; unitId: number },
): Promise<ScadaResult> {
  const { host, protocol, action, port, unitId } = ctx
  const live = !resolveDryRun(opts)

  if (protocol === "modbus") {
    if (action === "fuzz") {
      const r = await fuzzModbus(host, port, unitId)
      return r
    }
    if (action === "exploit") {
      return exploitScada(req, port, unitId)
    }
    if (action === "write_coil") {
      const r = await writeModbusCoil(host, req.address ?? 0, Boolean(req.value), port, unitId, true)
      return { protocol, action: "write_coil", host, port, success: r.success, dryRun: false, data: r, error: r.error }
    }
    if (action === "write_register") {
      const r = await writeModbusRegister(host, req.address ?? 0, Number(req.value ?? 0), port, unitId, true)
      return { protocol, action, host, port, success: r.success, dryRun: false, data: r, error: r.error }
    }
    if (action === "write") {
      const asBool = req.value === true || req.value === "true" || req.value === 1
      const asRegister = req.address != null && typeof req.value === "number" && req.value > 1
      if (asRegister) {
        const r = await writeModbusRegister(host, req.address ?? 0, Number(req.value ?? 0), port, unitId, true)
        return { protocol, action: "write_register", host, port, success: r.success, dryRun: false, data: r, error: r.error }
      }
      const r = await writeModbusCoil(host, req.address ?? 0, asBool, port, unitId, true)
      return { protocol, action: "write_coil", host, port, success: r.success, dryRun: false, data: r, error: r.error }
    }
    if (action === "read_registers" || action === "read_holding") {
      const r = await readModbusHoldingRegisters(host, port, unitId, req.address ?? 0, req.quantity ?? 10, true)
      return { protocol, action, host, port, success: r.success, dryRun: false, data: r, error: r.error }
    }
    const r = await readModbusCoils(host, port, unitId, req.address ?? 0, req.quantity ?? 10, true)
    return { protocol, action: action === "enumerate" ? "read" : action, host, port, success: r.success, dryRun: false, data: r, error: r.error }
  }

  if (protocol === "dnp3") {
    if (action === "fuzz" || action === "exploit") return probeDnp3(host, port, true)
    return probeDnp3(host, port, true)
  }
  if (protocol === "mqtt") {
    if (action === "fuzz") return fuzzMqtt(host, port)
    if (action === "exploit") return exploitMqtt(host, port, true)
    return probeMqtt(host, port, "ourmine_probe", true)
  }
  if (protocol === "bacnet") {
    if (action === "read_property" || action === "read") return bacnetReadProperty(host, port, req.address ?? 0, 77, true)
    if (action === "validate") return bacnetValidateDevice(host, port, true)
    if (action === "fuzz" || action === "exploit") return bacnetValidateDevice(host, port, true)
    return bacnetWhoIs(host, port, true)
  }
  if (protocol === "coap") {
    if (action === "fuzz") return fuzzCoap(host, port)
    if (action === "exploit") return exploitCoap(host, port, true)
    return probeCoap(host, port, true)
  }
  if (protocol === "s7") {
    if (action === "fuzz") return fuzzS7(host, port)
    if (action === "exploit") return exploitS7(host, port, true)
    return probeS7(host, port, true)
  }
  if (protocol === "profinet") {
    if (action === "fuzz" || action === "exploit" || action === "identify") return probeProfinet(host, port, true)
    return probeProfinet(host, port, true)
  }

  return { protocol, action, host, port, success: false, dryRun: false, error: `unknown protocol: ${protocol}` }
}

export default {
  readModbusCoils,
  readModbusHoldingRegisters,
  writeModbusCoil,
  writeModbusRegister,
  probeDnp3,
  probeMqtt,
  probeCoap,
  probeS7,
  exploitMqtt,
  exploitCoap,
  exploitS7,
  probeProfinet,
  bacnetWhoIs,
  bacnetReadProperty,
  bacnetValidateDevice,
  parseBacnetDeviceInstance,
  buildDnp3ReadIinFrame,
  executeScadaAction,
}
