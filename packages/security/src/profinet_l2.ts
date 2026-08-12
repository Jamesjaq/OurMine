/**
 * @module profinet_l2
 * Profinet DCP — UDP 34964 + optional L2 raw (OURMINE_PROFINET_RAW=1) + nmap fallback.
 */
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import * as dgram from "node:dgram"
import { resolveLiveMode } from "./exec_options.ts"
import { probeS7 as s7HandshakeProbe } from "./iot_scada.ts"

const execFileAsync = promisify(execFile)

export interface ProfinetProbeResult {
  host: string
  udp34964: boolean
  s7Port102: boolean
  l2Raw: boolean
  nmapDiscover: boolean
  rawHex?: string
  summary: string
}

function udpProbe(host: string, port: number, frame: Buffer, timeoutMs = 4000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket("udp4")
    const t = setTimeout(() => { s.close(); reject(new Error("timeout")) }, timeoutMs)
    s.once("message", (msg) => { clearTimeout(t); s.close(); resolve(msg) })
    s.once("error", (e) => { clearTimeout(t); s.close(); reject(e) })
    s.send(frame, port, host)
  })
}

/** PN-DCP Identify All request (UDP unicast/multicast). */
async function probeUdpDcp(host: string): Promise<{ ok: boolean; hex?: string }> {
  try {
    const frame = Buffer.from([0xfe, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    const resp = await udpProbe(host, 34964, frame)
    return { ok: resp.length > 4, hex: resp.subarray(0, 48).toString("hex") }
  } catch {
    return { ok: false }
  }
}

/** L2 Ethernet DCP via python3 AF_PACKET (requires cap_net_raw / root). */
async function probeL2Raw(host: string): Promise<boolean> {
  if (process.env.OURMINE_PROFINET_RAW !== "1") return false
  const script = `
import socket, struct, sys
try:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8892))
  s.bind(("eth0", 0))
  # PN-DCP Identify All ethertype 0x8892 minimal frame
  frame = bytes.fromhex("fefd000400000000")
  s.send(frame)
  s.settimeout(2)
  data = s.recv(256)
  sys.exit(0 if len(data) > 4 else 1)
except Exception:
  sys.exit(1)
`
  try {
    await execFileAsync("python3", ["-c", script], { timeout: 5000 })
    return true
  } catch {
    return false
  }
}

async function probeNmapProfinet(host: string): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync("nmap", [
      "-sU", "-p", "34964", "--script", "broadcast-profinet-discover", host, "-Pn", "-n",
    ], { timeout: 15000 })
    return /profinet|34964|open/i.test(stdout)
  } catch {
    try {
      const { stdout } = await execFileAsync("nmap", ["-sU", "-p", "34964", host, "-Pn", "-n"], { timeout: 10000 })
      return /open/i.test(stdout)
    } catch {
      return false
    }
  }
}

async function probeS7(host: string): Promise<boolean> {
  const r = await s7HandshakeProbe(host, 102, true)
  if (r.success) return true
  const data = r.data as { cotpOk?: boolean; setupCommOk?: boolean; tcpOnly?: boolean } | undefined
  return !!(data?.cotpOk || data?.setupCommOk || data?.tcpOnly)
}

export async function probeProfinetFull(host: string, live?: boolean): Promise<ProfinetProbeResult> {
  const isLive = live ?? resolveLiveMode()
  if (!isLive) {
    return {
      host, udp34964: false, s7Port102: false, l2Raw: false, nmapDiscover: false,
      summary: "dry-run — pass --live",
    }
  }

  const [udp, s7, l2, nmap] = await Promise.all([
    probeUdpDcp(host),
    probeS7(host),
    probeL2Raw(host),
    probeNmapProfinet(host),
  ])

  const ok = udp.ok || s7 || l2 || nmap
  return {
    host,
    udp34964: udp.ok,
    s7Port102: s7,
    l2Raw: l2,
    nmapDiscover: nmap,
    rawHex: udp.hex,
    summary: ok
      ? `Profinet: udp=${udp.ok} s7=${s7} l2=${l2} nmap=${nmap}`
      : "No Profinet/S7 response",
  }
}

export default { probeProfinetFull }
