/**
 * @module telecom_audit
 * Real telecom / carrier perimeter probes — SIP, Diameter port, SNMP, management APIs.
 * Dry-run skips network; no fabricated findings.
 */
import * as dgram from "node:dgram"
import * as net from "node:net"
import { execFileSync } from "node:child_process"
import { resolveDryRun } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"

export interface TelecomFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detail: string
  port?: number
  evidence?: string
}

export interface TelecomAuditResult {
  host: string
  dryRun: boolean
  sipReachable: boolean
  diameterPortOpen: boolean
  snmpResponded: boolean
  openTelecomPorts: number[]
  findings: TelecomFinding[]
}

const TELECOM_PORTS = [
  { port: 5060, name: "SIP" },
  { port: 5061, name: "SIPS" },
  { port: 3868, name: "Diameter" },
  { port: 162, name: "SNMP-trap" },
  { port: 161, name: "SNMP" },
  { port: 830, name: "NETCONF" },
  { port: 443, name: "HTTPS-mgmt" },
  { port: 8443, name: "HTTPS-alt" },
  { port: 22, name: "SSH" },
  { port: 8080, name: "HTTP-mgmt" },
]

function tcpProbe(host: string, port: number, timeoutMs = 2500): Promise<boolean> {
  return new Promise((resolve) => {
    const s = new net.Socket()
    s.setTimeout(timeoutMs)
    s.once("connect", () => { s.destroy(); resolve(true) })
    s.once("timeout", () => { s.destroy(); resolve(false) })
    s.once("error", () => { s.destroy(); resolve(false) })
    s.connect(port, host)
  })
}

function sipOptions(host: string, port = 5060, timeoutMs = 4000): Promise<{ ok: boolean; response: string }> {
  return new Promise((resolve) => {
    const msg = [
      `OPTIONS sip:probe@${host} SIP/2.0`,
      `Via: SIP/2.0/TCP ${host}:${port};branch=z9hG4bK-ourmine`,
      `Max-Forwards: 70`,
      `To: <sip:probe@${host}>`,
      `From: <sip:scanner@ourmine.local>;tag=probe1`,
      `Call-ID: ourmine-${Date.now()}@${host}`,
      `CSeq: 1 OPTIONS`,
      `Contact: <sip:scanner@ourmine.local>`,
      `Accept: application/sdp`,
      `Content-Length: 0`,
      "",
      "",
    ].join("\r\n")
    const s = new net.Socket()
    let buf = ""
    s.setTimeout(timeoutMs)
    s.connect(port, host, () => s.write(msg))
    s.on("data", (d) => { buf += d.toString("utf8") })
    s.on("close", () => resolve({ ok: /SIP\/2\.0 200|SIP\/2\.0 405|SIP\/2\.0 401/.test(buf), response: buf.slice(0, 500) }))
    s.on("timeout", () => { s.destroy(); resolve({ ok: false, response: buf }) })
    s.on("error", () => resolve({ ok: false, response: buf }))
  })
}

function snmpUdpProbe(host: string, community = "public", port = 161): Promise<boolean> {
  return new Promise((resolve) => {
    // SNMPv2c GetRequest sysDescr.0
    const oid = Buffer.from([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    const communityBuf = Buffer.from(community, "utf8")
    const inner = Buffer.concat([
      Buffer.from([0x02, 0x01, 0x01]), // version v2c
      Buffer.from([0x04, communityBuf.length]), communityBuf,
      Buffer.from([0xa0, 0x11, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x05]),
      oid,
    ])
    const packet = Buffer.concat([Buffer.from([0x30, inner.length]), inner])
    const socket = dgram.createSocket("udp4")
    const timer = setTimeout(() => { socket.close(); resolve(false) }, 3000)
    socket.once("message", () => { clearTimeout(timer); socket.close(); resolve(true) })
    socket.once("error", () => { clearTimeout(timer); socket.close(); resolve(false) })
    socket.send(packet, port, host)
  })
}

export async function auditTelecom(
  host: string,
  opts: { live?: boolean; dryRun?: boolean; snmpCommunity?: string } = {},
): Promise<TelecomAuditResult> {
  const dryRun = resolveDryRun(opts)
  const empty: TelecomAuditResult = {
    host,
    dryRun: true,
    sipReachable: false,
    diameterPortOpen: false,
    snmpResponded: false,
    openTelecomPorts: [],
    findings: [],
  }
  if (dryRun) return empty

  const openTelecomPorts: number[] = []
  const findings: TelecomFinding[] = []

  for (const { port, name } of TELECOM_PORTS) {
    if (await tcpProbe(host, port)) openTelecomPorts.push(port)
  }

  let sipReachable = false
  if (openTelecomPorts.includes(5060) || openTelecomPorts.includes(5061)) {
    const sipPort = openTelecomPorts.includes(5060) ? 5060 : 5061
    const sip = await sipOptions(host, sipPort)
    sipReachable = sip.ok
    if (sip.ok) {
      findings.push({
        id: "TEL-SIP-001",
        severity: "high",
        title: "SIP service responds to OPTIONS",
        detail: `SIP stack at ${host}:${sipPort} answered probe — VoIP/core enumeration possible`,
        port: sipPort,
        evidence: sip.response.slice(0, 200),
      })
    }
  }

  const diameterPortOpen = openTelecomPorts.includes(3868)
  if (diameterPortOpen) {
    findings.push({
      id: "TEL-DIA-001",
      severity: "high",
      title: "Diameter port open (3868)",
      detail: "LTE/5G core Diameter interface may be reachable — auth/policy abuse risk",
      port: 3868,
    })
  }

  let snmpResponded = false
  if (openTelecomPorts.includes(161)) {
    snmpResponded = await snmpUdpProbe(host, opts.snmpCommunity ?? "public", 161)
    if (snmpResponded) {
      findings.push({
        id: "TEL-SNMP-001",
        severity: "critical",
        title: "SNMP responded with default/community string",
        detail: "Network element SNMP accessible — config/ACL harvest possible (Salt Typhoon lane)",
        port: 161,
      })
    }
    if (isToolAvailable("snmpwalk")) {
      try {
        const out = execFileSync("snmpwalk", ["-v2c", "-c", opts.snmpCommunity ?? "public", host, "1.3.6.1.2.1.1", "-t", "3"], {
          encoding: "utf8",
          timeout: 15000,
        })
        if (out.trim()) {
          findings.push({
            id: "TEL-SNMP-002",
            severity: "high",
            title: "SNMP sysDescr retrieved",
            detail: out.split("\n").slice(0, 5).join("; "),
            port: 161,
            evidence: out.slice(0, 300),
          })
        }
      } catch { /* snmpwalk failed */ }
    }
  }

  if (openTelecomPorts.includes(830)) {
    findings.push({
      id: "TEL-NETCONF-001",
      severity: "medium",
      title: "NETCONF management port open",
      detail: "Port 830 — router/switch programmatic config interface",
      port: 830,
    })
  }

  return {
    host,
    dryRun: false,
    sipReachable,
    diameterPortOpen,
    snmpResponded,
    openTelecomPorts,
    findings,
  }
}

export default { auditTelecom, sipOptions, snmpUdpProbe }
