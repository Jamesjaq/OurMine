/**
 * @module runtime_capability
 * Runtime capability detection — auto-fallback when raw sockets or tools unavailable.
 */
import * as fs from "node:fs"
import { execFileSync } from "node:child_process"
import { isToolAvailable, type ToolInfo } from "./tool_detection.ts"

export interface CapabilityProbe {
  rawSockets: boolean
  capNetRaw: boolean
  unprivilegedUser: boolean
  containerLikely: boolean
}

export interface ToolFallback {
  primary: string
  fallback: string
  reason: string
}

export interface RuntimeCapabilityReport {
  probe: CapabilityProbe
  toolsChecked: number
  fallbacksAvailable: number
  fallbacks: ToolFallback[]
  recommendations: string[]
}

const FALLBACK_MAP: Array<{ primary: string; fallback: string; reason: string }> = [
  { primary: "nmap", fallback: "curl", reason: "nmap exit 126 in unprivileged container — use curl for HTTP probe" },
  { primary: "nmap", fallback: "nc", reason: "TCP connect via netcat when SYN scan unavailable" },
  { primary: "masscan", fallback: "nmap", reason: "masscan requires CAP_NET_RAW" },
  { primary: "crackmapexec", fallback: "netexec", reason: "netexec is crackmapexec successor" },
  { primary: "crackmapexec", fallback: "smbclient", reason: "smbclient for basic SMB auth" },
  { primary: "impacket-secretsdump", fallback: "rpcclient", reason: "rpcclient partial SAM enum" },
  { primary: "msfconsole", fallback: "curl", reason: "manual exploit probe when MSF absent" },
  { primary: "dig", fallback: "host", reason: "host command DNS lookup fallback" },
  { primary: "gobuster", fallback: "ffuf", reason: "ffuf directory fuzz fallback" },
  { primary: "ffuf", fallback: "curl", reason: "manual path probe when fuzzers absent" },
]

export function probeCapabilities(): CapabilityProbe {
  let rawSockets = true
  let capNetRaw = false
  let unprivilegedUser = process.getuid?.() !== 0
  let containerLikely = false

  try {
    const nmapTest = execFileSync("nmap", ["-sT", "-p", "80", "127.0.0.1"], {
      timeout: 8000,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    })
    rawSockets = nmapTest.length > 0
  } catch (err) {
    const msg = String((err as { status?: number; stderr?: Buffer }).stderr ?? err)
    if (msg.includes("126") || msg.includes("Operation not permitted") || msg.includes("socket")) {
      rawSockets = false
    }
  }

  try {
    if (process.getuid?.() === 0) capNetRaw = true
    else {
      const capsh = execFileSync("capsh", ["--print"], { encoding: "utf8", timeout: 2000 })
      capNetRaw = /cap_net_raw/i.test(capsh)
    }
  } catch { capNetRaw = false }

  try {
    containerLikely = fs.existsSync("/.dockerenv") || fs.existsSync("/run/.containerenv")
  } catch { /* ignore */ }

  return { rawSockets, capNetRaw, unprivilegedUser, containerLikely }
}

export function resolveToolFallback(primary: string): ToolFallback | null {
  for (const fb of FALLBACK_MAP) {
    if (fb.primary !== primary) continue
    if (isToolAvailable(fb.fallback)) return fb
  }
  return null
}

export function resolveScanCommand(host: string, port: number): { tool: string; command: string; note: string } {
  const probe = probeCapabilities()
  if (probe.rawSockets && isToolAvailable("nmap")) {
    return { tool: "nmap", command: `nmap -sT -p ${port} ${host}`, note: "TCP connect scan" }
  }
  if (isToolAvailable("curl") && (port === 80 || port === 443 || port === 8080)) {
    const proto = port === 443 ? "https" : "http"
    return { tool: "curl", command: `curl -sI --max-time 5 ${proto}://${host}:${port}/`, note: "HTTP probe fallback" }
  }
  if (isToolAvailable("nc") || isToolAvailable("netcat")) {
    const bin = isToolAvailable("nc") ? "nc" : "netcat"
    return { tool: bin, command: `${bin} -zv ${host} ${port}`, note: "netcat connect fallback" }
  }
  return { tool: "none", command: "", note: "No scan fallback available" }
}

export async function assessRuntimeCapabilities(): Promise<RuntimeCapabilityReport> {
  const probe = probeCapabilities()
  const fallbacks: ToolFallback[] = []
  const recommendations: string[] = []
  const primaries = [...new Set(FALLBACK_MAP.map((f) => f.primary))]

  for (const primary of primaries) {
    if (isToolAvailable(primary)) continue
    const fb = resolveToolFallback(primary)
    if (fb) fallbacks.push(fb)
  }

  if (!probe.rawSockets) {
    recommendations.push("Use nmap -sT or curl HTTP probes instead of SYN scan")
  }
  if (probe.containerLikely && !probe.capNetRaw) {
    recommendations.push("Running in container without CAP_NET_RAW — prefer connect scans")
  }
  if (!isToolAvailable("nmap") && isToolAvailable("curl")) {
    recommendations.push("nmap unavailable — curl-based service discovery enabled")
  }

  return {
    probe,
    toolsChecked: primaries.length,
    fallbacksAvailable: fallbacks.length,
    fallbacks,
    recommendations,
  }
}

export function pickAvailableTool(...names: string[]): ToolInfo | null {
  for (const name of names) {
    if (isToolAvailable(name)) {
      return { name, available: true, path: name, version: null, required: false, installHint: "" }
    }
    const fb = resolveToolFallback(name)
    if (fb && isToolAvailable(fb.fallback)) {
      return { name: fb.fallback, available: true, path: fb.fallback, version: null, required: false, installHint: fb.reason }
    }
  }
  return null
}

export default { assessRuntimeCapabilities, resolveToolFallback, resolveScanCommand, pickAvailableTool, probeCapabilities }
