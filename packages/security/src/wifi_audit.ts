/**
 * @module wifi_audit
 * Standard WiFi adapter recon — iw/nmcli/nmap. Offensive templates gated by OURMINE_WIFI_OFFENSIVE=1.
 */
import { execFileSync } from "node:child_process"
import * as fs from "node:fs"
import * as path from "node:path"
import { resolveDryRun } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"
import { ensureAresDir, writeArtifact } from "./ares/_base.ts"
import { CAMPUS_WIFI_HINTS } from "./institutional_hints.ts"

export interface WifiNetwork {
  ssid: string
  bssid?: string
  signal?: string
  security?: string
  channel?: string
  open?: boolean
  enterprise?: boolean
}

export interface WifiFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detail: string
  evidence?: string
}

export interface WifiAuditResult {
  target: string
  dryRun: boolean
  interface?: string
  networks: WifiNetwork[]
  openNetworks: WifiNetwork[]
  enterpriseHints: WifiNetwork[]
  findings: WifiFinding[]
  offensiveAllowed: boolean
  templatePaths: string[]
  artifacts: string[]
  summary: string
}

const OFFENSIVE_TEMPLATES = ["deauth_flood.sh", "evil_twin_hostapd.conf", "wpa_capture.sh"]

export function wifiOffensiveAllowed(): boolean {
  return process.env.OURMINE_WIFI_OFFENSIVE === "1" || process.env.OURMINE_WIFI_OFFENSIVE === "true"
}

export function wifiTemplatePaths(): string[] {
  const base = path.join(ensureAresDir("wifi"), "templates")
  fs.mkdirSync(base, { recursive: true })
  return OFFENSIVE_TEMPLATES.map((n) => path.join(base, n))
}

function parseIwScan(out: string): WifiNetwork[] {
  const networks: WifiNetwork[] = []
  let current: Partial<WifiNetwork> = {}
  for (const line of out.split("\n")) {
    const trimmed = line.trim()
    if (trimmed.startsWith("BSS ")) {
      if (current.ssid) networks.push(current as WifiNetwork)
      current = { bssid: trimmed.split(" ")[1]?.replace(/\(.*/, "") }
    } else if (trimmed.startsWith("SSID:")) {
      current.ssid = trimmed.slice(5).trim()
    } else if (trimmed.startsWith("signal:")) {
      current.signal = trimmed.slice(7).trim()
    } else if (trimmed.includes("RSN") || trimmed.includes("WPA")) {
      current.security = trimmed.includes("RSN") ? "WPA2/WPA3" : "WPA"
      current.enterprise = /802\.1X|EAP|enterprise/i.test(trimmed)
    } else if (trimmed.startsWith("capability:") && /Privacy/.test(trimmed) === false) {
      current.open = true
      current.security = "open"
    }
  }
  if (current.ssid) networks.push(current as WifiNetwork)
  return networks.filter((n) => n.ssid)
}

function parseNmcli(out: string): WifiNetwork[] {
  const networks: WifiNetwork[] = []
  for (const line of out.split("\n").slice(1)) {
    const parts = line.split(":")
    if (parts.length < 3) continue
    const ssid = parts[1]?.trim()
    if (!ssid || ssid === "--") continue
    const security = parts[2]?.trim() ?? ""
    networks.push({
      ssid,
      bssid: parts[0]?.trim(),
      signal: parts[6]?.trim(),
      security,
      open: /^\s*$|--/.test(security),
      enterprise: /802\.1X|enterprise/i.test(security),
    })
  }
  return networks
}

function runCmd(cmd: string, args: string[], timeoutMs = 8000): string {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] })
  } catch {
    return ""
  }
}

export async function auditWifi(
  target: string,
  opts: { live?: boolean; dryRun?: boolean; iface?: string; hint?: string } = {},
): Promise<WifiAuditResult> {
  const dryRun = resolveDryRun(opts)
  const templates = wifiTemplatePaths()
  const offensiveAllowed = wifiOffensiveAllowed()
  const h = `${opts.hint ?? ""} ${target}`.toLowerCase()
  const campusHint = CAMPUS_WIFI_HINTS.test(h)

  const campusFindings: WifiFinding[] = campusHint ? [{
    id: "wifi-eduroam-hint",
    severity: "info",
    title: "Campus/eduroam integration",
    detail: "802.1X/EAP via RADIUS (1812) — survey for eduroam SSID, open guest nets, and rogue AP vectors",
    evidence: "eduroam",
  }] : []

  const empty: WifiAuditResult = {
    target,
    dryRun: true,
    networks: campusHint ? [{ ssid: "eduroam", security: "WPA2-Enterprise", enterprise: true }] : [],
    openNetworks: [],
    enterpriseHints: campusHint ? [{ ssid: "eduroam", security: "WPA2-Enterprise", enterprise: true }] : [],
    findings: campusFindings,
    offensiveAllowed,
    templatePaths: templates,
    artifacts: templates,
    summary: campusHint
      ? "dry-run: campus/eduroam hint — wifi_audit primed for 802.1X survey"
      : offensiveAllowed
        ? "dry-run: WiFi recon skipped — set OURMINE_LIVE=1; offensive templates at templatePaths"
        : "dry-run: WiFi recon skipped — offensive templates require OURMINE_WIFI_OFFENSIVE=1",
  }
  if (dryRun) return empty

  const networks: WifiNetwork[] = []
  let iface = opts.iface

  if (!iface && isToolAvailable("iw")) {
    const devOut = runCmd("iw", ["dev"])
    const m = devOut.match(/Interface (\w+)/)
    iface = m?.[1]
  }
  if (!iface && isToolAvailable("nmcli")) {
    const devOut = runCmd("nmcli", ["-t", "-f", "DEVICE,TYPE", "dev"])
    iface = devOut.split("\n").find((l) => l.includes(":wifi"))?.split(":")[0]
  }

  if (iface && isToolAvailable("iw")) {
    runCmd("ip", ["link", "set", iface, "up"])
    networks.push(...parseIwScan(runCmd("iw", ["dev", iface, "scan"], 15000)))
  } else if (isToolAvailable("nmcli")) {
    networks.push(...parseNmcli(runCmd("nmcli", ["-t", "-f", "BSSID,SSID,SECURITY,SIGNAL", "dev", "wifi"])))
  }

  if (isToolAvailable("nmap") && networks.length === 0) {
    const nmapOut = runCmd("nmap", ["--script", "broadcast-wifi-ssids", "-e", iface ?? "wlan0"], 12000)
    for (const m of nmapOut.matchAll(/SSID: "([^"]+)"/g)) {
      networks.push({ ssid: m[1]!, security: "unknown" })
    }
  }

  const openNetworks = networks.filter((n) => n.open || n.security === "open")
  const enterpriseHints = networks.filter((n) => n.enterprise)
  const findings: WifiFinding[] = []
  const artifacts: string[] = []

  for (const n of openNetworks.slice(0, 5)) {
    findings.push({
      id: `wifi-open-${findings.length}`,
      severity: "medium",
      title: `Open network: ${n.ssid}`,
      detail: n.bssid ? `BSSID ${n.bssid}` : "No encryption observed",
      evidence: n.ssid,
    })
  }
  for (const n of enterpriseHints.slice(0, 5)) {
    findings.push({
      id: `wifi-eap-${findings.length}`,
      severity: "info",
      title: `WPA-Enterprise hint: ${n.ssid}`,
      detail: "802.1X/EAP — credential capture vector if rogue AP deployed",
      evidence: n.ssid,
    })
  }

  const scanReport = writeArtifact("wifi", `scan_${Date.now()}.json`, JSON.stringify({ iface, networks }, null, 2))
  artifacts.push(scanReport)

  if (offensiveAllowed) {
    for (const tpl of OFFENSIVE_TEMPLATES) {
      const content = tpl.includes("evil_twin")
        ? `# hostapd evil-twin template — target SSID from scan\nssid=${networks[0]?.ssid ?? "CORP-GUEST"}\n`
        : `# ${tpl} — requires OURMINE_WIFI_OFFENSIVE=1 and scoped authorization\n`
      artifacts.push(writeArtifact("wifi", tpl, content))
    }
  } else if (openNetworks.length || enterpriseHints.length) {
    findings.push({
      id: "wifi-offensive-gated",
      severity: "info",
      title: "Offensive WiFi templates available",
      detail: "Set OURMINE_WIFI_OFFENSIVE=1 for deauth/evil-twin template generation",
    })
  }

  return {
    target,
    dryRun: false,
    interface: iface,
    networks: networks.slice(0, 32),
    openNetworks,
    enterpriseHints,
    findings,
    offensiveAllowed,
    templatePaths: templates,
    artifacts,
    summary: `WiFi audit: ${networks.length} network(s), ${openNetworks.length} open, ${enterpriseHints.length} enterprise hint(s)`,
  }
}

export default { auditWifi, wifiTemplatePaths, wifiOffensiveAllowed }
