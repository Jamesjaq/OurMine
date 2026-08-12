/**
 * @module rmm_audit
 * Remote Monitoring & Management (RMM) abuse assessment — Scattered Spider, ALPHV, LockBit affiliates.
 * Detects legitimate RMM persistence indicators, unsigned installer paths, and C2 channel patterns.
 * Software-only: no hardware required. Dry-run returns simulated findings.
 */
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { resolveDryRun } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"
import { brokerExec } from "./ares/_base.ts"

export interface RmmFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detail: string
  tool?: string
  mitre?: string
  evidence?: string
}

export interface RmmAuditResult {
  target: string
  dryRun: boolean
  toolsChecked: string[]
  findings: RmmFinding[]
  persistencePaths: string[]
  summary: string
}

/** RMM tools abused by tier-1 actors 2024-2026 (CISA/FBI advisories). */
export const RMM_ABUSE_CATALOG = [
  { id: "anydesk", name: "AnyDesk", ports: [7070, 6568], paths: ["AnyDesk.exe", "ad_svc.exe"], actors: ["Scattered Spider", "ALPHV"] },
  { id: "teamviewer", name: "TeamViewer", ports: [5938], paths: ["TeamViewer.exe", "TeamViewer_Service.exe"], actors: ["Scattered Spider", "LockBit"] },
  { id: "splashtop", name: "Splashtop", ports: [6783], paths: ["SplashtopStreamer.exe"], actors: ["ALPHV", "BlackCat"] },
  { id: "screenconnect", name: "ScreenConnect/ConnectWise", ports: [8040, 8041], paths: ["ScreenConnect.ClientService.exe"], actors: ["LockBit", "BlackCat"] },
  { id: "atera", name: "Atera", ports: [9333], paths: ["AteraAgent.exe"], actors: ["Scattered Spider"] },
  { id: "ngrok", name: "Ngrok tunnel", ports: [4040], paths: ["ngrok.exe"], actors: ["ALPHV", "FIN7"] },
  { id: "rustdesk", name: "RustDesk", ports: [21116], paths: ["rustdesk.exe"], actors: ["eCrime affiliates"] },
] as const

const PERSISTENCE_LOCATIONS = [
  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "/Library/LaunchAgents/",
  "/etc/systemd/system/",
  "~/.config/autostart/",
]

function simulatedFindings(target: string): RmmFinding[] {
  return [
    {
      id: "rmm-unmonitored-anydesk",
      severity: "high",
      title: "Unmonitored AnyDesk installation path",
      detail: "AnyDesk commonly deployed post-compromise by Scattered Spider/ALPHV for persistence (T1219)",
      tool: "AnyDesk",
      mitre: "T1219",
      evidence: "C:\\ProgramData\\AnyDesk\\ad_svc.exe (simulated)",
    },
    {
      id: "rmm-screenconnect-no-allowlist",
      severity: "critical",
      title: "ScreenConnect without application allowlist",
      detail: "ConnectWise ScreenConnect abused by LockBit affiliates for hands-on-keyboard access",
      tool: "ScreenConnect",
      mitre: "T1219",
    },
    {
      id: "rmm-ngrok-tunnel",
      severity: "high",
      title: "Ngrok reverse tunnel indicator",
      detail: "ALPHV affiliates use ngrok/plink for C2 tunneling post-RMM deployment",
      tool: "Ngrok",
      mitre: "T1572",
    },
    {
      id: "rmm-helpdesk-social",
      severity: "medium",
      title: "RMM deployed via helpdesk social engineering",
      detail: `${target}: user instructed to install remote support tool during vishing call`,
      mitre: "T1566.002",
    },
  ]
}

async function scanLocalProcesses(): Promise<string[]> {
  if (process.platform === "linux" && isToolAvailable("ps")) {
    const r = await brokerExec("ps aux")
    return r.ok ? r.out.split("\n") : []
  }
  if (process.platform === "win32" && isToolAvailable("tasklist")) {
    const r = await brokerExec("tasklist")
    return r.ok ? r.out.split("\n") : []
  }
  return []
}

function matchRmmInProcessList(lines: string[]): RmmFinding[] {
  const findings: RmmFinding[] = []
  const blob = lines.join("\n").toLowerCase()
  for (const tool of RMM_ABUSE_CATALOG) {
    for (const proc of tool.paths) {
      if (blob.includes(proc.toLowerCase())) {
        findings.push({
          id: `rmm-live-${tool.id}`,
          severity: "high",
          title: `${tool.name} process detected`,
          detail: `Live process match for ${proc} — abused by ${tool.actors.join(", ")}`,
          tool: tool.name,
          mitre: "T1219",
          evidence: proc,
        })
      }
    }
  }
  return findings
}

function checkPersistencePaths(): string[] {
  const hits: string[] = []
  const home = os.homedir()
  for (const loc of PERSISTENCE_LOCATIONS) {
    const expanded = loc.startsWith("~") ? path.join(home, loc.slice(2)) : loc
    if (expanded.includes("HKLM") || expanded.includes("HKCU")) continue
    try {
      if (fs.existsSync(expanded)) hits.push(expanded)
    } catch { /* ignore */ }
  }
  return hits
}

export async function auditRmmAbuse(
  target: string,
  opts: { live?: boolean; dryRun?: boolean; scenario?: string } = {},
): Promise<RmmAuditResult> {
  const dryRun = resolveDryRun(opts)
  const toolsChecked = RMM_ABUSE_CATALOG.map((t) => t.name)

  if (dryRun) {
    const findings = simulatedFindings(target)
    return {
      target,
      dryRun: true,
      toolsChecked,
      findings,
      persistencePaths: PERSISTENCE_LOCATIONS.slice(0, 3),
      summary: `dry-run: ${findings.length} RMM abuse indicators (T1219) — set OURMINE_LIVE=1 for process scan`,
    }
  }

  const procLines = await scanLocalProcesses()
  const findings = matchRmmInProcessList(procLines)
  const persistencePaths = checkPersistencePaths()

  if (!findings.length) {
    findings.push({
      id: "rmm-no-local-match",
      severity: "info",
      title: "No local RMM processes detected",
      detail: `Remote assessment of ${target} — enumerate endpoint RMM via EDR/SIEM for T1219`,
      mitre: "T1219",
    })
  }

  if (persistencePaths.length) {
    findings.push({
      id: "rmm-persistence-paths",
      severity: "medium",
      title: "Autostart persistence locations accessible",
      detail: persistencePaths.join(", "),
      mitre: "T1547.001",
    })
  }

  return {
    target,
    dryRun: false,
    toolsChecked,
    findings,
    persistencePaths,
    summary: `${findings.length} RMM finding(s) on ${target}`,
  }
}

export default { auditRmmAbuse, RMM_ABUSE_CATALOG }
