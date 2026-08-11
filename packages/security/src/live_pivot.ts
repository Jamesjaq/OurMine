/**
 * Live Post-Exploitation Pivot Engine
 * Real crackmapexec/netexec SMB enumeration + Metasploit auxiliary scanning.
 * Auto-pivot chain for authorized red-team engagements.
 */
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { whichOrNull } from "./which.ts"
import { MetasploitClient } from "./msf_client.ts"

const execFileP = promisify(execFile)

export interface PivotFinding {
  type: "smb_share" | "smb_auth" | "host_enum" | "msf_scan" | "session"
  severity: "critical" | "high" | "medium" | "low"
  host: string
  detail: string
  output: string
  tool: string
}

export interface PivotResult {
  host: string
  findings: PivotFinding[]
  hostsReached: string[]
  summary: string
}

function cmeBinary(): string | null {
  return whichOrNull("netexec") ?? whichOrNull("crackmapexec")
}

export class LivePivotEngine {
  private msf = new MetasploitClient()

  async smbEnum(host: string): Promise<PivotFinding[]> {
    const findings: PivotFinding[] = []
    const bin = cmeBinary()
    if (!bin) {
      return [{
        type: "host_enum",
        severity: "low",
        host,
        detail: "netexec/crackmapexec not on PATH",
        output: "",
        tool: "none",
      }]
    }
    try {
      const res = await execFileP(bin, ["smb", host, "--shares"], { timeout: 120000 })
      const out = res.stdout + res.stderr
      const shareLines = out.split("\n").filter((l) => l.includes("READ") || l.includes("WRITE") || l.includes("Disk"))
      for (const line of shareLines.slice(0, 20)) {
        findings.push({
          type: "smb_share",
          severity: line.includes("WRITE") ? "high" : "medium",
          host,
          detail: line.trim().slice(0, 200),
          output: line.trim(),
          tool: bin,
        })
      }
      if (findings.length === 0 && out.length > 50) {
        findings.push({
          type: "host_enum",
          severity: "medium",
          host,
          detail: "SMB enumeration completed",
          output: out.slice(0, 2000),
          tool: bin,
        })
      }
    } catch (e) {
      const out = String((e as { stdout?: string; stderr?: string }).stdout ?? "") +
        String((e as { stderr?: string }).stderr ?? "")
      if (out.length > 20) {
        findings.push({
          type: "host_enum",
          severity: "medium",
          host,
          detail: "SMB enum partial output",
          output: out.slice(0, 2000),
          tool: bin,
        })
      }
    }
    return findings
  }

  async smbAuth(host: string, username: string, password: string): Promise<PivotFinding[]> {
    const findings: PivotFinding[] = []
    const bin = cmeBinary()
    if (!bin) return findings
    try {
      const args = ["smb", host, "-u", username, "-p", password, "--shares"]
      const res = await execFileP(bin, args, { timeout: 60000 })
      const out = res.stdout + res.stderr
      if (out.includes("(Pwn3d!)") || out.includes("+") || out.includes("READ")) {
        findings.push({
          type: "smb_auth",
          severity: "critical",
          host,
          detail: `Valid SMB credentials: ${username}@${host}`,
          output: out.slice(0, 1500),
          tool: bin,
        })
      }
    } catch (e) {
      const out = String((e as { stdout?: string }).stdout ?? "")
      if (out.includes("(Pwn3d!)")) {
        findings.push({
          type: "smb_auth",
          severity: "critical",
          host,
          detail: `Valid SMB credentials: ${username}@${host}`,
          output: out.slice(0, 1500),
          tool: cmeBinary() ?? "netexec",
        })
      }
    }
    return findings
  }

  async msfAuxScan(host: string, module = "auxiliary/scanner/portscan/tcp"): Promise<PivotFinding[]> {
    if (!whichOrNull("msfconsole")) {
      return [{
        type: "msf_scan",
        severity: "low",
        host,
        detail: "msfconsole not on PATH",
        output: "",
        tool: "msfconsole",
      }]
    }
    const out = await this.msf.runAuxiliaryScan(module, host, { PORTS: "445,135,139,5985,3389" })
    return [{
      type: "msf_scan",
      severity: out.includes("open") ? "medium" : "low",
      host,
      detail: `MSF auxiliary scan on ${host}`,
      output: out.slice(0, 3000),
      tool: "msfconsole",
    }]
  }

  /** Full post-exploit pivot: SMB enum → cred test → MSF port scan */
  async autoPivot(
    host: string,
    opts: { username?: string; password?: string; domain?: string } = {},
  ): Promise<PivotResult> {
    const findings: PivotFinding[] = []
    const hostsReached = new Set<string>([host])

    findings.push(...await this.smbEnum(host))

    if (opts.username && opts.password) {
      findings.push(...await this.smbAuth(host, opts.username, opts.password))
    }

    findings.push(...await this.msfAuxScan(host))

    for (const f of findings) {
      if (f.type === "smb_auth" && f.severity === "critical") {
        hostsReached.add(f.host)
      }
    }

    const critical = findings.filter((f) => f.severity === "critical").length
    const summary = `${findings.length} pivot findings, ${critical} critical, ${hostsReached.size} host(s) in scope`

    return {
      host,
      findings,
      hostsReached: [...hostsReached],
      summary,
    }
  }
}

export default LivePivotEngine
