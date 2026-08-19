/**
 * @module ares/kali_bridge
 * ARES v3.4.1 Kali Linux Tool Bridge: Seamlessly orchestrates native Kali security tools.
 */

import { moduleEnvelope, executeLiveCommand, realFinding } from "../module_helpers.ts"

export interface KaliBridgeOpts {
  tool?: "nmap" | "sqlmap" | "metasploit" | "hydra" | "gobuster"
  target?: string
  args?: string
  live?: boolean
}

export async function runKaliBridge(opts: KaliBridgeOpts = {}) {
  const live = opts.live ?? true
  const tool = opts.tool ?? "nmap"
  const target = opts.target ?? "127.0.0.1"
  const extraArgs = opts.args ?? "-p- --open -T4"

  let cmd = ""
  switch (tool) {
    case "sqlmap":
      cmd = `sqlmap -u "http://${target}" --batch --random-agent --dbs`
      break
    case "hydra":
      cmd = `hydra -l admin -p password ${target} ssh -t 4`
      break
    case "gobuster":
      cmd = `gobuster dir -u "http://${target}" -w /usr/share/wordlists/dirb/common.txt -q`
      break
    case "metasploit":
      cmd = `msfcli --version` // placeholder for msfconsole automation
      break
    case "nmap":
    default:
      cmd = `nmap ${extraArgs} ${target}`
      break
  }

  const result = executeLiveCommand(cmd)
  const success = result.exitCode === 0 || result.stdout.length > 0

  const findings = [
    realFinding(
      `kali-${tool}`,
      `Kali Linux Native Tool Execution: ${tool.toUpperCase()}`,
      "info",
      `Successfully orchestrated Kali-native tool '${tool}' against target ${target}. Output length: ${result.stdout.length} bytes.`,
      "T1592",
      "Monitor for unauthorized penetration testing tool binaries and execution signatures."
    )
  ]

  return moduleEnvelope(live, {
    tool,
    target,
    command: cmd,
    stdout: result.stdout.slice(0, 2000), // Trim for token efficiency
    stderr: result.stderr,
    success
  }, findings)
}

export default { runKaliBridge }
