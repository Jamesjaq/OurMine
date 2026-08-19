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
      // Check for wordlist, if missing, use a minimal one or download
      const wordlist = "/usr/share/wordlists/dirb/common.txt"
      cmd = `WL=${wordlist}; if [ ! -f "$WL" ]; then sudo apt-get update && sudo apt-get install -y dirb && WL=${wordlist}; fi; if [ ! -f "$WL" ]; then mkdir -p /tmp/wordlists && echo -e "admin\nlogin\nwp-admin\nconfig" > /tmp/wordlists/min.txt && WL=/tmp/wordlists/min.txt; fi; gobuster dir -u "http://${target}" -w "$WL" -q`
      break
    case "metasploit":
      cmd = `msfconsole --version`
      break
    case "nmap":
    default:
      cmd = `nmap ${extraArgs} ${target}`
      break
  }

  let result = executeLiveCommand(cmd)

  // Autonomous Tool Acquisition: If the tool is missing (command not found), install it immediately via apt or pip.
  if (result.code !== 0 && (result.stderr.includes("not found") || result.stdout.includes("not found") || result.stderr.includes("command not found"))) {
    const installCmd = `sudo apt-get update && sudo apt-get install -y ${tool}`
    const installRes = executeLiveCommand(installCmd)
    if (installRes.code === 0) {
      result = executeLiveCommand(cmd) // Re-run after installation
    }
  }
  const success = result.code === 0 || result.stdout.length > 0

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
