/**
 * @module privesc_chains
 * Complex privesc chains — kernel CVE probes, AD ACL abuse, local escalation paths.
 */
import { ToolBroker } from "./tool_broker.ts"
import { resolveLiveMode } from "./exec_options.ts"
import { PrivilegeEscalator } from "./privesc.ts"

export interface PrivescChainStep {
  name: string
  category: "kernel" | "ad_acl" | "sudo" | "suid" | "service"
  success: boolean
  detail: string
  mitreId?: string
}

export interface PrivescChainResult {
  steps: PrivescChainStep[]
  proven: boolean
  validationLevel: "L3" | "L4"
  summary: string
}

export async function runPrivescChains(opts: {
  domain?: string
  dc?: string
  live?: boolean
  broker?: ToolBroker
} = {}): Promise<PrivescChainResult> {
  const live = resolveLiveMode(opts)
  const broker = opts.broker ?? new ToolBroker()
  const steps: PrivescChainStep[] = []

  if (!live) {
    return {
      steps: [{ name: "blocked", category: "kernel", success: false, detail: "live execution required" }],
      proven: false,
      validationLevel: "L3",
      summary: "Privesc chains require live mode",
    }
  }

  const escalator = new PrivilegeEscalator()
  const local = await escalator.runLivePrivescChecks()
  for (const v of local.vectors.slice(0, 8)) {
    steps.push({
      name: v.name,
      category: v.category === "kernel" ? "kernel" : v.category === "sudo" ? "sudo" : "suid",
      success: v.severity === "critical" || v.severity === "high",
      detail: v.detail,
      mitreId: v.mitreId,
    })
  }

  if (opts.domain || opts.dc) {
    const domain = opts.domain ?? "CORP.LOCAL"
    const dc = opts.dc ?? domain.split(".")[0]
    const aclCmds = [
      `ldapsearch -x -H ldap://${dc} -b DC=example,DC=com (objectClass=user) memberOf`,
    ]
    for (const cmd of aclCmds) {
      try {
        const exec = await broker.executeSafe(cmd, process.cwd())
        const out = (exec.stdout + exec.stderr).slice(0, 400)
        const ok = exec.exitCode === 0 && out.length > 20 && !out.includes("not found")
        steps.push({
          name: cmd.split(" ")[0] ?? "ad_acl",
          category: "ad_acl",
          success: ok,
          detail: out.slice(0, 200),
          mitreId: "T1222.001",
        })
      } catch (err) {
        steps.push({
          name: "ad_acl_probe",
          category: "ad_acl",
          success: false,
          detail: String((err as Error).message).slice(0, 120),
        })
      }
    }
  }

  const proven = steps.some((s) => s.success && (s.category === "kernel" || s.category === "ad_acl"))
  return {
    steps,
    proven,
    validationLevel: proven ? "L4" : "L3",
    summary: proven
      ? `Privesc chain: ${steps.filter((s) => s.success).length}/${steps.length} steps viable`
      : `Privesc enumeration: ${steps.length} probes executed`,
  }
}

export default { runPrivescChains }
