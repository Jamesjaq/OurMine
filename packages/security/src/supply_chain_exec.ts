/**
 * @module supply_chain_exec
 * Supply chain execution path — move beyond audit-only to actionable compromise chains.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { ToolBroker } from "./tool_broker.ts"
import { analyze, auditPackage } from "./supply_chain.ts"

export interface SupplyChainExecStep {
  action: string
  success: boolean
  detail: string
  artifact?: string
}

export interface SupplyChainExecResult {
  package: string
  ecosystem: string
  steps: SupplyChainExecStep[]
  compromiseIndicators: string[]
  summary: string
}

export async function executeSupplyChainChain(opts: {
  package: string
  ecosystem?: string
  projectDir?: string
  live?: boolean
  broker?: ToolBroker
}): Promise<SupplyChainExecResult> {
  const pkg = opts.package
  const ecosystem = opts.ecosystem ?? "npm"
  const steps: SupplyChainExecStep[] = []
  const compromiseIndicators: string[] = []
  const broker = opts.broker ?? new ToolBroker()

  const auditResult = opts.live
    ? await analyze({ package: pkg, ecosystem, live: true })
    : await auditPackage(pkg, ecosystem, { dryRun: !opts.live })

  steps.push({
    action: "registry_audit",
    success: true,
    detail: JSON.stringify(auditResult).slice(0, 300),
  })

  if (opts.projectDir && fs.existsSync(opts.projectDir)) {
    const lockFiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "go.sum"]
    for (const lf of lockFiles) {
      const fp = path.join(opts.projectDir, lf)
      if (!fs.existsSync(fp)) continue
      const content = fs.readFileSync(fp, "utf8")
      if (content.includes(pkg)) {
        compromiseIndicators.push(`Package ${pkg} referenced in ${lf}`)
        steps.push({ action: "lockfile_match", success: true, detail: `Found in ${lf}`, artifact: fp })
      }
    }
  }

  if (opts.live && ecosystem === "npm" && opts.projectDir) {
    try {
      const cmd = `npm ls ${pkg} --json 2>/dev/null || true`
      const exec = await broker.executeSafe(cmd, opts.projectDir)
      steps.push({
        action: "dependency_tree",
        success: exec.exitCode === 0,
        detail: exec.stdout.slice(0, 400),
      })
      if (exec.stdout.includes(pkg)) compromiseIndicators.push(`Active dependency tree contains ${pkg}`)
    } catch (err) {
      steps.push({ action: "dependency_tree", success: false, detail: String((err as Error).message) })
    }
  }

  if (opts.live && fs.existsSync(path.join(opts.projectDir ?? "", "node_modules", pkg))) {
    const pkgJson = path.join(opts.projectDir!, "node_modules", pkg, "package.json")
    if (fs.existsSync(pkgJson)) {
      const meta = JSON.parse(fs.readFileSync(pkgJson, "utf8")) as { scripts?: Record<string, string> }
      const scripts = Object.keys(meta.scripts ?? {})
      if (scripts.some((s) => /postinstall|preinstall|prepare/.test(s))) {
        compromiseIndicators.push(`Suspicious lifecycle scripts in ${pkg}: ${scripts.join(", ")}`)
        steps.push({ action: "lifecycle_script_audit", success: true, detail: scripts.join(", ") })
      }
    }
  }

  const summary = compromiseIndicators.length
    ? `Supply chain exec: ${compromiseIndicators.length} indicator(s) for ${pkg}`
    : `Supply chain exec: audit complete for ${pkg} — no active compromise indicators`

  return { package: pkg, ecosystem, steps, compromiseIndicators, summary }
}

export default { executeSupplyChainChain }
