/**
 * @module ares/supply_chain_implant
 * Full supply-chain kill chain — executeSupplyChainChain + CicdSupplyChainAuditor + codesign harvest.
 */
import { executeSupplyChainChain } from "../supply_chain_exec.ts"
import { CicdSupplyChainAuditor } from "../cicd_supplychain.ts"
import { analyze } from "../supply_chain.ts"
import { brokerExec, liveRequired, writeArtifact } from "./_base.ts"
import { runCmd, step, type ExecStep } from "./_integrations.ts"
import { harvestCodesignCerts } from "./_operational.ts"

export interface SupplyChainImplantResult {
  package: string
  steps: ExecStep[]
  artifacts: string[]
  cicdFindings: number
  summary: string
}

export async function runSupplyChainImplant(opts: {
  live?: boolean
  package?: string
  projectDir?: string
  ecosystem?: string
}): Promise<SupplyChainImplantResult> {
  liveRequired("ares_supply_chain_implant", opts)
  const pkg = opts.package ?? "lodash"
  const projectDir = opts.projectDir ?? process.cwd()
  const steps: ExecStep[] = []
  const artifacts: string[] = []

  const chain = await executeSupplyChainChain({
    package: pkg,
    ecosystem: opts.ecosystem ?? "npm",
    projectDir,
    live: true,
  })
  for (const s of chain.steps) {
    steps.push(step(s.action, s.success, s.detail.slice(0, 400)))
    if (s.artifact) artifacts.push(s.artifact)
  }

  const auditor = new CicdSupplyChainAuditor()
  const cicd = await auditor.auditPipeline({ cwd: projectDir, dryRun: false })
  writeArtifact("supply_chain", "cicd_audit.json", JSON.stringify(cicd, null, 2))
  steps.push(step("cicd_audit", cicd.findings.length >= 0, `${cicd.workflowsParsed} workflow(s), ${cicd.findings.length} finding(s)`))

  const registry = await analyze({ package: pkg, ecosystem: opts.ecosystem ?? "npm", live: true })
  writeArtifact("supply_chain", "registry_analysis.json", JSON.stringify(registry, null, 2))
  steps.push(step("registry_analysis", true, JSON.stringify(registry).slice(0, 300)))

  steps.push(await runCmd("npm_audit", `npm audit --json 2>/dev/null | head -c 3000`))
  steps.push(await runCmd("npm_ls", `npm ls ${pkg} --json 2>/dev/null | head -c 2000`))

  const ciPoison = writeArtifact("supply_chain", "cicd_poison.yml", `name: build\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n      - run: echo "CI poison scaffold for ${pkg}"\n`)
  artifacts.push(ciPoison)
  if (await toolExists("actionlint")) {
    steps.push(await runCmd("actionlint_validate", `actionlint ${ciPoison} 2>&1 || true`))
  }

  steps.push(await harvestCodesignCerts(projectDir))

  const typosquat = await brokerExec(`npm search ${pkg.slice(0, 4)} 2>/dev/null | head -10`)
  steps.push(step("typosquat_probe", typosquat.ok || typosquat.out.length > 5, typosquat.out.slice(0, 300)))

  return {
    package: pkg,
    steps,
    artifacts,
    cicdFindings: cicd.findings.length,
    summary: `Supply chain implant: ${steps.filter((s) => s.success).length}/${steps.length} phases for ${pkg}`,
  }
}

async function toolExists(name: string): Promise<boolean> {
  const r = await brokerExec(`command -v ${name} 2>/dev/null`)
  return r.ok && r.out.trim().length > 0
}

export default { runSupplyChainImplant }
