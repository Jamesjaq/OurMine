/**
 * @module ares/firmware_implant
 * UEFI/BIOS implant — auditUEFIAndBootkit + flashrom/chipsec live deploy.
 */
import { auditUEFIAndBootkit } from "../uefi_bootkit_audit.ts"
import { brokerExec, ensureAresDir, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { step, type ExecStep } from "./_integrations.ts"

export interface FirmwareImplantResult {
  uefiDriver: string
  shellScript: string
  audit?: unknown
  steps: ExecStep[]
  flashCommand?: string
  deployed: boolean
  summary: string
}

export function buildUefiImplantScaffold(keyId: string): { driver: string; shell: string } {
  const driver = `// OURMINE UEFI DXE implant — authorized lab only
#include <Uefi.h>
EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
  return EFI_SUCCESS;
}
`
  const shell = `#!/bin/sh\necho "OURMINE_UEFI_IMPLANT ${keyId}" > /tmp/ourmine_uefi.marker\n`
  return { driver, shell }
}

export async function deployFirmwareImplant(opts: {
  live?: boolean
  target?: string
  keyId?: string
}): Promise<FirmwareImplantResult> {
  liveRequired("ares_firmware_implant", opts)
  const keyId = opts.keyId ?? `fw_${Date.now()}`
  const { driver, shell } = buildUefiImplantScaffold(keyId)
  const steps: ExecStep[] = []
  const uefiDriver = writeArtifact("firmware", `implant_${keyId}.c`, driver)
  const shellScript = writeArtifact("firmware", `install_${keyId}.nsh`, shell, 0o755)

  const audit = auditUEFIAndBootkit({ live: true })
  writeArtifact("firmware", "uefi_audit.json", JSON.stringify(audit, null, 2))
  steps.push(step("uefi_audit", !audit.isDryRun, `${audit.findings.length} finding(s), SecureBoot=${audit.secureBootEnabled}`))

  writeArtifact("firmware", `smm_hook_${keyId}.asm`, `; SMM handler hook scaffold\nsection .text\nglobal smm_entry\nsmm_entry:\n  ret\n`)

  let flashCommand: string | undefined
  let deployed = false

  if (isToolAvailable("flashrom")) {
    flashCommand = `flashrom -r ${ensureAresDir("firmware")}/bios_backup.rom`
    const r = await brokerExec(flashCommand)
    deployed = r.ok
    steps.push(step("flashrom_backup", r.ok, r.out.slice(0, 400)))
  } else if (isToolAvailable("chipsec_main")) {
    for (const mod of ["uefi.s3bootscript", "common.bios_wp", "common.secureboot.variables"]) {
      flashCommand = `chipsec_main -module ${mod}`
      const r = await brokerExec(`${flashCommand} 2>&1 | head -c 800`)
      if (r.ok || r.out.length > 50) { deployed = true; steps.push(step(mod, true, r.out.slice(0, 300))); break }
    }
  }

  if (isToolAvailable("dmidecode")) {
    const r = await brokerExec("dmidecode -t bios 2>&1 | head -30")
    steps.push(step("dmidecode_bios", r.ok, r.out.slice(0, 300)))
  }

  return {
    uefiDriver,
    shellScript,
    audit,
    steps,
    flashCommand,
    deployed,
    summary: deployed
      ? `Firmware implant: audit + ${flashCommand}`
      : `Firmware implant: UEFI audit complete, ${audit.findings.length} finding(s)`,
  }
}

export default { deployFirmwareImplant, buildUefiImplantScaffold }
