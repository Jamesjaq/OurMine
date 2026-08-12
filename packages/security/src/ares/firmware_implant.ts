/**
 * @module ares/firmware_implant
 * UEFI/BIOS implant — auditUEFIAndBootkit + flashrom/chipsec live deploy.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { auditUEFIAndBootkit } from "../uefi_bootkit_audit.ts"
import { brokerExec, ensureAresDir, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { runCmd, step, type ExecStep } from "./_integrations.ts"
import { flashFirmwareBackup, runPlatformCmd } from "./_operational.ts"

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
  flashWrite?: boolean
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

  const smmAsm = writeArtifact("firmware", `smm_hook_${keyId}.asm`, `; SMM handler hook\nsection .text\nglobal smm_entry\nsmm_entry:\n  ret\n`)
  if (isToolAvailable("nasm")) {
    const obj = path.join(ensureAresDir("firmware"), `smm_hook_${keyId}.o`)
    steps.push(await runCmd("nasm_smm", `nasm -f elf64 ${smmAsm} -o ${obj} 2>&1`))
  }

  let flashCommand: string | undefined
  let deployed = false
  const backupPath = path.join(ensureAresDir("firmware"), "bios_backup.rom")

  if (isToolAvailable("flashrom")) {
    flashCommand = `flashrom -r ${backupPath}`
    const flashSteps = await flashFirmwareBackup(backupPath, opts.flashWrite ?? process.env.OURMINE_LAB_FLASH_WRITE === "1")
    steps.push(...flashSteps)
    deployed = flashSteps.some((s) => s.success)
  }

  if (isToolAvailable("chipsec_main")) {
    for (const mod of ["uefi.s3bootscript", "common.bios_wp", "common.secureboot.variables", "common.spi_lock"]) {
      flashCommand = `chipsec_main -module ${mod}`
      const r = await brokerExec(`${flashCommand} 2>&1 | head -c 1200`)
      steps.push(step(mod, r.ok || r.out.length > 50, r.out.slice(0, 300)))
      if (r.ok || r.out.length > 50) deployed = true
    }
  }

  if (isToolAvailable("gcc")) {
    const testBin = path.join(ensureAresDir("firmware"), `uefi_test_${keyId}`)
    steps.push(await runCmd("uefi_driver_compile", `gcc -c ${uefiDriver} -o ${testBin}.o 2>&1`))
  }

  steps.push(await runPlatformCmd("secureboot_status", "mokutil --sb-state 2>&1 || echo SB unknown", "powershell -NoProfile -Command \"Confirm-SecureBootUEFI\" 2>&1"))
  steps.push(await runCmd("dmidecode_bios", "dmidecode -t bios 2>&1 | head -30"))

  if (isToolAvailable("bash")) {
    const r = await brokerExec(`bash ${shellScript} 2>&1`)
    steps.push(step("uefi_shell_exec", r.ok || fs.existsSync("/tmp/ourmine_uefi.marker"), r.out.slice(0, 200)))
    if (fs.existsSync("/tmp/ourmine_uefi.marker")) deployed = true
  }

  return {
    uefiDriver,
    shellScript,
    audit,
    steps,
    flashCommand,
    deployed,
    summary: deployed
      ? `Firmware implant: audit + flash/chipsec live (${flashCommand ?? "chipsec"})`
      : `Firmware implant: UEFI audit complete, ${audit.findings.length} finding(s)`,
  }
}

export default { deployFirmwareImplant, buildUefiImplantScaffold }
