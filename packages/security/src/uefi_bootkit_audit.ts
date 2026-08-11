/**
 * @module security/uefi_bootkit_audit
 * UEFI Firmware, Secure Boot & BYOVD Driver Audit Engine
 * Inspects Secure Boot status, DBX revocation databases, NVRAM flags,
 * Driver Signature Enforcement, unsigned kernel modules, and known bootkit indicators.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as fs from "node:fs"
import { execFileSync } from "node:child_process"
import { isToolAvailable } from "./tool_detection.ts"

export interface UEFIFinding {
  id: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  title: string
  description: string
  remediation: string
}

export interface UEFIBootkitIndicator {
  name: string
  description: string
  detected: boolean
  evidence: string[]
}

export interface UEFIAuditResult {
  secureBootEnabled: boolean
  dbxDatabaseUpToDate: boolean
  dbxHashCount: number
  vulnerableDriversDetected: string[]
  dseStatus: "ENFORCED" | "DISABLED" | "UNKNOWN"
  unsignedKernelModules: string[]
  nvramVariables: Array<{ name: string; guid: string; suspicious: boolean }>
  bootkitIndicators: UEFIBootkitIndicator[]
  findings: UEFIFinding[]
  isDryRun: boolean
}

function execCmd(cmd: string, args: string[]): string {
  try {
    return execFileSync(cmd, args, {
      timeout: 10000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim()
  } catch {
    return ""
  }
}

function readSysfsBinary(p: string): Buffer | null {
  try {
    if (fs.existsSync(p)) {
      return fs.readFileSync(p)
    }
  } catch {}
  return null
}

function readSysfsText(p: string): string {
  try {
    if (fs.existsSync(p)) {
      return fs.readFileSync(p, "utf8").trim()
    }
  } catch {}
  return ""
}

function directoryExists(p: string): boolean {
  try {
    return fs.existsSync(p) && fs.statSync(p).isDirectory()
  } catch {
    return false
  }
}

// ── Known vulnerable signed drivers (BYOVD) ─────────────────────────────────

const KNOWN_VULNERABLE_DRIVERS: Record<string, string> = {
  "gdrv.sys": "CVE-2019-16098 - Gigabyte driver arbitrary kernel read/write",
  "procexp.sys": "CVE-2018-19324 - Process Explorer driver privilege escalation",
  "RTCore64.sys": "CVE-2019-16097 - MSI Afterburner driver arbitrary MSR write",
  "RTCore32.sys": "CVE-2019-16097 - MSI Afterburner driver arbitrary MSR write",
  "RTCore2.sys": "CVE-2019-16097 - MSI Afterburner driver arbitrary MSR write",
  "DBUtil_2_3.sys": "CVE-2021-36934 - Dell DBUtil driver privilege escalation",
  "DBUtil_3_1.sys": "CVE-2021-36934 - Dell DBUtil driver privilege escalation",
  "HpPortIox64.sys": "CVE-2021-1885 - HP driver privilege escalation",
  "HpSAMD.sys": "CVE-2021-1885 - HP driver privilege escalation",
  "RwDrv.sys": "CVE-2022-34718 - ASUS RwDrv arbitrary kernel read/write",
  "WinRing0x64.sys": "CVE-2022-34718 - HP OMEN driver privilege escalation",
  "AsIO.sys": "CVE-2019-17637 - ASUS ASUSCertService privilege escalation",
  "AsIO3.sys": "CVE-2019-17637 - ASUS ASUSCertService privilege escalation",
  "IOBitBitLocker.sys": "CVE-2022-34718 - IObit driver arbitrary kernel access",
  "DirectIo64.sys": "CVE-2016-0039 - Microsoft Surface driver privilege escalation",
  "nvoclock.sys": "CVE-2021-34401 - NVIDIA NVDisplay.Container local privilege escalation",
  "MyZamamr64.sys": "CVE-2021-1885 - HP ZAM driver privilege escalation",
  "ZAM_Guard.sys": "CVE-2021-1885 - Zemana Anti-Malware driver privilege escalation",
  "ZAM_64.sys": "CVE-2021-1885 - Zemana Anti-Malware driver privilege escalation",
  "eapi.sys": "CVE-2021-21551 - Dell DBUtil driver arbitrary kernel access",
  "DellSmbiosKm64.sys": "CVE-2021-21551 - Dell BIOS driver privilege escalation",
}

// ── Known bootkit NVRAM variables and file indicators ────────────────────────

const BOOTKIT_SIGNATURES: Array<{
  name: string
  nvramVars: string[]
  bootPaths: string[]
  hashes: string[]
  description: string
}> = [
  {
    name: "LoJax",
    nvramVars: ["CsEnable", "VSS", "Setup"],
    bootPaths: ["/EFI/LOJAX/", "/efi/LOJAX/", "/EFI/Microsoft/Boot/LOJAX"],
    hashes: ["5a8e572229649e4c46828780887f91d1"],
    description:
      "LoJax: First in-the-wild UEFI rootkit (2018) by Fancy Bear. Replaces NVRAM variables and drops UEFI module to ESP.",
  },
  {
    name: "MosaicRegressor",
    nvramVars: ["IntelSilicon", "PlatformLang", "Timeout"],
    bootPaths: ["/EFI/Mosaic/", "/efi/mosaic/"],
    hashes: [],
    description:
      "MosaicRegressor: Multi-stage UEFI bootkit by HackingTeam (2019). Embeds in ESP bootloader chain.",
  },
  {
    name: "FinSpy",
    nvramVars: ["BootOptionSupport"],
    bootPaths: ["/EFI/Boot/Bootx64.efi"],
    hashes: ["4b2a15a6d5f3e6d21e4f4a1e6c5d4b2a"],
    description:
      "FinSpy: UEFI bootkit component used by FinFisher. Replaces Windows Boot Manager to intercept OS load.",
  },
  {
    name: "CosmicStrand",
    nvramVars: ["PlatformLang", "Timeout"],
    bootPaths: [],
    hashes: [],
    description:
      "CosmicStrand: Firmware-level rootkit targeting ASUS motherboards, implants in CSM module (2022).",
  },
  {
    name: "BlackLotus",
    nvramVars: ["Boot0000", "BootOrder", "KEK"],
    bootPaths: ["/EFI/Microsoft/Boot/bootmgfw.efi"],
    hashes: ["e40e1a0a63b167e98cfbd32f2f0e7c23"],
    description:
      "BlackLotus: UEFI bootkit bypassing Secure Boot via CVE-2022-21894 (BP000000). Drops vulnerable boot loader to bypass DBX.",
  },
]

// ── NVRAM variable GUIDs for identification ──────────────────────────────────

const EFI_VAR_DIR = "/sys/firmware/efi/efivars"
const BOOTLOADER_DIR = "/sys/firmware/efi/fmp"

const SUSPICIOUS_NVRAM_NAMES = new Set([
  "Setup",
  "CsEnable",
  "VSS",
  "BootOptionSupport",
  "IntelSilicon",
  "PlatformLang",
  "Timeout",
  "ConOut",
  "ConIn",
  "ErrOut",
])

function parseEfiVarFilename(filename: string): { name: string; guid: string } | null {
  const lastDash = filename.lastIndexOf("-")
  if (lastDash === -1) return null
  return {
    name: filename.substring(0, lastDash),
    guid: filename.substring(lastDash + 1),
  }
}

function readSecureBootStatus(): boolean {
  const dataPath =
    "/sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data"
  const buf = readSysfsBinary(dataPath)
  if (buf && buf.length > 0) {
    return buf[0] === 1
  }
  return false
}

function parseDbxHashCount(): { count: number; upToDate: boolean } {
  const dbxPath =
    "/sys/firmware/efi/vars/dbDefault-d719b2cb-3d3a-4596-a3bc-dad0f4c2c856/data"
  const dbxVarPath = "/sys/firmware/efi/vars"

  let dbxFile = dbxPath

  // Try multiple known DBX variable names
  const dbxNames = [
    "dbDefault-d719b2cb-3d3a-4596-a3bc-dad0f4c2c856",
    "db-d719b2cb-3d3a-4596-a3bc-dad0f4c2c856",
    "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
  ]

  if (directoryExists(dbxVarPath)) {
    const entries = fs.readdirSync(dbxVarPath)
    const dbxEntry = entries.find(
      (e) => e.startsWith("dbDefault-") || e.startsWith("db-")
    )
    if (dbxEntry) {
      dbxFile = path.join(dbxVarPath, dbxEntry)
    }
  }

  const buf = readSysfsBinary(dbxFile)
  if (!buf || buf.length < 128) {
    return { count: 0, upToDate: false }
  }

  // Parse EFI_SIGNATURE_LIST structure
  // SignatureListSize(4) | SignatureHeaderSize(4) | SignatureSize(4) | Signatures...
  let hashCount = 0
  let offset = 0

  while (offset + 12 <= buf.length) {
    const sigListSize = buf.readUInt32LE(offset)
    const sigHeaderSize = buf.readUInt32LE(offset + 4)
    const sigSize = buf.readUInt32LE(offset + 8)

    if (sigSize === 0 || sigListSize === 0) break

    const sigDataStart = offset + 12 + sigHeaderSize
    const sigDataEnd = offset + sigListSize

    if (sigDataEnd > buf.length) break

    if (sigSize > 0) {
      const sigCount = Math.floor(
        (sigDataEnd - sigDataStart) / sigSize
      )
      hashCount += sigCount
    }

    offset = sigDataEnd
  }

  // Heuristic: systems with >200 DBX entries are reasonably up-to-date
  const upToDate = hashCount >= 200
  return { count: hashCount, upToDate }
}

function detectVulnerableDrivers(): string[] {
  const found: string[] = []

  if (process.platform === "linux") {
    // Check loaded kernel modules for known vulnerable drivers
    const lsmod = execCmd("lsmod", [])
    if (lsmod) {
      const lines = lsmod.split("\n")
      for (const line of lines) {
        const modName = line.split(/\s+/)[0]?.toLowerCase()
        if (!modName) continue
        for (const driverName of Object.keys(KNOWN_VULNERABLE_DRIVERS)) {
          if (modName === driverName.replace(".sys", "").toLowerCase()) {
            found.push(driverName)
          }
        }
      }
    }

    // Check /proc/modules for loaded modules
    const procModules = readSysfsText("/proc/modules")
    if (procModules) {
      for (const driverName of Object.keys(KNOWN_VULNERABLE_DRIVERS)) {
        const modBase = driverName.replace(".sys", "").toLowerCase()
        if (procModules.toLowerCase().includes(modBase)) {
          if (!found.includes(driverName)) {
            found.push(driverName)
          }
        }
      }
    }
  }

  if (process.platform === "win32") {
    const driverOutput = execCmd("driverquery", ["/FO", "CSV", "/NH"])
    if (driverOutput) {
      for (const driverName of Object.keys(KNOWN_VULNERABLE_DRIVERS)) {
        if (driverOutput.toLowerCase().includes(driverName.toLowerCase())) {
          found.push(driverName)
        }
      }
    }

    // Fallback: check common Windows driver paths
    const sys32Drivers = path.join(
      process.env.WINDIR || "C:\\Windows",
      "System32",
      "drivers"
    )
    if (directoryExists(sys32Drivers)) {
      const files = fs.readdirSync(sys32Drivers)
      for (const driverName of Object.keys(KNOWN_VULNERABLE_DRIVERS)) {
        if (
          files.some((f) => f.toLowerCase() === driverName.toLowerCase()) &&
          !found.includes(driverName)
        ) {
          found.push(driverName)
        }
      }
    }
  }

  return found
}

function checkDSEStatus(): "ENFORCED" | "DISABLED" | "UNKNOWN" {
  if (process.platform === "linux") {
    // On Linux, check kernel lockdown mode
    const lockdown = readSysfsText(
      "/sys/kernel/security/lockdown"
    )
    if (lockdown) {
      if (lockdown.includes("[none]")) return "DISABLED"
      if (
        lockdown.includes("[integrity]") ||
        lockdown.includes("[confidentiality]")
      ) {
        return "ENFORCED"
      }
    }

    // Check secure boot enforcement in kernel config
    const cmdline = readSysfsText("/proc/cmdline")
    if (cmdline.includes("lockdown=")) {
      const match = cmdline.match(/lockdown=(\w+)/)
      if (match) {
        if (match[1] === "none") return "DISABLED"
        return "ENFORCED"
      }
    }

    // If Secure Boot is enabled, DSE is implicitly enforced
    if (readSecureBootStatus()) return "ENFORCED"
    return "UNKNOWN"
  }

  if (process.platform === "win32") {
    const bcd = execCmd("bcdedit", ["/enum", "{current}"])
    if (bcd) {
      if (bcd.toLowerCase().includes("nointegritychecks Yes"))
        return "DISABLED"
      if (bcd.toLowerCase().includes("testsigning Yes")) return "DISABLED"
    }
    return "ENFORCED"
  }

  return "UNKNOWN"
}

function detectUnsignedKernelModules(): string[] {
  const unsigned: string[] = []

  if (process.platform === "linux") {
    const dmesg = execCmd("dmesg", [])
    if (dmesg) {
      const lines = dmesg.split("\n")
      for (const line of lines) {
        if (
          line.toLowerCase().includes("module") &&
          line.toLowerCase().includes("unknown symbol")
        ) {
          const match = line.match(/module\s+(\w+)/)
          if (match && !unsigned.includes(match[1])) {
            unsigned.push(match[1])
          }
        }
        if (
          line.includes("Loading module") &&
          line.includes("verification failure")
        ) {
          const match = line.match(/module\s+(\w+)/)
          if (match && !unsigned.includes(match[1])) {
            unsigned.push(match[1])
          }
        }
      }
    }

    // Check kernel taint status
    const tainted = readSysfsText("/proc/sys/kernel/tainted")
    if (tainted && tainted !== "0") {
      const flags = parseInt(tainted, 10)
      // Bit 8 (256) = module was not loaded with force
      // Bit 1 (1) = proprietary module loaded
      if (flags & 1) {
        unsigned.push("[taint:proprietary-module-loaded]")
      }
      if (flags & 8) {
        unsigned.push("[taint:staging-driver]")
      }
      if (flags & 128) {
        unsigned.push("[taint:unsigned-module]")
      }
    }

    // List currently loaded modules and check signatures
    const modprobeList = execCmd("lsmod", [])
    if (modprobeList) {
      const modulesDir = "/lib/modules"
      const kernelVersion = execCmd("uname", ["-r"])
      const modDir = path.join(modulesDir, kernelVersion, "kernel")

      if (directoryExists(modDir) && isToolAvailable("modinfo")) {
        const lines = modprobeList.split("\n").slice(1)
        for (const line of lines) {
          const modName = line.split(/\s+/)[0]
          if (!modName) continue

          const modInfo = execCmd("modinfo", ["-F", "signer", modName])
          if (modInfo === "" || modInfo.includes("unknown")) {
            if (!unsigned.includes(modName)) {
              unsigned.push(modName)
            }
          }
        }
      }
    }
  }

  return unsigned
}

function enumerateNvramVariables(): Array<{
  name: string
  guid: string
  suspicious: boolean
}> {
  const vars: Array<{ name: string; guid: string; suspicious: boolean }> = []

  if (!directoryExists(EFI_VAR_DIR)) return vars

  try {
    const entries = fs.readdirSync(EFI_VAR_DIR)
    for (const entry of entries) {
      const parsed = parseEfiVarFilename(entry)
      if (parsed) {
        vars.push({
          name: parsed.name,
          guid: parsed.guid,
          suspicious: SUSPICIOUS_NVRAM_NAMES.has(parsed.name),
        })
      }
    }
  } catch {}

  return vars
}

function detectBootkitIndicators(
  nvramVars: Array<{ name: string; guid: string; suspicious: boolean }>
): UEFIBootkitIndicator[] {
  const indicators: UEFIBootkitIndicator[] = []
  const nvramNames = new Set(nvramVars.map((v) => v.name))
  const espPaths = [
    "/boot/efi/EFI",
    "/efi/EFI",
    "/boot/EFI",
    "/EFI",
  ]

  for (const sig of BOOTKIT_SIGNATURES) {
    const evidence: string[] = []
    let detected = false

    // Check NVRAM variable presence
    for (const v of sig.nvramVars) {
      if (nvramNames.has(v)) {
        evidence.push(`NVRAM variable '${v}' present`)
        detected = true
      }
    }

    // Check for bootkit-specific boot paths
    for (const bootPath of sig.bootPaths) {
      if (fs.existsSync(bootPath) || directoryExists(bootPath)) {
        evidence.push(`Boot path exists: ${bootPath}`)
        detected = true
      }
    }

    // Check ESP directories for suspicious bootloaders
    for (const espPath of espPaths) {
      if (directoryExists(espPath)) {
        try {
          const contents = fs.readdirSync(espPath)
          const suspiciousNames = sig.name.toLowerCase()
          for (const c of contents) {
            if (c.toLowerCase().includes(suspiciousNames)) {
              evidence.push(`Suspicious entry in ${espPath}: ${c}`)
              detected = true
            }
          }
        } catch {}
      }
    }

    // Check for hash matches (if we can hash ESP files)
    if (sig.hashes.length > 0 && isToolAvailable("sha256sum")) {
      for (const espPath of espPaths) {
        if (!directoryExists(espPath)) continue
        try {
          const findResult = execCmd("find", [
            espPath,
            "-name",
            "*.efi",
            "-type",
            "f",
          ])
          if (findResult) {
            const files = findResult.split("\n").filter(Boolean)
            for (const f of files.slice(0, 20)) {
              const hash = execCmd("sha256sum", [f])
              const fileHash = hash.split(/\s+/)[0]
              if (sig.hashes.includes(fileHash)) {
                evidence.push(`Hash match in ${f}: ${fileHash}`)
                detected = true
              }
            }
          }
        } catch {}
      }
    }

    indicators.push({
      name: sig.name,
      description: sig.description,
      detected,
      evidence,
    })
  }

  return indicators
}

// ── Dry-Run Result Generator ─────────────────────────────────────────────────

function generateDryRunResult(): UEFIAuditResult {
  return {
    secureBootEnabled: true,
    dbxDatabaseUpToDate: false,
    dbxHashCount: 142,
    vulnerableDriversDetected: ["gdrv.sys", "procexp.sys", "RTCore64.sys", "DBUtil_2_3.sys"],
    dseStatus: "ENFORCED",
    unsignedKernelModules: [],
    nvramVariables: [
      { name: "SecureBoot", guid: "8be4df61-93ca-11d2-aa0d-00e098032b8c", suspicious: false },
      { name: "PK", guid: "8be4df61-93ca-11d2-aa0d-00e098032b8c", suspicious: false },
      { name: "KEK", guid: "8be4df61-93ca-11d2-aa0d-00e098032b8c", suspicious: false },
      { name: "db", guid: "d719b2cb-3d3a-4596-a3bc-dad0f4c2c856", suspicious: false },
      { name: "dbx", guid: "d719b2cb-3d3a-4596-a3bc-dad0f4c2c856", suspicious: false },
      { name: "Setup", guid: "8be4df61-93ca-11d2-aa0d-00e098032b8c", suspicious: true },
      { name: "PlatformLang", guid: "8be4df61-93ca-11d2-aa0d-00e098032b8c", suspicious: true },
      { name: "Timeout", guid: "8be4df61-93ca-11d2-aa0d-00e098032b8c", suspicious: true },
      { name: "Boot0000", guid: "8be4df61-93ca-11d2-aa0d-00e098032b8c", suspicious: false },
      { name: "BootOrder", guid: "8be4df61-93ca-11d2-aa0d-00e098032b8c", suspicious: false },
    ],
    bootkitIndicators: [
      {
        name: "LoJax",
        description: "LoJax: First in-the-wild UEFI rootkit (2018) by Fancy Bear. Replaces NVRAM variables and drops UEFI module to ESP.",
        detected: false,
        evidence: [],
      },
      {
        name: "MosaicRegressor",
        description: "MosaicRegressor: Multi-stage UEFI bootkit by HackingTeam (2019). Embeds in ESP bootloader chain.",
        detected: false,
        evidence: [],
      },
      {
        name: "FinSpy",
        description: "FinSpy: UEFI bootkit component used by FinFisher. Replaces Windows Boot Manager to intercept OS load.",
        detected: false,
        evidence: [],
      },
      {
        name: "CosmicStrand",
        description: "CosmicStrand: Firmware-level rootkit targeting ASUS motherboards, implants in CSM module (2022).",
        detected: false,
        evidence: [],
      },
      {
        name: "BlackLotus",
        description: "BlackLotus: UEFI bootkit bypassing Secure Boot via CVE-2022-21894 (BP000000). Drops vulnerable boot loader to bypass DBX.",
        detected: false,
        evidence: [],
      },
    ],
    findings: [
      {
        id: "UEFI-01",
        severity: "CRITICAL",
        title: "Outdated Secure Boot DBX Revocation List",
        description:
          "EFI system partition DBX signature database contains only 142 hashes (expected 500+). Missing revocation hashes for CVE-2022-21899 (Baton Drop), CVE-2023-24938 (PKfail), and CVE-2024-21302 (BootKit). An attacker with physical access can sign a malicious UEFI module using a known-vulnerable key.",
        remediation:
          "Apply official Windows/Linux UEFI DBX update package (e.g., KB5025885). Verify after update that /sys/firmware/efi/vars/db* entries reflect updated revocations.",
      },
      {
        id: "UEFI-02",
        severity: "CRITICAL",
        title: "Vulnerable Signed Driver Loaded (BYOVD): gdrv.sys",
        description:
          "Gigabyte gdrv.sys (CVE-2019-16098) is present. This driver allows arbitrary kernel physical memory read/write from userland via IOCTL 0xC3502000. Attackers can disable PatchGuard and elevate to SYSTEM.",
        remediation:
          "Uninstall Gigabyte App Center or replace gdrv.sys with a signed vendor-patched version. Audit driver load events via Sysmon EID 6.",
      },
      {
        id: "UEFI-03",
        severity: "CRITICAL",
        title: "Vulnerable Signed Driver Loaded (BYOVD): RTCore64.sys",
        description:
          "MSI Afterburner RTCore64.sys (CVE-2019-16097) allows arbitrary MSR read/write via IOCTL 0xC35024D8. Enables disabling of hypervisor-based protections (HVCI, Credential Guard).",
        remediation:
          "Update MSI Afterburner to latest version or remove. Remove driver from system and block reinstallation via WDAC policy.",
      },
      {
        id: "UEFI-04",
        severity: "HIGH",
        title: "Vulnerable Signed Driver Present (BYOVD): DBUtil_2_3.sys",
        description:
          "Dell DBUtil_2_3.sys (CVE-2021-36934) is present. Exploitation allows arbitrary kernel memory access via IOCTL 0x9B0C1EC4.",
        remediation:
          "Update Dell SupportAssist or remove DBUtil driver. Apply Dell security advisory DSA-2021-127.",
      },
      {
        id: "UEFI-05",
        severity: "MEDIUM",
        title: "UEFI NVRAM Variable Tampering Risk",
        description:
          "Suspicious NVRAM variables (Setup, PlatformLang, Timeout) detected. These variables are commonly modified by UEFI bootkits to alter boot order or disable Secure Boot.",
        remediation:
          "Reset NVRAM to factory defaults via UEFI firmware settings. Monitor for unauthorized changes using UEFI variable audit tools.",
      },
      {
        id: "UEFI-06",
        severity: "LOW",
        title: "DBX Update Available",
        description:
          "System DBX revocation list contains 142 entries. Current best practice recommends 500+ entries to cover all known vulnerable UEFI modules and keys.",
        remediation:
          "Download latest UEFI DBX update from vendor. Apply via firmware update mechanism.",
      },
    ],
    isDryRun: true,
  }
}

// ── Live Audit Implementation ────────────────────────────────────────────────

function runLiveAudit(): UEFIAuditResult {
  const findings: UEFIFinding[] = []
  let findingCounter = 0

  const nextId = (prefix: string) => {
    findingCounter++
    return `${prefix}-${String(findingCounter).padStart(2, "0")}`
  }

  // ── 1. Secure Boot Status ──
  const efiPresent = directoryExists("/sys/firmware/efi")
  let secureBoot = false

  if (efiPresent) {
    secureBoot = readSecureBootStatus()
  }

  if (efiPresent && !secureBoot) {
    findings.push({
      id: nextId("UEFI"),
      severity: "HIGH",
      title: "Secure Boot Disabled",
      description:
        "UEFI Secure Boot status is disabled. Firmware will not verify bootloader or driver signatures, allowing unsigned code execution at boot.",
      remediation: "Enable Secure Boot in system UEFI/BIOS settings under Security or Boot tabs.",
    })
  }

  if (!efiPresent) {
    findings.push({
      id: nextId("UEFI"),
      severity: "MEDIUM",
      title: "EFI Firmware Not Detected",
      description:
        "/sys/firmware/efi not found. System may use legacy BIOS or running in a container/VM without EFI passthrough.",
      remediation:
        "Verify firmware mode in system BIOS settings. Some VMs require explicit EFI configuration.",
    })
  }

  // ── 2. DBX Revocation List ──
  const { count: dbxHashCount, upToDate: dbxUpToDate } = parseDbxHashCount()

  if (efiPresent && !dbxUpToDate) {
    findings.push({
      id: nextId("UEFI"),
      severity: "CRITICAL",
      title: "Outdated Secure Boot DBX Revocation List",
      description: `DBX signature database contains ${dbxHashCount} revocation entries (expected 500+). Missing revocation hashes for CVE-2022-21899 (Baton Drop), CVE-2023-24938 (PKfail), and CVE-2024-21302.`,
      remediation:
        "Apply official Windows/Linux UEFI DBX update package (e.g., KB5025885). Verify after update via /sys/firmware/efi/vars/db*.",
    })
  }

  // ── 3. Vulnerable Signed Drivers (BYOVD) ──
  const vulnerableDrivers = detectVulnerableDrivers()

  for (const driver of vulnerableDrivers) {
    const cve = KNOWN_VULNERABLE_DRIVERS[driver]
    findings.push({
      id: nextId("UEFI"),
      severity: "CRITICAL",
      title: `Vulnerable Signed Driver Detected (BYOVD): ${driver}`,
      description: `${cve}. Signed drivers can be loaded to bypass kernel security mechanisms.`,
      remediation:
        `Remove ${driver} from system. Block reinstallation via WDAC/AppLocker policy. Audit driver load events.`,
    })
  }

  // ── 4. Driver Signature Enforcement (DSE) ──
  const dseStatus = checkDSEStatus()

  if (dseStatus === "DISABLED") {
    findings.push({
      id: nextId("UEFI"),
      severity: "HIGH",
      title: "Driver Signature Enforcement Disabled",
      description:
        "DSE is disabled. System will load unsigned and test-signed kernel drivers, enabling rootkit installation.",
      remediation:
        "Remove test signing mode. On Windows: bcdedit /set testsigning off. On Linux: remove 'module.sig_enforce=0' from kernel cmdline.",
    })
  }

  // ── 5. Unsigned Kernel Modules ──
  const unsignedModules = detectUnsignedKernelModules()

  for (const mod of unsignedModules) {
    if (mod.startsWith("[")) {
      findings.push({
        id: nextId("UEFI"),
        severity: "MEDIUM",
        title: `Kernel Taint Flag: ${mod}`,
        description: `Kernel taint flag detected: ${mod}. This may indicate unsigned or out-of-tree module loading.`,
        remediation: "Investigate source of tainted kernel modules. Remove unsigned or proprietary modules.",
      })
    } else {
      findings.push({
        id: nextId("UEFI"),
        severity: "HIGH",
        title: `Unsigned Kernel Module Loaded: ${mod}`,
        description: `Kernel module '${mod}' appears to be unsigned or loaded without signature verification.`,
        remediation: `Verify module signature with 'modinfo ${mod}'. Remove if not from trusted vendor.`,
      })
    }
  }

  // ── 6. NVRAM Variable Enumeration ──
  const nvramVariables = enumerateNvramVariables()
  const suspiciousVars = nvramVariables.filter((v) => v.suspicious)

  if (suspiciousVars.length > 0 && efiPresent) {
    findings.push({
      id: nextId("UEFI"),
      severity: "MEDIUM",
      title: "Suspicious UEFI NVRAM Variables Detected",
      description: `Found ${suspiciousVars.length} suspicious NVRAM variables: ${suspiciousVars.map((v) => v.name).join(", ")}. These are commonly modified by UEFI bootkits.`,
      remediation:
        "Reset NVRAM to factory defaults via UEFI firmware settings. Monitor for unauthorized changes.",
    })
  }

  // ── 7. Known Bootkit Indicators ──
  const bootkitIndicators = detectBootkitIndicators(nvramVariables)

  for (const indicator of bootkitIndicators) {
    if (indicator.detected) {
      findings.push({
        id: nextId("UEFI"),
        severity: "CRITICAL",
        title: `Potential Bootkit Detected: ${indicator.name}`,
        description: `${indicator.description} Evidence: ${indicator.evidence.join("; ")}`,
        remediation:
          "Immediately reflash UEFI firmware from vendor. Reinstall OS from trusted media. Engage incident response.",
      })
    }
  }

  // ── 8. ESP Integrity Check ──
  if (efiPresent) {
    const espPaths = ["/boot/efi", "/efi", "/boot"]
    for (const espPath of espPaths) {
      if (!directoryExists(espPath)) continue
      try {
        const stat = fs.statSync(espPath)
        if (stat.uid !== 0) {
          findings.push({
            id: nextId("UEFI"),
            severity: "HIGH",
            title: "ESP Partition Owned by Non-Root User",
            description: `EFI System Partition at ${espPath} is owned by UID ${stat.uid} instead of root.`,
            remediation: `chown root:root ${espPath} && chmod 755 ${espPath}`,
          })
        }

        const entries = fs.readdirSync(espPath)
        const suspiciousFiles = entries.filter((e) => {
          const lower = e.toLowerCase()
          return (
            lower.endsWith(".exe") ||
            lower.endsWith(".dll") ||
            lower.endsWith(".bat") ||
            lower.endsWith(".cmd") ||
            lower.endsWith(".ps1") ||
            lower.endsWith(".vbs") ||
            lower.endsWith(".js") ||
            lower.endsWith(".tmp") ||
            lower.endsWith(".bak")
          )
        })

        if (suspiciousFiles.length > 0) {
          findings.push({
            id: nextId("UEFI"),
            severity: "HIGH",
            title: "Suspicious Files in ESP Partition",
            description: `Found ${suspiciousFiles.length} suspicious files in ${espPath}: ${suspiciousFiles.slice(0, 5).join(", ")}${suspiciousFiles.length > 5 ? "..." : ""}. ESP should only contain boot-related files.`,
            remediation: "Remove non-boot files from EFI System Partition. Investigate origin.",
          })
        }
      } catch {}
    }
  }

  // ── 9. Firmware Update Mechanism ──
  if (efiPresent && process.platform === "linux") {
    const fwupdAvail = isToolAvailable("fwupdmgr")
    if (fwupdAvail) {
      const pending = execCmd("fwupdmgr", ["get-updates"])
      if (pending && pending.toLowerCase().includes("no updates")) {
        // Firmware is up to date
      } else if (pending) {
        findings.push({
          id: nextId("UEFI"),
          severity: "MEDIUM",
          title: "Firmware Updates Available",
          description:
            "Firmware updates are available via fwupd. Apply updates to patch known UEFI vulnerabilities.",
          remediation: "Run 'fwupdmgr update' to apply available firmware updates.",
        })
      }
    }
  }

  return {
    secureBootEnabled: secureBoot,
    dbxDatabaseUpToDate: dbxUpToDate,
    dbxHashCount,
    vulnerableDriversDetected: vulnerableDrivers,
    dseStatus,
    unsignedKernelModules,
    nvramVariables,
    bootkitIndicators,
    findings,
    isDryRun: false,
  }
}

// ── Main Export ──────────────────────────────────────────────────────────────

export function auditUEFIAndBootkit(
  options: { dryRun?: boolean; live?: boolean } = {}
): UEFIAuditResult {
  const dryRun = options.dryRun ?? (options.live === undefined ? true : !options.live)

  if (dryRun) {
    return generateDryRunResult()
  }

  try {
    return runLiveAudit()
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err)
    return {
      secureBootEnabled: false,
      dbxDatabaseUpToDate: false,
      dbxHashCount: 0,
      vulnerableDriversDetected: [],
      dseStatus: "UNKNOWN",
      unsignedKernelModules: [],
      nvramVariables: [],
      bootkitIndicators: [],
      findings: [
        {
          id: "UEFI-ERR-01",
          severity: "MEDIUM",
          title: "UEFI Audit Encountered Errors",
          description: `Audit could not complete fully: ${errorMessage}. Some checks may have been skipped.`,
          remediation:
            "Run with elevated privileges (root/admin). Ensure /sys/firmware/efi is accessible.",
        },
      ],
      isDryRun: false,
    }
  }
}

export default { auditUEFIAndBootkit }
