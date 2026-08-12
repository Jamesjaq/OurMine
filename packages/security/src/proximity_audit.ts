/**
 * @module proximity_audit
 * Unified USB + WiFi + BLE proximity audit — routes by target hint.
 */
import { auditUsb, type UsbAuditResult } from "./usb_audit.ts"
import { auditWifi, type WifiAuditResult } from "./wifi_audit.ts"
import { auditBle, type BleAuditResult } from "./ble_audit.ts"
import { resolveDryRun } from "./exec_options.ts"

export type ProximityChannel = "usb" | "wifi" | "ble" | "all"

export interface ProximityAuditResult {
  target: string
  dryRun: boolean
  channels: ProximityChannel[]
  usb?: UsbAuditResult
  wifi?: WifiAuditResult
  ble?: BleAuditResult
  findings: Array<{ channel: ProximityChannel; id: string; title: string; severity: string }>
  templatePaths: string[]
  artifacts: string[]
  summary: string
}

const USB_HINTS = /\b(usb|badusb|rubber ducky|physical|hid|ducky|lobby)\b/i
const WIFI_HINTS = /\b(wifi|wlan|wireless|802\.11|ssid|evil.?twin|perimeter)\b/i
const BLE_HINTS = /\b(ble|bluetooth|smart lock|beacon|gatt|iot)\b/i

export function detectProximityChannels(hint: string): ProximityChannel[] {
  const channels: ProximityChannel[] = []
  if (USB_HINTS.test(hint)) channels.push("usb")
  if (WIFI_HINTS.test(hint)) channels.push("wifi")
  if (BLE_HINTS.test(hint)) channels.push("ble")
  if (!channels.length) channels.push("all")
  return channels
}

export async function auditProximity(
  target: string,
  opts: { live?: boolean; dryRun?: boolean; hint?: string; channels?: ProximityChannel[] } = {},
): Promise<ProximityAuditResult> {
  const dryRun = resolveDryRun(opts)
  const hint = opts.hint ?? target
  const channels = opts.channels ?? detectProximityChannels(hint)
  const runAll = channels.includes("all")
  const findings: ProximityAuditResult["findings"] = []
  const templatePaths: string[] = []
  const artifacts: string[] = []
  let usb: UsbAuditResult | undefined
  let wifi: WifiAuditResult | undefined
  let ble: BleAuditResult | undefined

  if (runAll || channels.includes("usb")) {
    usb = await auditUsb(target, { live: opts.live, dryRun: opts.dryRun })
    templatePaths.push(...usb.templatePaths)
    artifacts.push(...usb.artifacts)
    for (const f of usb.findings) {
      findings.push({ channel: "usb", id: f.id, title: f.title, severity: f.severity })
    }
  }
  if (runAll || channels.includes("wifi")) {
    wifi = await auditWifi(target, { live: opts.live, dryRun: opts.dryRun })
    templatePaths.push(...wifi.templatePaths)
    artifacts.push(...wifi.artifacts)
    for (const f of wifi.findings) {
      findings.push({ channel: "wifi", id: f.id, title: f.title, severity: f.severity })
    }
  }
  if (runAll || channels.includes("ble")) {
    ble = await auditBle(target, { live: opts.live, dryRun: opts.dryRun })
    artifacts.push(...ble.artifacts)
    for (const f of ble.findings) {
      findings.push({ channel: "ble", id: f.id, title: f.title, severity: f.severity })
    }
  }

  const parts = [
    usb?.summary,
    wifi?.summary,
    ble?.summary,
  ].filter(Boolean)

  return {
    target,
    dryRun,
    channels: runAll ? ["usb", "wifi", "ble"] : channels,
    usb,
    wifi,
    ble,
    findings,
    templatePaths: [...new Set(templatePaths)],
    artifacts: [...new Set(artifacts)],
    summary: dryRun
      ? `proximity dry-run: ${(runAll ? ["usb", "wifi", "ble"] : channels).join("+")} template paths only`
      : parts.join("; ") || "proximity audit complete",
  }
}

export default { auditProximity, detectProximityChannels }
