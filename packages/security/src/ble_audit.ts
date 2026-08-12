/**
 * @module ble_audit
 * Standard Bluetooth/BLE discovery — bluetoothctl/hcitool read-only scan. No fabrication on dry-run.
 */
import { execFileSync } from "node:child_process"
import * as fs from "node:fs"
import * as path from "node:path"
import { resolveDryRun } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"
import { ensureAresDir, writeArtifact } from "./ares/_base.ts"

export interface BleDevice {
  address: string
  name?: string
  rssi?: string
  services?: string[]
  deviceClass?: string
}

export interface BleFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detail: string
  evidence?: string
}

export interface BleAuditResult {
  target: string
  dryRun: boolean
  devices: BleDevice[]
  findings: BleFinding[]
  artifacts: string[]
  summary: string
}

function runCmd(cmd: string, args: string[], timeoutMs = 10000): string {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] })
  } catch {
    return ""
  }
}

function parseHcitoolScan(out: string): BleDevice[] {
  const devices: BleDevice[] = []
  for (const line of out.split("\n")) {
    const m = line.match(/^([0-9A-F:]{17})\s+(.+)$/i)
    if (m) devices.push({ address: m[1]!.toUpperCase(), name: m[2]!.trim() })
  }
  return devices
}

function parseBluetoothctl(out: string): BleDevice[] {
  const devices: BleDevice[] = []
  let current: Partial<BleDevice> = {}
  for (const line of out.split("\n")) {
    const trimmed = line.trim()
    if (trimmed.startsWith("Device ")) {
      if (current.address) devices.push(current as BleDevice)
      const parts = trimmed.split(" ")
      current = { address: parts[1]!, name: parts.slice(2).join(" ").replace(/^\(/, "").replace(/\)$/, "") }
    } else if (trimmed.startsWith("RSSI:")) {
      current.rssi = trimmed.slice(5).trim()
    } else if (trimmed.startsWith("UUID:")) {
      current.services = [...(current.services ?? []), trimmed.slice(5).trim()]
    }
  }
  if (current.address) devices.push(current as BleDevice)
  return devices
}

const SMART_LOCK_HINTS = /\b(lock|kwikset|yale|august|schlage|nuki|level|smart.?lock)\b/i

export async function auditBle(
  target: string,
  opts: { live?: boolean; dryRun?: boolean; scanSeconds?: number } = {},
): Promise<BleAuditResult> {
  const dryRun = resolveDryRun(opts)
  const empty: BleAuditResult = {
    target,
    dryRun: true,
    devices: [],
    findings: [],
    artifacts: [],
    summary: "dry-run: BLE scan skipped — set OURMINE_LIVE=1 for bluetoothctl/hcitool discovery",
  }
  if (dryRun) return empty

  const devices: BleDevice[] = []
  const scanSec = opts.scanSeconds ?? 8

  if (isToolAvailable("bluetoothctl")) {
    runCmd("bluetoothctl", ["power", "on"], 3000)
    const scanOut = runCmd("bash", ["-c", `timeout ${scanSec} bluetoothctl scan on 2>&1; bluetoothctl devices 2>&1`], (scanSec + 4) * 1000)
    devices.push(...parseBluetoothctl(scanOut))
  } else if (isToolAvailable("hcitool")) {
    runCmd("hciconfig", ["hci0", "up"], 3000)
    devices.push(...parseHcitoolScan(runCmd("hcitool", ["scan", "--flush"], (scanSec + 2) * 1000)))
  }

  const findings: BleFinding[] = []
  for (const d of devices.slice(0, 24)) {
    const isLock = SMART_LOCK_HINTS.test(d.name ?? "")
    findings.push({
      id: `ble-${d.address.replace(/:/g, "")}`,
      severity: isLock ? "high" : "info",
      title: isLock ? `Smart lock candidate: ${d.name ?? d.address}` : `BLE device: ${d.name ?? d.address}`,
      detail: d.rssi ? `RSSI ${d.rssi}` : d.address,
      evidence: d.address,
    })
  }

  if (isToolAvailable("gatttool") && devices[0]) {
    const gattOut = runCmd("gatttool", ["-b", devices[0]!.address, "--primary"], 6000)
    if (gattOut.trim()) {
      devices[0]!.services = gattOut.split("\n").filter((l) => l.includes("handle")).slice(0, 8)
      findings.push({
        id: "ble-gatt-enum",
        severity: "info",
        title: `GATT services on ${devices[0]!.address}`,
        detail: `${devices[0]!.services?.length ?? 0} primary service(s) enumerated`,
        evidence: gattOut.slice(0, 200),
      })
    }
  }

  const artifacts: string[] = []
  if (devices.length) {
    artifacts.push(
      writeArtifact("ble", `scan_${Date.now()}.json`, JSON.stringify({ target, devices }, null, 2)),
    )
  }

  return {
    target,
    dryRun: false,
    devices,
    findings,
    artifacts,
    summary: devices.length
      ? `BLE audit: ${devices.length} device(s) discovered`
      : "BLE audit: no devices found (adapter present?)",
  }
}

export default { auditBle }
