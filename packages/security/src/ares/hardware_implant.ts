/**
 * @module ares/hardware_implant
 * Hardware implants — BadUSB, HID descriptors, SDR/RF probes, MCU firmware.
 */
import { compileDuckyScript, generateHIDReportDescriptor, cloneRFIDCard } from "../physical.ts"
import { generateC2Image } from "../stego_c2.ts"
import { brokerExec, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { step, type ExecStep } from "./_integrations.ts"

export interface HardwareImplantResult {
  implantId: string
  types: string[]
  artifacts: string[]
  steps: ExecStep[]
  probed: boolean
  summary: string
}

export async function deployHardwareImplant(opts: {
  live?: boolean
  type?: "usb" | "rf" | "sdr" | "all"
}): Promise<HardwareImplantResult> {
  liveRequired("ares_hardware_implant", opts)
  const implantId = `hw_${Date.now()}`
  const type = opts.type ?? "all"
  const types: string[] = []
  const artifacts: string[] = []
  const steps: ExecStep[] = []
  let probed = false

  if (type === "usb" || type === "all") {
    const ducky = compileDuckyScript("DELAY 1000\nSTRING OURMINE_HW_IMPLANT\nENTER\n", false)
    artifacts.push(writeArtifact("hardware", `${implantId}.hex`, ducky.compiledPayloadHex))
    const hid = generateHIDReportDescriptor()
    writeArtifact("hardware", `${implantId}_hid.json`, JSON.stringify(hid, null, 2))
    types.push("usb_hid_implant", "badusb")
    if (isToolAvailable("lsusb")) {
      const r = await brokerExec("lsusb")
      probed = r.ok
      steps.push(step("lsusb", r.ok, r.out.slice(0, 400)))
    }
  }

  const rfid = cloneRFIDCard("DEADBEEF", 0x0044, 0x08, false)
  writeArtifact("hardware", `${implantId}_rfid.json`, JSON.stringify(rfid, null, 2))
  types.push("rfid_clone")
  steps.push(step("rfid_clone", true, rfid.technology))

  if (type === "rf" || type === "sdr" || type === "all") {
    types.push("rf_bridge", "sdr_covert")
    if (isToolAvailable("rtl_test")) {
      const r = await brokerExec("rtl_test -t 2>&1 | head -15")
      probed = probed || r.ok
      steps.push(step("rtl_test", r.ok, r.out.slice(0, 200)))
    }
  }

  const bmp = generateC2Image(`HW:${implantId}`)
  artifacts.push(writeArtifact("hardware", `${implantId}_stego.bmp`, bmp))
  artifacts.push(writeArtifact("hardware", `${implantId}_mcu.ino`, `void setup() { Keyboard.begin(); delay(1000); Keyboard.print("OURMINE"); Keyboard.end(); }\nvoid loop() {}\n`))
  types.push("stego_carrier", "mcu_firmware")

  return {
    implantId,
    types,
    artifacts,
    steps,
    probed,
    summary: `Hardware implant: ${types.length} type(s), probed=${probed}`,
  }
}

export default { deployHardwareImplant }
