/**
 * @module ares/hardware_implant
 * Hardware implants — BadUSB, HID descriptors, SDR/RF probes, MCU firmware flash.
 */
import { compileDuckyScript, generateHIDReportDescriptor, cloneRFIDCard } from "../physical.ts"
import { generateC2Image } from "../stego_c2.ts"
import { brokerExec, ensureAresDir, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { runCmd, step, type ExecStep } from "./_integrations.ts"
import { enableUsbGadget, sdrTransmitProbe } from "./_operational.ts"

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
    steps.push(await enableUsbGadget("hid"))
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
    steps.push(await sdrTransmitProbe(915.0))
    if (steps[steps.length - 1]?.success) probed = true
  }

  const bmp = generateC2Image(`HW:${implantId}`)
  artifacts.push(writeArtifact("hardware", `${implantId}_stego.bmp`, bmp))
  const mcuIno = writeArtifact("hardware", `${implantId}_mcu.ino`, `#include <Keyboard.h>\nvoid setup() { Keyboard.begin(); delay(1000); Keyboard.print("OURMINE"); Keyboard.end(); }\nvoid loop() {}\n`)
  artifacts.push(mcuIno)
  types.push("stego_carrier", "mcu_firmware")

  if (isToolAvailable("arduino-cli")) {
    steps.push(await runCmd("arduino_compile", `arduino-cli compile --fqbn arduino:avr:leonardo ${ensureAresDir("hardware")} 2>&1 | head -15`))
  }
  if (isToolAvailable("avrdude")) {
    steps.push(await runCmd("avrdude_version", "avrdude -? 2>&1 | head -5"))
    types.push("mcu_flash_ready")
  }

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
