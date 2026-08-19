/**
 * @module ares/zero_day_fuzzer
 * Coverage-guided fuzzing + crash triage + exploit synthesis via exploit_synthesis.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { brokerExec, ensureAresDir, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { parseAflCrashes, step, type ExecStep } from "./_integrations.ts"
import {
  brokerExecLong,
  ensureLabFuzzHarness,
  findPatternOffset,
  minimizeCrash,
  reproCrashInSandbox,
} from "./_operational.ts"
import { synthesizeFromIndicator, buildDeserScaffold } from "../exploit_synthesis.ts"
import { researchCve } from "../auto_research.ts"

export interface FuzzCrash {
  input: string
  signal?: string
  output: string
  exploitable: boolean
  harness?: string
  synthesis?: unknown
  offset?: number
  minimized?: string
}

export interface ZeroDayFuzzResult {
  engine: string
  iterations: number
  crashes: FuzzCrash[]
  steps: ExecStep[]
  exploitScaffold?: string
  artifactDir: string
  summary: string
}

function mutationalFuzz(seed: Buffer, rounds: number): Buffer[] {
  const out: Buffer[] = []
  for (let i = 0; i < rounds; i++) {
    const b = Buffer.from(seed)
    b[i % b.length] = (b[i % b.length]! + (i % 251) + 1) & 0xff
    out.push(b)
  }
  return out
}

function triageCrash(output: string, exitCode?: number): boolean {
  return exitCode !== 0 && /segfault|SIGSEGV|stack smashing|heap overflow|use-after-free|asan:|ubsan:|abort|core dumped/i.test(output)
}

export async function runZeroDayFuzzer(opts: {
  target?: string
  live?: boolean
  seedFile?: string
  rounds?: number
  cveId?: string
  aflTimeoutSec?: number
}): Promise<ZeroDayFuzzResult> {
  liveRequired("ares_zero_day_fuzzer", opts)
  const dir = ensureAresDir("fuzz")
  const rounds = opts.rounds ?? 64
  const crashes: FuzzCrash[] = []
  const steps: ExecStep[] = []
  let engine = "mutational-node"
  let iterations = rounds

  if (opts.cveId) {
    const cve = await researchCve({ cveId: opts.cveId }, { dryRun: false, fetchExploits: true })
    steps.push(step("cve_research", !!cve, JSON.stringify(cve).slice(0, 400)))
    writeArtifact("fuzz", `cve_${opts.cveId}.json`, JSON.stringify(cve, null, 2))
  }

  let target = opts.target
  let seedFile = opts.seedFile
  
  if (!target) {
    throw new Error(`[ARES] Zero-Day Fuzzer requires a target binary path. Lab fallbacks are disabled in v3.2.1.`)
  }

  if (target === "lab" || target === "auto") {
    const lab = ensureLabFuzzHarness(dir)
    steps.push(step("lab_harness_compile", lab.compiled, lab.harness))
    if (lab.compiled) {
      target = lab.harness
      seedFile = seedFile ?? lab.seed
    } else {
      throw new Error(`[ARES] Lab fuzz harness compilation failed. Cannot proceed with autonomous fuzzing.`)
    }
  }

  const aflTimeout = opts.aflTimeoutSec ?? 45
  if (isToolAvailable("afl-fuzz") && seedFile && fs.existsSync(seedFile) && fs.existsSync(target)) {
    engine = "afl-fuzz"
    const outDir = path.join(dir, "afl-out")
    fs.mkdirSync(outDir, { recursive: true })
    const seedDir = path.dirname(seedFile)
    if (!fs.readdirSync(seedDir).length) fs.copyFileSync(seedFile, path.join(seedDir, "seed.txt"))
    const r = await brokerExecLong(
      `AFL_SKIP_CPUFREQ=1 afl-fuzz -i ${seedDir} -o ${outDir} -m none -t 2000 -- ${target} @@`,
      aflTimeout,
    )
    steps.push(step("afl_fuzz", r.out.includes("crashes") || r.out.includes("unique"), r.out.slice(0, 500)))
    if (isToolAvailable("afl-cmin")) {
      const cminDir = path.join(dir, "afl-cmin")
      fs.mkdirSync(cminDir, { recursive: true })
      const cm = await brokerExec(`afl-cmin -i ${outDir}/queue -o ${cminDir} -m none -- ${target} @@ 2>&1 | tail -5`)
      steps.push(step("afl_cmin", cm.ok || cm.out.includes("corpus"), cm.out.slice(0, 300)))
    }
    for (const crashPath of parseAflCrashes(outDir)) {
      const minimized = await minimizeCrash(crashPath, target)
      const crashBuf = fs.readFileSync(minimized)
      const repro = await brokerExec(`${target} ${minimized} 2>&1`)
      const sbx = await reproCrashInSandbox(target, minimized).catch((e) => ({ exitCode: 1, stderr: String(e), stdout: "", sandboxed: false }))
      const exploitable = triageCrash(repro.out + sbx.stderr, repro.exit || sbx.exitCode)
      let synthesis: unknown
      if (exploitable) {
        synthesis = await synthesizeFromIndicator(target, repro.out + sbx.stderr, { live: true })
        buildDeserScaffold(repro.out)
      }
      const marker = Buffer.from("OURMINE")
      const offset = findPatternOffset(crashBuf, marker)
      crashes.push({
        input: crashPath,
        minimized,
        output: (repro.out + sbx.stderr).slice(0, 300),
        exploitable,
        synthesis,
        offset: offset >= 0 ? offset : undefined,
        signal: sbx.exitCode !== 0 ? `exit=${sbx.exitCode}` : undefined,
      })
    }
    iterations = parseAflCrashes(outDir).length + rounds
  } else {
    const seedPath = seedFile ?? writeArtifact("fuzz", "seed.bin", "OURMINE_FUZZ_SEED\x00AAAA")
    const seed = fs.readFileSync(seedPath)
    for (let i = 0; i < rounds; i++) {
      const mutant = mutationalFuzz(seed, 1)[0]!
      const inp = path.join(dir, `input_${i}.bin`)
      fs.writeFileSync(inp, mutant)
      const r = await brokerExec(`${target} ${inp} 2>&1`)
      if (triageCrash(r.out, r.exit)) {
        const synthesis = await synthesizeFromIndicator(target, r.out, { live: true })
        crashes.push({ input: inp, output: r.out.slice(0, 300), exploitable: true, synthesis })
      }
    }
    steps.push(step("mutational_fuzz", true, `${rounds} iterations, ${crashes.length} crash(es)`))
  }

  let exploitScaffold: string | undefined
  if (crashes.length) {
    const crash = crashes[0]!
    const payloadPath = crash.minimized ?? crash.input
    const synth = crash.synthesis as { polyglots?: unknown[]; deserScaffold?: unknown } | undefined
    exploitScaffold = writeArtifact("fuzz", "exploit_scaffold.py", `#!/usr/bin/env python3
# Auto-generated from crash triage — authorized lab only
import struct, sys
payload = open("${payloadPath}", "rb").read()
offset = ${crash.offset ?? "None"}
# Synthesis: ${JSON.stringify(synth?.deserScaffold ?? "manual ROP")}
if offset is not None:
    payload = payload[:offset] + struct.pack("<Q", 0x4141414141414141) + payload[offset+8:]
sys.stdout.buffer.write(payload)
`)
    steps.push(step("exploit_scaffold", true, exploitScaffold))
  }

  return {
    engine,
    iterations,
    crashes,
    steps,
    exploitScaffold,
    artifactDir: dir,
    summary: crashes.length
      ? `Zero-day fuzzer: ${crashes.length} crash(es) triaged + synthesized via ${engine}`
      : `Zero-day fuzzer: ${iterations} iterations, no crashes (target may be hardened)`,
  }
}

export default { runZeroDayFuzzer }
