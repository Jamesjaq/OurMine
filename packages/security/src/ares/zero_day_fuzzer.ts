/**
 * @module ares/zero_day_fuzzer
 * Coverage-guided fuzzing + crash triage + exploit synthesis via exploit_synthesis.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { brokerExec, ensureAresDir, liveRequired, isToolAvailable, writeArtifact } from "./_base.ts"
import { parseAflCrashes, step, type ExecStep } from "./_integrations.ts"
import { synthesizeFromIndicator, buildDeserScaffold } from "../exploit_synthesis.ts"
import { researchCve } from "../auto_research.ts"

export interface FuzzCrash {
  input: string
  signal?: string
  output: string
  exploitable: boolean
  harness?: string
  synthesis?: unknown
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

function triageCrash(output: string): boolean {
  return /segfault|SIGSEGV|stack smashing|heap overflow|use-after-free|asan:|ubsan:|abort/i.test(output)
}

export async function runZeroDayFuzzer(opts: {
  target: string
  live?: boolean
  seedFile?: string
  rounds?: number
  cveId?: string
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

  if (isToolAvailable("afl-fuzz") && opts.seedFile && fs.existsSync(opts.seedFile)) {
    engine = "afl-fuzz"
    const outDir = path.join(dir, "afl-out")
    fs.mkdirSync(outDir, { recursive: true })
    const seedDir = path.dirname(opts.seedFile)
    const r = await brokerExec(`timeout 30 afl-fuzz -i ${seedDir} -o ${outDir} -m none -t 2000 -- ${opts.target} @@ 2>&1 || true`)
    iterations = rounds
    steps.push(step("afl_fuzz", r.ok || r.out.includes("crashes"), r.out.slice(0, 500)))
    for (const crashPath of parseAflCrashes(outDir)) {
      const crashOut = fs.readFileSync(crashPath)
      const repro = await brokerExec(`${opts.target} ${crashPath} 2>&1`)
      const exploitable = triageCrash(repro.out)
      let synthesis: unknown
      if (exploitable) {
        synthesis = await synthesizeFromIndicator(opts.target, repro.out, { live: true })
        buildDeserScaffold(repro.out)
      }
      crashes.push({ input: crashPath, output: repro.out.slice(0, 300), exploitable, synthesis })
    }
  } else {
    const seedPath = opts.seedFile ?? writeArtifact("fuzz", "seed.bin", "OURMINE_FUZZ_SEED\x00AAAA")
    const seed = fs.readFileSync(seedPath)
    for (let i = 0; i < rounds; i++) {
      const mutant = mutationalFuzz(seed, 1)[0]!
      const inp = path.join(dir, `input_${i}.bin`)
      fs.writeFileSync(inp, mutant)
      const r = await brokerExec(`${opts.target} ${inp} 2>&1`)
      if (!r.ok && triageCrash(r.out)) {
        const synthesis = await synthesizeFromIndicator(opts.target, r.out, { live: true })
        crashes.push({ input: inp, output: r.out.slice(0, 300), exploitable: true, synthesis })
      }
    }
    steps.push(step("mutational_fuzz", true, `${rounds} iterations, ${crashes.length} crash(es)`))
  }

  let exploitScaffold: string | undefined
  if (crashes.length) {
    const crash = crashes[0]!
    const synth = crash.synthesis as { polyglots?: unknown[]; deserScaffold?: unknown } | undefined
    exploitScaffold = writeArtifact("fuzz", "exploit_scaffold.py", `#!/usr/bin/env python3
# Auto-generated from crash triage — authorized lab only
import sys
payload = open("${crash.input}", "rb").read()
# Synthesis: ${JSON.stringify(synth?.deserScaffold ?? "manual ROP")}
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
