#!/usr/bin/env node
/** Run security tests excluding lab/live suites that hang CI. */
import { readdirSync, existsSync } from "node:fs"
import { spawnSync } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

const SKIP = new Set([
  "tier1_phases.test.js",
  "live_offensive.test.js",
  "top_cut.test.js",
  "ares_modules.test.js",
])

const scriptsDir = path.dirname(fileURLToPath(import.meta.url))
const testDir = path.resolve(scriptsDir, "../test")
const genScript = path.join(scriptsDir, "generate-module-smokes.ts")

// Regenerate module smokes before fast suite
spawnSync(process.execPath, ["--experimental-strip-types", genScript], { stdio: "inherit" })

const files: string[] = []
for (const f of readdirSync(testDir)) {
  if (f.endsWith(".test.js") && !SKIP.has(f)) files.push(path.join(testDir, f))
}
const genDir = path.join(testDir, "generated")
if (existsSync(genDir)) {
  for (const f of readdirSync(genDir)) {
    if (f.endsWith(".test.js")) files.push(path.join(genDir, f))
  }
}

const result = spawnSync(
  process.execPath,
  ["--experimental-strip-types", "--test", ...files.sort()],
  {
    stdio: "inherit",
    env: { ...process.env, OURMINE_TEST_FAST: "1", OURMINE_ALLOW_DRY_RUN: "1" },
  },
)

process.exit(result.status ?? 1)
