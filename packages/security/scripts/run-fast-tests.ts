#!/usr/bin/env node
/** Run security tests excluding lab/live suites that hang CI. */
import { readdirSync } from "node:fs"
import { spawnSync } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

const SKIP = new Set([
  "tier1_phases.test.js",
  "live_offensive.test.js",
  "top_cut.test.js",
  "ares_modules.test.js", // live execution smoke (~240s)
])

const testDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../test")
const files = readdirSync(testDir)
  .filter((f) => f.endsWith(".test.js") && !SKIP.has(f))
  .map((f) => path.join(testDir, f))

const result = spawnSync(
  process.execPath,
  ["--experimental-strip-types", "--test", ...files],
  {
    stdio: "inherit",
    env: { ...process.env, OURMINE_TEST_FAST: "1", OURMINE_ALLOW_DRY_RUN: "1" },
  },
)

process.exit(result.status ?? 1)
